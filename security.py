"""Command validation for the netmiko MCP server.

Default-deny model: a command is only forwarded to a device if it matches an
entry in allowed_commands. denied_commands always takes precedence over
allowed_commands, even if a command happens to match both.

Glob support: a single trailing '*' is allowed per entry.
  - "show run*"  (inline glob) matches "show run", "show running-config", etc.
  - "show ip route *" (space glob) matches "show ip route vrf blue" but NOT
    "show ip route" alone.
Patterns with '*' anywhere other than a single trailing position are rejected
at load time so a misconfigured policy fails loudly instead of silently
allowing more than intended.
"""

import re
import tomllib
from dataclasses import dataclass

# Characters permitted in a submitted command. Deliberately excludes
# newline/carriage-return/tab and Unicode whitespace lookalikes so a command
# cannot smuggle a second line or bypass whitespace-based checks.
ALLOWED_COMMAND_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ./:_-,\"'|"
)

REASON_ALLOWED = "ALLOWED"
REASON_UNSAFE_CHAR = "UNSAFE_CHAR"
REASON_DENY_MATCH = "DENY_MATCH"
REASON_NO_ALLOW_MATCH = "NO_ALLOW_MATCH"

# State-changing configuration commands that are always denied for
# set_config_commands_and_commit_or_save, regardless of config_allowed_commands
# / config_denied_commands. Merged into every config policy's denied_commands
# so these stay blocked even if the operator's TOML doesn't list them, or a
# broad config_allowed_commands glob would otherwise match them.
#
# "no shutdown" (re-enabling an interface) is intentionally NOT included here:
# unlike "shutdown", it is not the risky direction of the toggle.
BASELINE_CONFIG_DENIED_COMMANDS: tuple[str, ...] = (
    "shutdown",
    "shutdown*",
    "clear*",
)


@dataclass(frozen=True)
class ValidationResult:
    allowed: bool
    reason: str
    normalized_command: str


@dataclass(frozen=True)
class CommandPolicy:
    allowed_commands: tuple[str, ...] = ()
    denied_commands: tuple[str, ...] = ()


def load_command_policy(path: str | None) -> CommandPolicy:
    """Load the allow/deny command policy from a TOML file.

    Returns an empty policy (deny-all) when path is None. This is the safe
    default: without an explicit commands file, no command is permitted.
    """
    if path is None:
        return CommandPolicy()

    with open(path, "rb") as f:
        data = tomllib.load(f)

    return CommandPolicy(
        allowed_commands=tuple(data.get("allowed_commands", [])),
        denied_commands=tuple(data.get("denied_commands", [])),
    )


def load_config_command_policy(path: str | None) -> CommandPolicy:
    """Load the allow/deny policy for configuration commands.

    Reads config_allowed_commands / config_denied_commands from the same TOML
    file as load_command_policy (a separate --commands-file is not needed).
    BASELINE_CONFIG_DENIED_COMMANDS is always appended to denied_commands.

    Returns a policy with only the baseline denies (deny-all, since
    allowed_commands is empty) when path is None.
    """
    if path is None:
        return CommandPolicy()

    with open(path, "rb") as f:
        data = tomllib.load(f)

    return CommandPolicy(
        allowed_commands=tuple(data.get("config_allowed_commands", [])),
        denied_commands=tuple(data.get("config_denied_commands", [])),
    )


def _invalid_glob_entries(entries: tuple[str, ...]) -> list[str]:
    """Return entries whose '*' usage is not a single trailing glob."""
    invalid = []
    for entry in entries:
        words = entry.strip().split()
        if not words:
            continue
        if entry.count("*") > 1:
            invalid.append(entry)
            continue
        last = words[-1]
        if last == "*":
            if len(words) == 1:
                invalid.append(entry)
        elif last.endswith("*"):
            if len(last) == 1 or any("*" in w for w in words[:-1]):
                invalid.append(entry)
        elif "*" in entry:
            invalid.append(entry)
    return invalid


def validate_command_lists(policy: CommandPolicy) -> list[str]:
    """Validate the policy's glob usage. Returns human-readable error strings,
    empty when the policy is valid. Intended to be called once at startup so a
    misconfigured commands file is caught before the server accepts requests.
    """
    errors: list[str] = []
    bad_allow = _invalid_glob_entries(policy.allowed_commands)
    if bad_allow:
        errors.append(
            f"allowed_commands contains unsupported glob pattern(s): {bad_allow}. "
            f"'*' must appear only as a trailing word ('cmd *') or trailing character ('cmd*')."
        )
    bad_deny = _invalid_glob_entries(policy.denied_commands)
    if bad_deny:
        errors.append(
            f"denied_commands contains unsupported glob pattern(s): {bad_deny}. "
            f"'*' must appear only as a trailing word ('cmd *') or trailing character ('cmd*')."
        )
    return errors


def _glob_to_regex(pattern: str) -> re.Pattern[str]:
    escaped = re.escape(pattern.strip())
    escaped = escaped.replace(r"\ \*", r"\ .*")
    escaped = escaped.replace(r"\*", r".*")
    return re.compile("^" + escaped + "$", re.IGNORECASE)


def _matches_any(command: str, entries: tuple[str, ...]) -> bool:
    for entry in entries:
        if "*" in entry:
            if _glob_to_regex(entry).match(command):
                return True
        elif command.lower() == entry.strip().lower():
            return True
    return False


def validate_command(command: str, policy: CommandPolicy) -> ValidationResult:
    """Validate a command against the given allow/deny policy.

    Rules, applied in order:
    1. Whitespace is normalized (runs collapsed to a single space, stripped).
    2. Only characters in ALLOWED_COMMAND_CHARS are permitted.
    3. denied_commands is checked first and always wins over allowed_commands.
    4. The command must match an entry in allowed_commands, or it is denied.
    """
    # Check the raw command for disallowed characters (newline, tab, Unicode
    # whitespace lookalikes, etc.) BEFORE normalizing. str.split()/" ".join()
    # below treats all whitespace as equivalent, so checking after
    # normalization would silently absorb a smuggled newline into a plain
    # space instead of rejecting it.
    if any(c not in ALLOWED_COMMAND_CHARS for c in command):
        return ValidationResult(
            allowed=False,
            reason=REASON_UNSAFE_CHAR,
            normalized_command=" ".join(command.split()),
        )

    normalized = " ".join(command.split())

    if _matches_any(normalized, policy.denied_commands):
        return ValidationResult(
            allowed=False, reason=REASON_DENY_MATCH, normalized_command=normalized
        )

    if _matches_any(normalized, policy.allowed_commands):
        return ValidationResult(
            allowed=True, reason=REASON_ALLOWED, normalized_command=normalized
        )

    return ValidationResult(
        allowed=False, reason=REASON_NO_ALLOW_MATCH, normalized_command=normalized
    )


def validate_config_command(command: str, policy: CommandPolicy) -> ValidationResult:
    """Validate a single configuration-mode command line.

    Identical to validate_command, except BASELINE_CONFIG_DENIED_COMMANDS is
    always enforced in addition to policy.denied_commands — regardless of how
    policy was constructed — so state-changing commands like interface
    shutdown or clear stay blocked even if a caller builds a CommandPolicy
    directly instead of going through load_config_command_policy().
    """
    effective_policy = CommandPolicy(
        allowed_commands=policy.allowed_commands,
        denied_commands=policy.denied_commands + BASELINE_CONFIG_DENIED_COMMANDS,
    )
    return validate_command(command, effective_policy)
