from security import (
    REASON_ALLOWED,
    REASON_DENY_MATCH,
    REASON_NO_ALLOW_MATCH,
    REASON_UNSAFE_CHAR,
    CommandPolicy,
    load_command_policy,
    validate_command,
    validate_command_lists,
)


def test_default_policy_denies_everything():
    policy = CommandPolicy()
    result = validate_command("show version", policy)
    assert result.allowed is False
    assert result.reason == REASON_NO_ALLOW_MATCH


def test_exact_allow_match_is_allowed():
    policy = CommandPolicy(allowed_commands=("show version",))
    result = validate_command("show version", policy)
    assert result.allowed is True
    assert result.reason == REASON_ALLOWED


def test_command_not_in_allow_list_is_denied():
    policy = CommandPolicy(allowed_commands=("show version",))
    result = validate_command("show ip route", policy)
    assert result.allowed is False
    assert result.reason == REASON_NO_ALLOW_MATCH


def test_deny_takes_precedence_over_allow():
    policy = CommandPolicy(
        allowed_commands=("show running-config",),
        denied_commands=("show running-config",),
    )
    result = validate_command("show running-config", policy)
    assert result.allowed is False
    assert result.reason == REASON_DENY_MATCH


def test_inline_glob_allows_suffix():
    policy = CommandPolicy(allowed_commands=("show ip interface*",))
    assert validate_command("show ip interface", policy).allowed is True
    assert validate_command("show ip interfaces brief", policy).allowed is True


def test_space_glob_requires_extra_word():
    policy = CommandPolicy(allowed_commands=("show ip route *",))
    assert validate_command("show ip route", policy).allowed is False
    assert validate_command("show ip route vrf blue", policy).allowed is True


def test_whitespace_is_normalized():
    policy = CommandPolicy(allowed_commands=("show version",))
    result = validate_command("show    version  ", policy)
    assert result.allowed is True
    assert result.normalized_command == "show version"


def test_unsafe_character_is_rejected():
    policy = CommandPolicy(allowed_commands=("show version",))
    result = validate_command("show version\nreload", policy)
    assert result.allowed is False
    assert result.reason == REASON_UNSAFE_CHAR


def test_allow_match_is_case_insensitive():
    policy = CommandPolicy(allowed_commands=("show version",))
    result = validate_command("SHOW VERSION", policy)
    assert result.allowed is True


def test_validate_command_lists_rejects_mid_word_glob():
    policy = CommandPolicy(allowed_commands=("show * interface",))
    errors = validate_command_lists(policy)
    assert len(errors) == 1
    assert "allowed_commands" in errors[0]


def test_validate_command_lists_rejects_bare_star():
    policy = CommandPolicy(denied_commands=("*",))
    errors = validate_command_lists(policy)
    assert len(errors) == 1
    assert "denied_commands" in errors[0]


def test_validate_command_lists_accepts_valid_globs():
    policy = CommandPolicy(
        allowed_commands=("show ip interface*", "show ip route *"),
        denied_commands=("show running-config*",),
    )
    assert validate_command_lists(policy) == []


def test_load_command_policy_returns_empty_when_path_is_none():
    policy = load_command_policy(None)
    assert policy == CommandPolicy()


def test_load_command_policy_reads_toml(tmp_path):
    commands_file = tmp_path / "commands.toml"
    commands_file.write_text(
        'allowed_commands = ["show version"]\ndenied_commands = ["show running-config"]\n'
    )
    policy = load_command_policy(str(commands_file))
    assert policy.allowed_commands == ("show version",)
    assert policy.denied_commands == ("show running-config",)
