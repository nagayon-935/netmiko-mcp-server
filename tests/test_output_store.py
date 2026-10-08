from datetime import datetime, timezone
from pathlib import Path

import pytest

import output_store


@pytest.fixture(autouse=True)
def _use_tmp_output_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(output_store, "output_dir", str(tmp_path / "outputs"))


def test_save_and_list_outputs():
    output_store.save_output("router1", "show version", "line1\nline2")

    filenames = output_store.list_outputs("router1")

    assert len(filenames) == 1
    assert filenames[0].startswith("show_version_")


def test_list_outputs_empty_for_unknown_device():
    assert output_store.list_outputs("nope") == []


def test_save_output_serializes_structured_data():
    output_store.save_output("router1", "show version", {"a": 1})

    filename = output_store.list_outputs("router1")[0]
    content = output_store.read_output("router1", filename, limit=10)

    assert '"a": 1' in content


def test_read_output_paginates():
    output_store.save_output(
        "router1", "show run", "\n".join(f"line{i}" for i in range(10))
    )
    filename = output_store.list_outputs("router1")[0]

    page1 = output_store.read_output("router1", filename, offset=0, limit=3)
    assert "Lines 1-3 of 10" in page1
    assert "line0" in page1 and "line2" in page1
    assert "offset=3" in page1

    page2 = output_store.read_output("router1", filename, offset=3, limit=3)
    assert "Lines 4-6 of 10" in page2


def test_read_output_missing_file_returns_error():
    result = output_store.read_output("router1", "doesnotexist.txt")
    assert "not found" in result


@pytest.mark.parametrize("bad_device", ["../escape", "a/b", "", ".", "a\x00b"])
def test_save_output_rejects_unsafe_device_name(bad_device):
    with pytest.raises(ValueError, match="Security Error"):
        output_store.save_output(bad_device, "show version", "x")


def test_read_output_rejects_path_traversal_in_filename():
    result = output_store.read_output("router1", "../../etc/passwd")
    assert "Security Error" in result


def test_device_symlink_cannot_save_list_or_read_outside_output_dir(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o755)
    (outside / "private.txt").write_text("private data")
    original_mode = outside.stat().st_mode
    base_dir = Path(output_store.output_dir)
    base_dir.mkdir()
    (base_dir / "router1").symlink_to(outside, target_is_directory=True)

    with pytest.raises(ValueError, match="Security Error"):
        output_store.save_output("router1", "show version", "new data")
    with pytest.raises(ValueError, match="Security Error"):
        output_store.list_outputs("router1")
    assert "Security Error" in output_store.read_output("router1", "private.txt")
    assert outside.stat().st_mode == original_mode
    assert list(outside.iterdir()) == [outside / "private.txt"]
    assert (outside / "private.txt").read_text() == "private data"


def test_output_file_symlink_cannot_list_or_read_external_file(tmp_path):
    output_store.save_output("router1", "show version", "ok")
    outside = tmp_path / "private.txt"
    outside.write_text("private data")
    device_dir = Path(output_store.output_dir) / "router1"
    (device_dir / "external.txt").symlink_to(outside)

    with pytest.raises(ValueError, match="Security Error"):
        output_store.list_outputs("router1")
    assert "Security Error" in output_store.read_output("router1", "external.txt")


def test_same_timestamp_outputs_do_not_overwrite_each_other(monkeypatch):
    class FixedDatetime:
        @staticmethod
        def now(tz):
            return datetime(2026, 1, 1, tzinfo=timezone.utc)

    monkeypatch.setattr(output_store, "datetime", FixedDatetime)
    first = output_store.save_output("router1", "show version", "first")
    second = output_store.save_output("router1", "show version", "second")

    assert first != second
    assert "first" in output_store.read_output("router1", first)
    assert "second" in output_store.read_output("router1", second)


def test_output_permissions_are_private_from_first_write(monkeypatch):
    original_fdopen = output_store.os.fdopen
    modes = []

    def inspect_fd(fd, *args, **kwargs):
        modes.append(output_store.os.fstat(fd).st_mode & 0o777)
        return original_fdopen(fd, *args, **kwargs)

    monkeypatch.setattr(output_store.os, "fdopen", inspect_fd)
    output_store.save_output("router1", "show version", "private output")

    assert modes == [0o600]


@pytest.mark.parametrize("offset, limit", [(-1, 500), (0, 0), (0, -1)])
def test_read_output_rejects_invalid_pagination(offset, limit):
    filename = output_store.save_output("router1", "show version", "first\nsecond")

    assert output_store.read_output("router1", filename, offset, limit).startswith(
        "Error:"
    )
