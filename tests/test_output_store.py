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
