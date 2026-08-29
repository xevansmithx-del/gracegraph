from __future__ import annotations

from conftest import file_sha

from gracegraph.inventory import evaluate_artifact


def artifact(path, digest=None, inventory=None):
    result = {"id": "artifact", "path": path, "authority": "SOFTWARE"}
    if digest is not None:
        result["sha256"] = digest
    if inventory is not None:
        result["inventory"] = inventory
    return result


def test_missing_artifact_never_passes(tmp_path):
    result = evaluate_artifact(tmp_path, artifact("missing.txt"))
    assert result["state"] == "MISSING"


def test_checksum_mismatch_is_invalid(tmp_path):
    path = tmp_path / "value.txt"
    path.write_text("real", encoding="utf-8")
    result = evaluate_artifact(tmp_path, artifact("value.txt", "0" * 64))
    assert result["state"] == "INVALID"


def test_matching_checksum_is_verified(tmp_path):
    path = tmp_path / "value.txt"
    path.write_text("real", encoding="utf-8")
    result = evaluate_artifact(tmp_path, artifact("value.txt", file_sha(path)))
    assert result["state"] == "VERIFIED"


def make_inventory(tmp_path):
    root = tmp_path / "release"
    root.mkdir()
    data = root / "data.txt"
    data.write_text("bound\n", encoding="utf-8")
    manifest = root / "SHA256SUMS.txt"
    manifest.write_text(f"{file_sha(data)}  data.txt\n", encoding="utf-8")
    return root, manifest


def test_exact_inventory_passes(tmp_path):
    root, manifest = make_inventory(tmp_path)
    result = evaluate_artifact(
        tmp_path,
        artifact(
            "release/SHA256SUMS.txt",
            file_sha(manifest),
            {"root": "release", "manifest": "release/SHA256SUMS.txt"},
        ),
    )
    assert result["state"] == "VERIFIED"


def test_unmanifested_file_invalidates_inventory(tmp_path):
    root, manifest = make_inventory(tmp_path)
    (root / "UNMANIFESTED.txt").write_text("hidden", encoding="utf-8")
    result = evaluate_artifact(
        tmp_path,
        artifact(
            "release/SHA256SUMS.txt",
            file_sha(manifest),
            {"root": "release", "manifest": "release/SHA256SUMS.txt"},
        ),
    )
    assert result["state"] == "INVALID"
    assert result["inventory"]["unmanifested"] == ["UNMANIFESTED.txt"]


def test_listed_but_missing_file_invalidates_inventory(tmp_path):
    root, manifest = make_inventory(tmp_path)
    manifest.write_text(f"{'0' * 64}  absent.txt\n", encoding="utf-8")
    result = evaluate_artifact(
        tmp_path,
        artifact(
            "release/SHA256SUMS.txt",
            file_sha(manifest),
            {"root": "release", "manifest": "release/SHA256SUMS.txt"},
        ),
    )
    assert result["state"] == "INVALID"
    assert result["inventory"]["listed_but_missing"] == ["absent.txt"]


def test_inventory_symlink_is_invalid(tmp_path):
    root, manifest = make_inventory(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    (root / "escape.txt").symlink_to(outside)
    result = evaluate_artifact(
        tmp_path,
        artifact(
            "release/SHA256SUMS.txt",
            file_sha(manifest),
            {"root": "release", "manifest": "release/SHA256SUMS.txt"},
        ),
    )
    assert result["state"] == "INVALID"


def test_hardlinked_artifact_is_invalid(tmp_path):
    import os

    source = tmp_path / "source.txt"
    linked = tmp_path / "linked.txt"
    source.write_text("same inode", encoding="utf-8")
    os.link(source, linked)
    result = evaluate_artifact(tmp_path, artifact("linked.txt", file_sha(linked)))
    assert result["state"] == "INVALID"
    assert any("hard-linked" in reason for reason in result["reasons"])
