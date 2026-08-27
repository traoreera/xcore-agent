"""Unit tests for xcore_agent.crypto's tree-hashing primitive — see
test_packer.py for the end-to-end version (a real build never embeds these
files at all, not just "excludes them from the hash").
"""

from xcore_agent import crypto


def test_compute_tree_digest_changes_when_a_file_changes(tmp_path):
    (tmp_path / "a.txt").write_text("hello")
    before = crypto.compute_tree_digest(tmp_path)

    (tmp_path / "a.txt").write_text("goodbye")
    after = crypto.compute_tree_digest(tmp_path)

    assert before != after


def test_exclude_matches_exact_relative_path_only(tmp_path):
    (tmp_path / "manifest.json").write_text("{}")
    (tmp_path / "a.txt").write_text("hello")
    without_manifest = crypto.compute_tree_digest(tmp_path, exclude=frozenset({"manifest.json"}))

    (tmp_path / "manifest.json").write_text("{different content, still excluded}")
    still_without_manifest = crypto.compute_tree_digest(
        tmp_path, exclude=frozenset({"manifest.json"})
    )

    assert without_manifest == still_without_manifest


def test_skip_patterns_ignores_matching_files_anywhere_in_the_tree(tmp_path):
    (tmp_path / "a.txt").write_text("hello")
    baseline = crypto.compute_tree_digest(tmp_path)

    nested = tmp_path / ".venv" / "lib" / "site-packages"
    nested.mkdir(parents=True)
    (nested / "somepkg.py").write_text("# huge dependency tree\n")

    with_venv_but_skipped = crypto.compute_tree_digest(tmp_path, skip_patterns=(".venv",))
    with_venv_unfiltered = crypto.compute_tree_digest(tmp_path)

    assert with_venv_but_skipped == baseline  # .venv contributed nothing
    assert with_venv_unfiltered != baseline  # without skip_patterns, it does


def test_skip_patterns_glob_matches_extension_anywhere(tmp_path):
    (tmp_path / "a.txt").write_text("hello")
    baseline = crypto.compute_tree_digest(tmp_path)

    (tmp_path / "conf").mkdir()
    (tmp_path / "conf" / "private.pem").write_text("-----BEGIN PRIVATE KEY-----\n")

    filtered = crypto.compute_tree_digest(tmp_path, skip_patterns=("*.pem",))

    assert filtered == baseline


def test_skip_patterns_does_not_filter_env_template(tmp_path):
    # .env.template must survive a skip_patterns=(".env",) filter — it's a
    # legitimate deployment artifact, not the secret ".env" itself.
    (tmp_path / ".env.template").write_text("SECRET_KEY=\n")

    without_env = crypto.compute_tree_digest(tmp_path, skip_patterns=(".env",))
    unfiltered = crypto.compute_tree_digest(tmp_path)

    assert without_env == unfiltered
