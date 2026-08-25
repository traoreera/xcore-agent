from xcore_agent.agent.state_store import StateStore


def test_read_returns_none_when_no_state(tmp_path):
    store = StateStore(tmp_path)
    assert store.read() is None


def test_write_then_read_roundtrip(tmp_path):
    store = StateStore(tmp_path)
    written = store.write(project_id="prj_x", version="1.2.3")
    read_back = store.read()
    assert read_back == written
    assert read_back.version == "1.2.3"
    assert read_back.project_id == "prj_x"


def test_write_persists_under_dot_xcore(tmp_path):
    store = StateStore(tmp_path)
    store.write(project_id="prj_x", version="1.0.0")
    assert (tmp_path / ".xcore" / "state.json").is_file()


def test_write_overwrites_previous_state(tmp_path):
    store = StateStore(tmp_path)
    store.write(project_id="prj_x", version="1.0.0")
    store.write(project_id="prj_x", version="2.0.0")
    assert store.read().version == "2.0.0"


def test_namespaced_stores_do_not_collide_on_shared_project_root(tmp_path):
    # Two MarketplaceWatchers (one per slug) polling the SAME project_root —
    # without namespace, both would read/write the same state.json and
    # clobber each other's recorded version on every check.
    xauth_store = StateStore(tmp_path, namespace="xauth")
    xdevkeys_store = StateStore(tmp_path, namespace="xdevkeys")

    xauth_store.write(project_id="xauth", version="1.0.0")
    xdevkeys_store.write(project_id="xdevkeys", version="2.0.0")

    assert xauth_store.read().version == "1.0.0"
    assert xdevkeys_store.read().version == "2.0.0"
    assert (tmp_path / ".xcore" / "state-xauth.json").is_file()
    assert (tmp_path / ".xcore" / "state-xdevkeys.json").is_file()


def test_namespaced_store_does_not_share_file_with_unnamespaced_default(tmp_path):
    default_store = StateStore(tmp_path)
    default_store.write(project_id="prj_x", version="1.0.0")

    namespaced_store = StateStore(tmp_path, namespace="xauth")
    assert namespaced_store.read() is None
