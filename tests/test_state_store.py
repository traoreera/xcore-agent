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
