"""
tests/test_bpmn_graph_storing.py
─────────────────────────────────
Unit tests for bpmn_graph_storing.py using a mocked Neo4j driver.
No live Neo4j instance is required.
"""

from unittest.mock import MagicMock, call, patch

import pytest

import bpmn_security.graph.bpmn_graph_storing as bgs


# ---------------------------------------------------------------------------
# Helpers — minimal fixture data
# ---------------------------------------------------------------------------

def _make_process(proc_id="Proc1", with_lane=True, with_task=True):
    elements = []
    lanes = []

    if with_task:
        elements.append({
            "id": "Task1", "type": "Task", "subtype": "UserTask",
            "name": "Do Something", "annotation": "Audit=High",
            "is_data_centric": True, "is_persistent": False,
        })

    # sequence flow
    elements.append({
        "id": "SF1", "type": "sequenceFlow", "isEdge": True,
        "source": "Start1", "target": "Task1",
    })

    # start event
    elements.append({
        "id": "Start1", "type": "StartEvent", "name": "Start",
    })

    if with_lane:
        lanes.append({
            "id": "Lane1", "type": "Lane", "name": "Lane",
            "refs": ["Task1", "Start1"],
            "elements": [],
        })

    return {
        "id": proc_id, "type": "Process", "name": "Test Process",
        "elements": elements,
        "lanes": lanes,
    }


def _make_driver_mock():
    """Return a mock Neo4j driver with session context manager."""
    tx = MagicMock()
    session = MagicMock()
    session.__enter__ = MagicMock(return_value=session)
    session.__exit__  = MagicMock(return_value=False)
    session.execute_write = MagicMock()
    driver = MagicMock()
    driver.session = MagicMock(return_value=session)
    return driver, session, tx


# ---------------------------------------------------------------------------
# _safe_props
# ---------------------------------------------------------------------------

class TestSafeProps:
    def test_strips_non_scalar_keys(self):
        props = {
            "id": "x", "name": "n", "elements": [1, 2], "lanes": [],
            "refs": ["a"], "count": 3, "flag": True,
        }
        result = bgs._safe_props(props)
        assert "elements" not in result
        assert "lanes" not in result
        assert "refs" not in result
        assert result["id"] == "x"
        assert result["count"] == 3
        assert result["flag"] is True

    def test_keeps_string_int_float_bool(self):
        props = {"s": "hello", "i": 1, "f": 1.5, "b": False}
        result = bgs._safe_props(props)
        assert result == {"s": "hello", "i": 1, "f": 1.5, "b": False}

    def test_strips_list_and_dict_values(self):
        props = {"ok": "yes", "bad_list": [1, 2], "bad_dict": {"a": 1}}
        result = bgs._safe_props(props)
        assert "bad_list" not in result
        assert "bad_dict" not in result
        assert result["ok"] == "yes"


# ---------------------------------------------------------------------------
# _resolve_credentials — hard-fail when NEO4J_PASSWORD absent
# ---------------------------------------------------------------------------

class TestResolveCredentials:
    def test_exits_when_password_missing(self, monkeypatch):
        monkeypatch.delenv("NEO4J_PASSWORD", raising=False)
        with pytest.raises(SystemExit):
            bgs._resolve_credentials()

    def test_uses_env_vars(self, monkeypatch):
        monkeypatch.setenv("NEO4J_URI",      "bolt://host:7687")
        monkeypatch.setenv("NEO4J_USER",     "bob")
        monkeypatch.setenv("NEO4J_PASSWORD", "secret")
        uri, user, pw = bgs._resolve_credentials()
        assert uri  == "bolt://host:7687"
        assert user == "bob"
        assert pw   == "secret"

    def test_defaults_applied(self, monkeypatch):
        monkeypatch.delenv("NEO4J_URI",  raising=False)
        monkeypatch.delenv("NEO4J_USER", raising=False)
        monkeypatch.setenv("NEO4J_PASSWORD", "pw")
        uri, user, _ = bgs._resolve_credentials()
        assert uri  == "bolt://localhost:7687"
        assert user == "neo4j"


# ---------------------------------------------------------------------------
# store_bpmn — mock driver, verify execute_write calls
# ---------------------------------------------------------------------------

class TestStoreBpmn:
    def _store(self, processes, message_flows=None, data_associations=None):
        mfs = message_flows or []
        das = data_associations or []
        driver_mock, session_mock, _ = _make_driver_mock()

        with patch.object(bgs, "_get_driver", return_value=driver_mock):
            bgs.store_bpmn(
                processes, mfs, das,
                uri="bolt://localhost:7687", user="neo4j", password="test",
            )

        return session_mock

    def test_execute_write_called_at_least_once(self):
        proc = _make_process()
        session = self._store([proc])
        assert session.execute_write.call_count >= 1

    def test_first_call_is_delete_all(self):
        proc = _make_process()
        session = self._store([proc])
        first_call_fn = session.execute_write.call_args_list[0][0][0]
        assert first_call_fn is bgs._delete_all

    def test_driver_closed_after_store(self):
        proc = _make_process()
        driver_mock, _, _ = _make_driver_mock()
        with patch.object(bgs, "_get_driver", return_value=driver_mock):
            bgs.store_bpmn([proc], [], [],
                           uri="bolt://localhost:7687", user="neo4j", password="test")
        driver_mock.close.assert_called_once()

    def test_process_creation_called(self):
        proc = _make_process()
        session = self._store([proc])
        # _create_process_recursive should be in the execute_write calls
        calls = [c[0][0] for c in session.execute_write.call_args_list]
        assert bgs._create_process_recursive in calls

    def test_call_activity_linking_called(self):
        proc = _make_process()
        session = self._store([proc])
        calls = [c[0][0] for c in session.execute_write.call_args_list]
        assert bgs._link_call_activities in calls

    def test_multiple_processes_all_stored(self):
        procs = [_make_process("P1"), _make_process("P2")]
        session = self._store(procs)
        create_calls = [
            c for c in session.execute_write.call_args_list
            if c[0][0] is bgs._create_process_recursive
        ]
        assert len(create_calls) == 2


# ---------------------------------------------------------------------------
# _link_call_activities
# ---------------------------------------------------------------------------

class TestLinkCallActivities:
    def test_call_activity_creates_call_flow(self):
        tx = MagicMock()
        root = {
            "id": "Proc1",
            "elements": [{
                "id": "CA1",
                "type": "CallActivity",
                "calledElement": "Proc2",
            }],
        }
        bgs._link_call_activities(tx, root)
        # Should have called _create_rel (via tx.run)
        tx.run.assert_called()

    def test_no_call_activities_no_call_flow(self):
        tx = MagicMock()
        root = {
            "id": "Proc1",
            "elements": [{"id": "T1", "type": "Task"}],
        }
        bgs._link_call_activities(tx, root)
        tx.run.assert_not_called()


# ---------------------------------------------------------------------------
# _create_lane_recursive
# ---------------------------------------------------------------------------

class TestCreateLaneRecursive:
    def test_lane_node_created(self):
        tx = MagicMock()
        lane = {"id": "Lane1", "type": "Lane", "name": "Test", "elements": [], "refs": []}
        bgs._create_lane_recursive(tx, lane, "Proc1")
        assert tx.run.call_count >= 2   # MERGE node + MERGE BELONGS_TO

    def test_nested_lane_recurses(self):
        tx = MagicMock()
        child = {"id": "Lane2", "type": "Lane", "name": "Child", "elements": [], "refs": []}
        parent = {"id": "Lane1", "type": "Lane", "name": "Parent", "elements": [child], "refs": []}
        bgs._create_lane_recursive(tx, parent, "Proc1")
        # At least 2 MERGE node calls + 2 BELONGS_TO calls
        assert tx.run.call_count >= 4
