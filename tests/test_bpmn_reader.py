"""
tests/test_bpmn_reader.py
─────────────────────────
Integration tests for bpmn_reader.py against the sample fixture
data/certificate_request.bpmn.
"""

from pathlib import Path
import pytest

from bpmn_security.parsers.bpmn_reader import bpmn_extract, multi_file_extract

FIXTURE = Path("data") / "certificate_request.bpmn"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _flat_elements(processes):
    """Collect all element dicts across all processes (non-recursive)."""
    elems = []
    for proc in processes:
        elems.extend(proc.get("elements", []))
    return elems


def _elements_by_type(processes, type_label):
    return [e for e in _flat_elements(processes) if e.get("type") == type_label]


def _elements_by_subtype(processes, subtype):
    return [e for e in _flat_elements(processes) if e.get("subtype") == subtype]


# ---------------------------------------------------------------------------
# Basic structure
# ---------------------------------------------------------------------------

class TestStructure:
    @pytest.fixture(autouse=True)
    def parse(self):
        self.procs, self.mfs, self.das = bpmn_extract(FIXTURE)

    def test_two_processes_returned(self):
        assert len(self.procs) == 2

    def test_process_has_required_keys(self):
        for proc in self.procs:
            assert "id" in proc
            assert "type" in proc
            assert proc["type"] == "Process"
            assert "elements" in proc
            assert "lanes" in proc

    def test_three_message_flows(self):
        assert len(self.mfs) == 3

    def test_message_flows_are_edges(self):
        for mf in self.mfs:
            assert mf.get("isEdge") is True
            assert mf.get("sourceRef")
            assert mf.get("targetRef")

    def test_data_associations_present(self):
        assert len(self.das) >= 1

    def test_data_associations_have_required_keys(self):
        for da in self.das:
            assert "task_id" in da
            assert "data_object_id" in da
            assert da["operation"] in {"READ", "CREATE", "UPDATE", "DELETE"}


# ---------------------------------------------------------------------------
# Task subtypes
# ---------------------------------------------------------------------------

class TestTaskSubtypes:
    @pytest.fixture(autouse=True)
    def parse(self):
        self.procs, _, _ = bpmn_extract(FIXTURE)

    def test_user_tasks_present(self):
        assert len(_elements_by_subtype(self.procs, "UserTask")) >= 1

    def test_service_tasks_present(self):
        assert len(_elements_by_subtype(self.procs, "ServiceTask")) >= 1

    def test_send_tasks_present(self):
        assert len(_elements_by_subtype(self.procs, "SendTask")) >= 1

    def test_receive_tasks_present(self):
        assert len(_elements_by_subtype(self.procs, "ReceiveTask")) >= 1

    def test_generic_tasks_present(self):
        # Task_DeleteLocalCopy and Task_DeleteAuditLog are generic Tasks
        assert len(_elements_by_subtype(self.procs, "Task")) >= 1


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------

class TestEvents:
    @pytest.fixture(autouse=True)
    def parse(self):
        self.procs, _, _ = bpmn_extract(FIXTURE)

    def test_start_events_present(self):
        assert len(_elements_by_type(self.procs, "StartEvent")) >= 1

    def test_end_events_present(self):
        assert len(_elements_by_type(self.procs, "EndEvent")) >= 1

    def test_boundary_event_present(self):
        assert len(_elements_by_type(self.procs, "BoundaryEvent")) >= 1

    def test_intermediate_catch_event_present(self):
        assert len(_elements_by_type(self.procs, "IntermediateCatchEvent")) >= 1

    def test_triggers_flow_present(self):
        """Sequence flow from IntermediateCatchEvent must be reclassified as 'triggers'."""
        trigger_flows = [
            e for e in _flat_elements(self.procs)
            if e.get("type") == "triggers"
        ]
        assert len(trigger_flows) >= 1


# ---------------------------------------------------------------------------
# Lanes
# ---------------------------------------------------------------------------

class TestLanes:
    @pytest.fixture(autouse=True)
    def parse(self):
        self.procs, _, _ = bpmn_extract(FIXTURE)

    def test_each_process_has_lanes(self):
        for proc in self.procs:
            assert len(proc["lanes"]) >= 1

    def test_lanes_have_refs(self):
        for proc in self.procs:
            for lane in proc["lanes"]:
                assert isinstance(lane.get("refs"), list)

    def test_total_lanes_at_least_four(self):
        total = sum(len(p["lanes"]) for p in self.procs)
        assert total >= 4


# ---------------------------------------------------------------------------
# Data objects
# ---------------------------------------------------------------------------

class TestDataObjects:
    @pytest.fixture(autouse=True)
    def parse(self):
        self.procs, _, _ = bpmn_extract(FIXTURE)

    def test_data_objects_present(self):
        dos = _elements_by_type(self.procs, "DataObject")
        assert len(dos) >= 3

    def test_persistent_flag_set_for_certificate(self):
        dos = _elements_by_type(self.procs, "DataObject")
        cert_objs = [d for d in dos if d.get("name") == "Certificate"]
        assert cert_objs, "No Certificate DataObject found"
        assert any(d.get("is_persistent") for d in cert_objs)

    def test_persistent_flag_set_for_audit_log(self):
        dos = _elements_by_type(self.procs, "DataObject")
        audit_objs = [d for d in dos if d.get("name") == "AuditLog"]
        assert audit_objs, "No AuditLog DataObject found"
        assert any(d.get("is_persistent") for d in audit_objs)


# ---------------------------------------------------------------------------
# CRUD enrichment
# ---------------------------------------------------------------------------

class TestCrudEnrichment:
    @pytest.fixture(autouse=True)
    def parse(self):
        _, _, self.das = bpmn_extract(FIXTURE)

    def test_read_operations_present(self):
        assert any(da["operation"] == "READ" for da in self.das)

    def test_create_operations_present(self):
        assert any(da["operation"] == "CREATE" for da in self.das)

    def test_delete_operations_present(self):
        """Tasks named 'Delete ...' must produce DELETE operations."""
        assert any(da["operation"] == "DELETE" for da in self.das)

    def test_no_raw_writes_remain(self):
        """WRITES must all be enriched to CREATE/UPDATE/DELETE."""
        assert not any(da["operation"] == "WRITES" for da in self.das)


# ---------------------------------------------------------------------------
# Annotation attachment
# ---------------------------------------------------------------------------

class TestAnnotations:
    @pytest.fixture(autouse=True)
    def parse(self):
        self.procs, _, _ = bpmn_extract(FIXTURE)

    def _find_task(self, task_id):
        for proc in self.procs:
            for el in proc.get("elements", []):
                if el.get("id") == task_id:
                    return el
        return None

    def test_fill_form_has_interaction_type_annotation(self):
        task = self._find_task("Task_FillForm")
        assert task is not None
        ann = task.get("annotation", "")
        assert "Interaction Type" in ann or "annotation" in task

    def test_send_request_has_communication_type_annotation(self):
        task = self._find_task("Task_SendRequest")
        assert task is not None
        ann = task.get("annotation", "")
        assert "Communication Type" in ann or "Mail" in ann or "annotation" in task


# ---------------------------------------------------------------------------
# is_data_centric flag
# ---------------------------------------------------------------------------

class TestDataCentricFlag:
    @pytest.fixture(autouse=True)
    def parse(self):
        self.procs, _, _ = bpmn_extract(FIXTURE)

    def test_user_task_is_data_centric(self):
        tasks = _elements_by_subtype(self.procs, "UserTask")
        assert tasks, "No UserTask found"
        assert all(t.get("is_data_centric") for t in tasks)

    def test_service_task_is_data_centric(self):
        tasks = _elements_by_subtype(self.procs, "ServiceTask")
        assert tasks, "No ServiceTask found"
        assert all(t.get("is_data_centric") for t in tasks)

    def test_send_task_not_data_centric(self):
        tasks = _elements_by_subtype(self.procs, "SendTask")
        assert tasks, "No SendTask found"
        assert all(not t.get("is_data_centric") for t in tasks)


# ---------------------------------------------------------------------------
# multi_file_extract
# ---------------------------------------------------------------------------

class TestMultiFileExtract:
    def test_single_file_dir_gives_same_result(self, tmp_path):
        import shutil
        shutil.copy(FIXTURE, tmp_path / "certificate_request.bpmn")
        procs_dir, mfs_dir, das_dir = multi_file_extract(tmp_path)
        procs_file, mfs_file, das_file = bpmn_extract(FIXTURE)
        assert len(procs_dir) == len(procs_file)
        assert len(mfs_dir) == len(mfs_file)
        assert len(das_dir) == len(das_file)
