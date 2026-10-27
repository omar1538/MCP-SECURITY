"""Tests for eval/tasks.py - benign task suite construction."""

from __future__ import annotations

import json

from eval.tasks import Task, _process_task, build_task_suite, load_tasks


class TestProcessTask:
    def _inv(self, status: str) -> dict:
        return {
            "invoice_no": "INV-2026-1000", "file": "INV-2026-1000.pdf", "vendor": "Test Vendor SAS",
            "iban": "GB33BUKB20201555555555", "total": 1234.56, "status": status,
            "payment_txns": ["TXN-00001", "TXN-00002"] if status == "duplicate_payment" else ["TXN-00001"],
        }

    def test_unpaid_creates_payment(self):
        task = _process_task(self._inv("unpaid"))
        assert task.family == "process_unpaid"
        assert "create_payment_request" in [s["tool"] for s in task.oracle]

    def test_paid_no_payment(self):
        task = _process_task(self._inv("paid"))
        assert "create_payment_request" not in [s["tool"] for s in task.oracle]

    def test_anomaly_flags(self):
        task = _process_task(self._inv("duplicate_payment"))
        flag = next(c for c in task.check["checks"] if c.get("type") == "flagged")
        assert "INV-2026-1000" in flag["subject_ids"]

    def test_no_harm_present(self):
        def has_not(c):
            if c["type"] == "not":
                return True
            if "checks" in c:
                return any(has_not(x) for x in c["checks"])
            if "check" in c:
                return has_not(c["check"])
            return False
        for status in ("paid", "unpaid", "duplicate_payment", "amount_mismatch"):
            assert has_not(_process_task(self._inv(status)).check)

    def test_serialisation(self):
        task = _process_task(self._inv("unpaid"))
        assert Task.from_dict(json.loads(task.to_json())).check == task.check


class TestBuildSuite:
    def test_families(self, ground_truth, data_dir):
        fams = {t.family for t in build_task_suite(ground_truth, data_dir / "finance.db")}
        for f in ("process_unpaid", "process_paid", "categorize", "flag_anomaly",
                  "account_summary", "notify"):
            assert f in fams

    def test_counts(self, ground_truth, data_dir):
        tasks = build_task_suite(ground_truth, data_dir / "finance.db")
        assert sum(t.family.startswith("process_") for t in tasks) == len(ground_truth["invoices"])
        assert sum(t.family == "categorize" for t in tasks) == 4
        assert sum(t.family == "flag_anomaly" for t in tasks) == len(ground_truth["anomalies"])

    def test_unique_ids(self, ground_truth, data_dir):
        ids = [t.task_id for t in build_task_suite(ground_truth, data_dir / "finance.db")]
        assert len(ids) == len(set(ids))

    def test_all_have_oracle_and_check(self, ground_truth, data_dir):
        for t in build_task_suite(ground_truth, data_dir / "finance.db"):
            assert t.oracle and t.check.get("type")

    def test_unpaid_iban_matches(self, ground_truth, data_dir):
        tasks = build_task_suite(ground_truth, data_dir / "finance.db")
        inv_by_no = {i["invoice_no"]: i for i in ground_truth["invoices"]}
        for t in (t for t in tasks if t.family == "process_unpaid"):
            inv = inv_by_no[t.meta["invoice_no"]]
            pay = next(c for c in t.check["checks"] if c.get("type") == "payment_request")
            assert pay["iban"] == inv["iban"]

    def test_load_tasks(self, data_dir):
        assert load_tasks(data_dir / "ground_truth.json", data_dir / "finance.db")
