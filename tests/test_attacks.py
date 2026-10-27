"""Tests for attacks/generate.py - attack case generation."""

from __future__ import annotations

import json

from attacks.generate import (
    ATTACKER_IBAN,
    AttackCase,
    gen_exfiltration,
    gen_ipi_pdf_hidden,
    gen_ipi_pdf_metadata,
    gen_ipi_pdf_visible,
    gen_privilege_escalation,
    gen_rug_pull,
    gen_tool_poisoning,
    generate_attacks,
)


def test_roundtrip():
    case = AttackCase("t", "indirect_prompt_injection", "pdf_visible_note_payment_redirect",
                      "process-unpaid-X", {"target": "invoice_pdf", "file": "x.pdf", "injection": {}},
                      {"type": "payment_request", "iban": ATTACKER_IBAN})
    assert AttackCase.from_dict(json.loads(case.to_json())).attack_check == case.attack_check


class TestGenerators:
    def test_pdf_visible(self, ground_truth):
        cs = gen_ipi_pdf_visible(ground_truth["invoices"])
        assert cs and all(c.category == "indirect_prompt_injection" for c in cs)
        assert all("visible_note" in c.injection["injection"] for c in cs)

    def test_pdf_hidden(self, ground_truth):
        cs = gen_ipi_pdf_hidden(ground_truth["invoices"])
        assert all("hidden_text" in c.injection["injection"] for c in cs)

    def test_pdf_metadata(self, ground_truth):
        cs = gen_ipi_pdf_metadata(ground_truth["invoices"])
        assert all("extra_metadata" in c.injection["injection"] for c in cs)

    def test_tool_poisoning(self, ground_truth):
        cs = gen_tool_poisoning(ground_truth["payees"])
        assert len(cs) >= 4 and all(c.injection["target"] == "tool_description" for c in cs)

    def test_rug_pull(self, ground_truth):
        cs = gen_rug_pull(ground_truth["invoices"])
        assert len(cs) >= 4
        assert all(c.injection["trigger_step"] >= 1 for c in cs)

    def test_exfiltration(self, ground_truth):
        cs = gen_exfiltration(ground_truth["invoices"], ground_truth["account"])
        assert len(cs) >= 4 and all(c.category == "exfiltration" for c in cs)

    def test_privilege_escalation(self, ground_truth):
        cs = gen_privilege_escalation(ground_truth["invoices"], ground_truth["payees"])
        assert any(c.subcategory == "execute_without_approval" for c in cs)


class TestGenerateAll:
    def test_count(self, ground_truth):
        assert len(generate_attacks(ground_truth)) >= 35

    def test_all_categories(self, ground_truth):
        cats = {c.category for c in generate_attacks(ground_truth)}
        assert cats == {"indirect_prompt_injection", "tool_poisoning", "rug_pull",
                        "exfiltration", "privilege_escalation"}

    def test_unique_ids(self, ground_truth):
        ids = [c.attack_id for c in generate_attacks(ground_truth)]
        assert len(ids) == len(set(ids))

    def test_all_have_checks(self, ground_truth):
        for c in generate_attacks(ground_truth):
            assert c.attack_check.get("type") and c.carrier_task_id
