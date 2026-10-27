"""Gateway policy: the configurable set of defense layers.

The gateway enforces five independent layers, each individually toggleable so the
Day-5 ablation can measure what each one contributes:

* ``pin_descriptions``  - hash-pin every tool description at startup; if it changes
  mid-run (a rug-pull), quarantine the tool and deny calls to it.
* ``iban_allowlist``    - a payment request may only target an IBAN that is already
  registered (a known payee or the operating account). Blocks payment redirects.
* ``require_approval``  - irreversible / high-privilege tools (execute_payment,
  update_payee_bank_details) are denied unless an explicit human approval token is
  present. Blocks privilege escalation.
* ``egress_filter``     - outbound email to a non-internal domain is denied, and so
  is any message carrying sensitive tokens (IBANs, balances) to an external party.
  Blocks data exfiltration.
* ``scan_untrusted``    - tool outputs that carry external content (document reads,
  transaction memos) are scanned for injection patterns, tagged with provenance,
  and wrapped in a quarantine banner before the model sees them.

Enforcement is deterministic and does not depend on the model being "smart enough"
to resist an injection: even a fully compromised agent that decides to call the
harmful tool is stopped at the gateway.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class GatewayPolicy:
    pin_descriptions: bool = True
    iban_allowlist: bool = True
    require_approval: bool = True
    egress_filter: bool = True
    scan_untrusted: bool = True

    internal_domain: str = "northwind.example"
    # Tools that must never run without an explicit approval token.
    approval_required_tools: tuple[str, ...] = (
        "execute_payment",
        "update_payee_bank_details",
    )
    # Tools whose output is external / attacker-influenceable content.
    untrusted_output_tools: tuple[str, ...] = ("read_document",)

    @classmethod
    def all_on(cls) -> GatewayPolicy:
        return cls()

    @classmethod
    def all_off(cls) -> GatewayPolicy:
        return cls(
            pin_descriptions=False,
            iban_allowlist=False,
            require_approval=False,
            egress_filter=False,
            scan_untrusted=False,
        )

    def only(self, *layers: str) -> GatewayPolicy:
        """Return a copy with only the named layers enabled."""
        off = GatewayPolicy.all_off()
        for layer in layers:
            setattr(off, layer, True)
        off.internal_domain = self.internal_domain
        return off

    def without(self, *layers: str) -> GatewayPolicy:
        """Return a copy with the named layers disabled (all others as-is)."""
        import copy

        p = copy.copy(self)
        for layer in layers:
            setattr(p, layer, False)
        return p

    @property
    def enabled_layers(self) -> list[str]:
        return [
            name
            for name in ("pin_descriptions", "iban_allowlist", "require_approval",
                         "egress_filter", "scan_untrusted")
            if getattr(self, name)
        ]


@dataclass
class Decision:
    allow: bool
    reason: str = ""
    layer: str = ""


@dataclass
class AuditEntry:
    server: str
    tool: str
    args: dict
    allowed: bool
    reason: str = ""
    layer: str = ""
    provenance: str = "trusted"  # trusted | untrusted | sanitized


@dataclass
class GatewayStats:
    calls: int = 0
    denied: int = 0
    rug_pulls_detected: int = 0
    injections_flagged: int = 0
    denied_by_layer: dict[str, int] = field(default_factory=dict)
