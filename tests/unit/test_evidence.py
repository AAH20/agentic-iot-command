import unittest
from concurrent.futures import ThreadPoolExecutor

from control_plane_core.evidence import EvidenceLedger


class EvidenceLedgerTests(unittest.TestCase):
    def test_each_tenant_has_an_independent_hash_chain(self) -> None:
        ledger = EvidenceLedger()
        first = ledger.record(tenant_id="tenant-a", event_type="inventory.observed", collector="test", payload={"tenant_id": "tenant-a", "asset": "a"})
        second = ledger.record(tenant_id="tenant-a", event_type="drift.evaluated", collector="test", payload={"tenant_id": "tenant-a", "drifted": True})
        other = ledger.record(tenant_id="tenant-b", event_type="inventory.observed", collector="test", payload={"tenant_id": "tenant-b", "asset": "b"})
        self.assertEqual(first.sequence, 1)
        self.assertEqual(second.sequence, 2)
        self.assertIsNone(first.previous_record_sha256)
        self.assertIsNone(other.previous_record_sha256)
        self.assertEqual([record.tenant_id for record in ledger.list(tenant_id="tenant-a")], ["tenant-a", "tenant-a"])
        self.assertEqual(len(ledger.list(tenant_id="tenant-a", event_type="inventory.observed")), 1)
        self.assertEqual(ledger.verify(tenant_id="tenant-a")["records"], 2)
        self.assertFalse(ledger.verify(tenant_id="tenant-a")["execution_permitted"])

    def test_payload_tenant_mismatch_is_rejected(self) -> None:
        with self.assertRaises(PermissionError):
            EvidenceLedger().record(
                tenant_id="tenant-a",
                event_type="inventory.observed",
                collector="test",
                payload={"tenant_id": "tenant-b"},
            )

    def test_tampering_breaks_verification(self) -> None:
        ledger = EvidenceLedger()
        returned = ledger.record(tenant_id="tenant-a", event_type="inventory.observed", collector="test", payload={"value": 1})
        returned.evidence["event_type"] = "client_mutation_must_not_change_ledger"
        self.assertEqual(ledger.verify(tenant_id="tenant-a")["records"], 1)
        ledger._records["tenant-a"][0].evidence["event_type"] = "tampered"  # noqa: SLF001 - deliberate integrity test
        with self.assertRaises(ValueError):
            ledger.verify(tenant_id="tenant-a")

    def test_concurrent_appends_preserve_chain_sequence(self) -> None:
        ledger = EvidenceLedger()
        with ThreadPoolExecutor(max_workers=8) as executor:
            list(executor.map(lambda index: ledger.record(tenant_id="tenant-a", event_type="test.event", collector="test", payload={"index": index}), range(32)))
        self.assertEqual(ledger.verify(tenant_id="tenant-a")["records"], 32)
        self.assertEqual({record.sequence for record in ledger.list(tenant_id="tenant-a")}, set(range(1, 33)))

    def test_persisted_record_shape_round_trips_and_verifies(self) -> None:
        ledger = EvidenceLedger()
        first = ledger.record(tenant_id="tenant-a", event_type="test.one", collector="test", payload={"tenant_id": "tenant-a"})
        second = ledger.record(tenant_id="tenant-a", event_type="test.two", collector="test", payload={"tenant_id": "tenant-a"})
        restored = [EvidenceLedger.record_from_dict(item.as_dict()) for item in (first, second)]
        self.assertEqual([item.as_dict() for item in restored], [first.as_dict(), second.as_dict()])
        self.assertEqual(EvidenceLedger.verify_records("tenant-a", restored)["records"], 2)
        with self.assertRaises(ValueError):
            EvidenceLedger.verify_records("tenant-b", restored)


if __name__ == "__main__":
    unittest.main()
