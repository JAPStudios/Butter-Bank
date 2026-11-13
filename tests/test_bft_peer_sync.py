import threading
import unittest
from unittest.mock import patch

import bft_node


class _StopAfterCycle:
    def __init__(self):
        self.waited = []

    def is_set(self):
        return False

    def wait(self, interval):
        self.waited.append(interval)
        return True


class _StopAfterCycles:
    def __init__(self, cycles):
        self.cycles = cycles
        self.waited = []

    def is_set(self):
        return len(self.waited) >= self.cycles

    def wait(self, interval):
        self.waited.append(interval)
        return len(self.waited) >= self.cycles


class _Chain:
    def __init__(self):
        self.peers = ["unavailable", "healthy"]
        self.blocks = [{"height": 0}]
        self.lock = threading.Lock()


class _Engine:
    def __init__(self):
        self.snapshots = []
        self.retries = 0

    def catch_up_chain(self, blocks):
        self.snapshots.append(blocks)

    def retry_pending_finalization(self):
        self.retries += 1


class PeerSyncLoopTests(unittest.TestCase):
    def test_transient_peer_failure_does_not_stop_other_peers_or_retry_cycle(self):
        chain = _Chain()
        engine = _Engine()
        stop = _StopAfterCycle()
        contacted = []

        def sync(_chain, peer):
            contacted.append(peer)
            if peer == "unavailable":
                raise OSError("temporary network failure")
            return True

        with patch.object(bft_node, "synchronize_peer", side_effect=sync):
            with self.assertLogs(bft_node.LOGGER, level="WARNING") as captured:
                bft_node.bft_peer_sync_loop(chain, engine, interval=3, stop_event=stop)

        self.assertIn("unavailable", "\\n".join(captured.output))
        self.assertEqual(contacted, ["unavailable", "healthy"])
        self.assertEqual(engine.snapshots, [[{"height": 0}]])
        self.assertEqual(engine.retries, 1)
        self.assertEqual(stop.waited, [3.0])

    def test_sync_loop_rejects_invalid_intervals(self):
        for interval in (0, -1, float("inf"), float("nan"), True, "10"):
            with self.subTest(interval=interval):
                with self.assertRaises(ValueError):
                    bft_node.bft_peer_sync_loop(
                        _Chain(), _Engine(), interval=interval,
                        stop_event=_StopAfterCycle(),
                    )

    def test_catch_up_and_finalization_failures_are_retried_next_cycle(self):
        chain = _Chain()
        stop = _StopAfterCycles(2)

        class FlakyEngine(_Engine):
            def catch_up_chain(self, blocks):
                self.snapshots.append(blocks)
                if len(self.snapshots) == 1:
                    raise OSError("temporary chain catch-up failure")

            def retry_pending_finalization(self):
                self.retries += 1
                if self.retries == 1:
                    raise OSError("temporary finalization storage failure")

        engine = FlakyEngine()
        with patch.object(bft_node, "synchronize_peer", return_value=True):
            with self.assertLogs(bft_node.LOGGER, level="ERROR") as captured:
                bft_node.bft_peer_sync_loop(
                    chain, engine, interval=3, stop_event=stop
                )

        self.assertEqual(len(engine.snapshots), 2)
        self.assertEqual(engine.retries, 2)
        self.assertEqual(stop.waited, [3.0, 3.0])
        log_output = "\\n".join(captured.output)
        self.assertIn("BFT chain catch-up failed", log_output)
        self.assertIn("BFT pending finalization retry failed", log_output)

    def test_validator_set_recovery_is_retried_after_transient_failure(self):
        chain = _Chain()
        chain.validators = [{"public_key": "validator-a", "voting_power": 1}]
        chain.validators_hash = "new-validator-set"
        chain.validator_activation_height = 2
        stop = _StopAfterCycles(2)

        class RecoveringEngine(_Engine):
            def __init__(self):
                super().__init__()
                self.validator_set_hash = "old-validator-set"
                self.validator_activation_height = 1
                self.pending_validator_recovery = True
                self.activations = []

            def activate_validator_set(
                self, validators, signer, activation_height, chain_height
            ):
                self.activations.append(
                    (validators, signer, activation_height, chain_height)
                )
                self.validator_set_hash = chain.validators_hash
                self.validator_activation_height = activation_height
                self.pending_validator_recovery = False

        engine = RecoveringEngine()
        recovery_calls = []

        def recover():
            recovery_calls.append(True)
            if len(recovery_calls) == 1:
                raise OSError("temporary validator-state recovery failure")
            return {
                "validators": chain.validators,
                "signer": None,
                "activation_height": chain.validator_activation_height,
                "chain_height": len(chain.blocks),
            }

        with patch.object(bft_node, "synchronize_peer", return_value=True):
            with self.assertLogs(bft_node.LOGGER, level="ERROR") as captured:
                bft_node.bft_peer_sync_loop(
                    chain, engine, interval=3, stop_event=stop,
                    on_validator_set=recover,
                )

        self.assertEqual(len(recovery_calls), 2)
        self.assertEqual(len(engine.activations), 1)
        self.assertEqual(engine.activations[0][2:], (2, 1))
        self.assertEqual(engine.snapshots, [[{"height": 0}]])
        self.assertIn(
            "BFT chain catch-up failed; will retry next cycle",
            "\\n".join(captured.output),
        )


if __name__ == "__main__":
    unittest.main()
