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
            bft_node.bft_peer_sync_loop(chain, engine, interval=3, stop_event=stop)

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


if __name__ == "__main__":
    unittest.main()
