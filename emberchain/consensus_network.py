"""HTTP transport for signed Biscuits BFT messages.

Use HTTPS peer URLs in deployment. Messages are authenticated by the consensus
signatures; transport encryption and peer admission remain deployment concerns.
"""
import hashlib
from collections import deque
import json
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from consensus import canonical_json, verify_vote
from engine import ConsensusEngine


class ConsensusHTTPServer:
    def __init__(self, engine, peers=(), on_finalized=None, host="127.0.0.1", port=8334):
        if not isinstance(engine, ConsensusEngine):
            raise TypeError("engine must be a ConsensusEngine")
        self.engine = engine
        self.peers = []
        for peer in peers:
            parsed = urlparse(peer)
            if (parsed.scheme not in ("https", "http") or not parsed.hostname
                    or parsed.username or parsed.password or parsed.path not in ("", "/")
                    or parsed.query or parsed.fragment):
                raise ValueError("invalid consensus peer URL")
            if parsed.scheme != "https" and parsed.hostname not in ("127.0.0.1", "localhost", "::1"):
                raise ValueError("non-loopback consensus peers must use HTTPS")
            self.peers.append(peer.rstrip("/"))
        self.on_finalized = on_finalized
        self.seen = set()
        self.seen_order = deque()
        self.seen_lock = threading.Lock()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                return

            def send_json(self, status, value):
                payload = canonical_json(value)
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def read_json(self):
                raw = self.headers.get("Content-Length")
                if raw is None:
                    raise ValueError("Content-Length is required")
                try:
                    size = int(raw)
                except ValueError:
                    raise ValueError("invalid Content-Length")
                if size < 1 or size > 1_000_000:
                    raise ValueError("invalid message size")
                value = json.loads(self.rfile.read(size))
                if not isinstance(value, dict):
                    raise ValueError("message must be a JSON object")
                return value

            def do_POST(self):
                path = urlparse(self.path).path
                try:
                    message = self.read_json()
                    if path == "/consensus/proposal":
                        proposal, block = message.get("proposal"), message.get("block")
                        if not isinstance(proposal, dict) or not isinstance(block, dict):
                            self.send_json(400, {"ok": False, "error": "proposal and block objects required"})
                            return
                        if not outer.engine.receive_proposal(proposal, block):
                            self.send_json(400, {"ok": False, "error": "invalid or out-of-round proposal"})
                            return
                        digest = outer._remember("proposal", message)
                        if digest:
                            outer._broadcast("/consensus/proposal", message)
                        # Every validator independently prevotes a validated proposal.
                        try:
                            outer.publish_vote(outer.engine.prevote(proposal["block_hash"]))
                        except ValueError:
                            # A persisted lock may correctly prevent this vote.
                            pass
                        self.send_json(200, {"ok": True})
                        return
                    if path == "/consensus/vote":
                        vote = message.get("vote")
                        if not isinstance(vote, dict):
                            self.send_json(400, {"ok": False, "error": "vote object required"})
                            return
                        if (not verify_vote(vote, outer.engine.validators, outer.engine.chain_id)
                                or vote["height"] != outer.engine.height
                                or vote["round"] != outer.engine.round):
                            self.send_json(400, {"ok": False, "error": "invalid or out-of-round vote"})
                            return
                        digest = outer._remember("vote", message)
                        if not digest:
                            self.send_json(200, {"ok": True, "duplicate": True})
                            return
                        action = outer.engine.receive_vote(vote)
                        if isinstance(action, dict) and "signature" in action:
                            # Count the local validator's own precommit before relay.
                            finalized = outer.engine.receive_vote(action)
                            outer._broadcast("/consensus/vote", {"vote": action})
                            if finalized is not None:
                                outer._finalize(finalized)
                        elif action is not None:
                            outer._finalize(action)
                        outer._broadcast("/consensus/vote", message)
                        self.send_json(200, {"ok": True})
                        return
                    self.send_json(404, {"ok": False, "error": "not found"})
                except (ValueError, TypeError, json.JSONDecodeError) as exc:
                    self.send_json(400, {"ok": False, "error": str(exc)})
                except Exception:
                    self.send_json(500, {"ok": False, "error": "internal consensus transport error"})

        self.server = ThreadingHTTPServer((host, port), Handler)

    def publish_proposal(self, proposal, block):
        """Validate a locally-created proposal and relay it to configured peers."""
        if not self.engine.receive_proposal(proposal, block):
            raise ValueError("local proposal failed consensus validation")
        message = {"proposal": proposal, "block": block}
        if self._remember("proposal", message):
            self._broadcast("/consensus/proposal", message)
        try:
            self.publish_vote(self.engine.prevote(proposal["block_hash"]))
        except ValueError:
            pass
        return True

    def publish_vote(self, vote):
        """Record and relay a locally signed vote."""
        if (not verify_vote(vote, self.engine.validators, self.engine.chain_id)
                or vote["height"] != self.engine.height
                or vote["round"] != self.engine.round):
            raise ValueError("local vote is invalid or out of round")
        message = {"vote": vote}
        if not self._remember("vote", message):
            return False
        action = self.engine.receive_vote(vote)
        if isinstance(action, dict) and "signature" in action:
            finalized = self.engine.receive_vote(action)
            self._broadcast("/consensus/vote", {"vote": action})
            if finalized is not None:
                self._finalize(finalized)
        elif action is not None:
            self._finalize(action)
        self._broadcast("/consensus/vote", message)
        return True

    def _remember(self, kind, message):
        digest = hashlib.sha256(kind.encode() + b":" + canonical_json(message)).hexdigest()
        with self.seen_lock:
            if digest in self.seen:
                return False
            self.seen.add(digest)
            self.seen_order.append(digest)
            if len(self.seen_order) > 100_000:
                expired = self.seen_order.popleft()
                self.seen.discard(expired)
            return True

    def _broadcast(self, path, message):
        payload = canonical_json(message)
        for peer in self.peers:
            request = urllib.request.Request(
                peer + path, data=payload,
                headers={"Content-Type": "application/json"}, method="POST"
            )
            try:
                with urllib.request.urlopen(request, timeout=3):
                    pass
            except Exception:
                continue

    def _finalize(self, result):
        if self.on_finalized is not None:
            self.on_finalized(result)

    def serve_forever(self):
        self.server.serve_forever()

    def shutdown(self):
        self.server.shutdown()
        self.server.server_close()
