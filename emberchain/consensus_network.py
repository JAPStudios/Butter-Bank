"""HTTP transport for signed Biscuits BFT messages.

Use HTTPS peer URLs in deployment. Messages are authenticated by the consensus
signatures; transport encryption and peer admission remain deployment concerns.
"""
import hashlib
from collections import deque
import time
import json
import os
import stat
import ssl
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from consensus import canonical_json, verify_vote, verify_round_change
from engine import ConsensusEngine


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False

    def __init__(self, server_address, handler_class, max_workers=64):
        if not isinstance(max_workers, int) or isinstance(max_workers, bool) or max_workers < 1:
            raise ValueError("max_workers must be a positive integer")
        self._request_slots = threading.BoundedSemaphore(max_workers)
        super().__init__(server_address, handler_class)

    def process_request(self, request, client_address):
        if not self._request_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._request_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._request_slots.release()


class ConsensusHTTPServer:
    def __init__(self, engine, peers=(), on_finalized=None, host="127.0.0.1", port=8334, tls_certfile=None, tls_keyfile=None):
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
            try:
                parsed.port
            except ValueError:
                raise ValueError("consensus peer URL has an invalid port")
            if parsed.scheme != "https" and parsed.hostname not in ("127.0.0.1", "localhost", "::1"):
                raise ValueError("non-loopback consensus peers must use HTTPS")
            normalized_peer = peer.rstrip("/")
            if normalized_peer not in self.peers:
                self.peers.append(normalized_peer)
        self.on_finalized = on_finalized
        self.seen = set()
        self.seen_order = deque()
        self.seen_lock = threading.Lock()
        self.request_history = {}
        self.request_lock = threading.Lock()
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

            def rate_allowed(self):
                address = self.client_address[0]
                now = time.monotonic()
                with outer.request_lock:
                    history = outer.request_history.get(address)
                    if history is None:
                        if len(outer.request_history) >= 10_000:
                            expired = [
                                ip for ip, events in outer.request_history.items()
                                if not events or now - events[-1] > 60
                            ]
                            for ip in expired:
                                outer.request_history.pop(ip, None)
                            if len(outer.request_history) >= 10_000:
                                return False
                        history = deque()
                        outer.request_history[address] = history
                    while history and now - history[0] > 60:
                        history.popleft()
                    if len(history) >= 600:
                        return False
                    history.append(now)
                    return True
    
            def do_POST(self):
                if not self.rate_allowed():
                    self.send_json(429, {"ok": False, "error": "consensus request rate limit exceeded"})
                    return
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
                    if path == "/consensus/round-change":
                        round_change = message.get("round_change")
                        if (not isinstance(round_change, dict)
                                or not verify_round_change(
                                    round_change, outer.engine.validators, outer.engine.chain_id
                                )
                                or round_change["height"] != outer.engine.height
                                or round_change["round"] <= outer.engine.round):
                            self.send_json(400, {"ok": False, "error": "invalid or stale round-change message"})
                            return
                        digest = outer._remember("round-change", message)
                        if not digest:
                            self.send_json(200, {"ok": True, "duplicate": True})
                            return
                        outer.engine.receive_round_change(round_change)
                        outer._broadcast("/consensus/round-change", message)
                        self.send_json(200, {"ok": True, "round": outer.engine.round})
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
                            pending = outer.engine.retry_pending_finalization()
                            if pending is not None:
                                outer._finalize(pending)
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

        self.server = BoundedThreadingHTTPServer((host, port), Handler, max_workers=64)
        if host not in ("127.0.0.1", "localhost", "::1") and not (tls_certfile and tls_keyfile):
            self.server.server_close()
            raise ValueError("non-loopback consensus listeners require a TLS certificate and private key")
        if bool(tls_certfile) != bool(tls_keyfile):
            self.server.server_close()
            raise ValueError("both TLS certificate and private key are required")
        if tls_certfile:
            if hasattr(os, "getuid"):
                key_mode = stat.S_IMODE(os.stat(tls_keyfile).st_mode)
                if key_mode & 0o077:
                    self.server.server_close()
                    raise ValueError("consensus TLS private key must have permissions 0600")
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                context.load_cert_chain(tls_certfile, tls_keyfile)
                self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
            except Exception:
                self.server.server_close()
                raise

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

    def publish_round_change(self, target_round):
        """Sign, persist, locally process, and relay a round-change request."""
        message = self.engine.request_round_change(target_round)
        envelope = {"round_change": message}
        if self._remember("round-change", envelope):
            self.engine.receive_round_change(message)
        # Re-broadcast idempotently so a lost first delivery can be recovered.
        self._broadcast("/consensus/round-change", envelope)
        return message

    def publish_vote(self, vote):
        """Record and relay a locally signed vote."""
        if (not verify_vote(vote, self.engine.validators, self.engine.chain_id)
                or vote["height"] != self.engine.height
                or vote["round"] != self.engine.round):
            raise ValueError("local vote is invalid or out of round")
        message = {"vote": vote}
        if not self._remember("vote", message):
            pending = self.engine.retry_pending_finalization()
            if pending is not None:
                self._finalize(pending)
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
