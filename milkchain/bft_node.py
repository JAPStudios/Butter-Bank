#!/usr/bin/env python3
"""Run a Biscuits account-chain node using stake-free BFT finality."""
import argparse
import json
import logging
import math
import os
import stat
import time
import threading
from pathlib import Path
from http.server import ThreadingHTTPServer
from urllib.parse import urlparse

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from consensus import make_proposal, select_proposer
from consensus_network import ConsensusHTTPServer
from engine import ConsensusEngine
from signer import ConsensusSigner
from bft_chain import BFTChain
from node import API, synchronize_peer


LOGGER = logging.getLogger(__name__)


class BFTAPI(API):
    consensus_server = None
    consensus_key = None

    def do_POST(self):
        if urlparse(self.path).path != "/propose":
            return super().do_POST()
        try:
            request = self.body()
            if set(request) - {
                "block", "valid_round", "valid_round_certificate",
                "validator_transition",
            }:
                raise ValueError("proposal request contains unsupported fields")
            chain = self.chain
            key = self.consensus_key
            engine = self.consensus_server.engine
            proposer = key.public_key().public_bytes_raw().hex()
            selected = select_proposer(chain.validators, engine.height, engine.round)
            if proposer != selected:
                self.sendj(409, {"ok": False, "error": "this validator is not the proposer for the current round",
                                 "selected_proposer": selected})
                return
            block = request.get("block")
            if block is None:
                block = chain.build_proposal(
                    proposer, self.consensus_server.engine.round,
                    request.get("validator_transition"),
                )
            elif not isinstance(block, dict) or chain.validate_proposal_block(block) is None:
                raise ValueError("supplied proposal block is invalid for the current finalized chain")
            proposal = make_proposal(
                key, chain.id, engine.height, engine.round,
                block["hash"], engine.validator_set_hash,
                request.get("valid_round"),
                request.get("valid_round_certificate", []),
            )
            self.consensus_server.publish_proposal(proposal, block)
            self.sendj(200, {"ok": True, "proposal": proposal, "block": block})
        except Exception as exc:
            self.sendj(400, {"ok": False, "error": str(exc)})


def load_validator_key(path):
    key_path = Path(path)
    if key_path.is_symlink() or not key_path.is_file():
        raise ValueError("validator private key must be a regular non-symlink file")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(key_path, flags)
    except OSError as exc:
        raise ValueError("validator private key file cannot be opened safely") from exc
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode):
        os.close(descriptor)
        raise ValueError("validator private key must be a regular file")
    if hasattr(os, "getuid") and stat.S_IMODE(metadata.st_mode) & 0o077:
        os.close(descriptor)
        raise ValueError("validator private key file must have permissions 0600")
    with os.fdopen(descriptor, "r", encoding="ascii") as stream:
        raw = stream.read().strip()
    try:
        seed = bytes.fromhex(raw)
    except ValueError:
        raise ValueError("validator private key must be a 32-byte hex seed")
    if len(seed) != 32:
        raise ValueError("validator private key must be a 32-byte hex seed")
    return Ed25519PrivateKey.from_private_bytes(seed)


def validator_state_path(base_path, chain):
    """Use a distinct durable signing history for each validator-set activation."""
    base = Path(base_path)
    if chain.validator_activation_height == 1:
        return base
    return base.with_name(
        f"{base.name}.activation-{chain.validator_activation_height}."
        f"set-{chain.validators_hash}.json"
    )


def build_validator_activation(key, chain, base_state_path):
    """Create or recover signing state only for a key in the active validator set."""
    public_key = key.public_key().public_bytes_raw().hex()
    signer = None
    if public_key in {item["public_key"] for item in chain.validators}:
        signer = ConsensusSigner(
            key, chain.id, chain.validators,
            validator_state_path(base_state_path, chain),
            initial_height=chain.validator_activation_height,
        )
        try:
            if signer.height < len(chain.blocks):
                signer.catch_up(chain.blocks[signer.height:])
            if signer.height != len(chain.blocks):
                raise ValueError(
                    "validator signing history does not match the finalized chain height"
                )
        except Exception:
            signer.close()
            raise
    return {
        "validators": chain.validators,
        "signer": signer,
        "activation_height": chain.validator_activation_height,
        "chain_height": len(chain.blocks),
    }


def bft_peer_sync_loop(chain, engine, interval=10, stop_event=None, on_validator_set=None):
    """Keep peer synchronization alive across transient peer and storage failures."""
    if not isinstance(interval, (int, float)) or isinstance(interval, bool):
        raise ValueError("peer sync interval must be a finite positive number")
    try:
        interval = float(interval)
    except (OverflowError, ValueError):
        raise ValueError("peer sync interval must be a finite positive number")
    if not math.isfinite(interval) or interval <= 0:
        raise ValueError("peer sync interval must be a finite positive number")
    stop_event = stop_event if stop_event is not None else threading.Event()
    while not stop_event.is_set():
        # A single unavailable or malformed peer must not permanently kill
        # synchronization with every other peer.
        for peer in list(chain.peers):
            if stop_event.is_set():
                break
            try:
                synchronize_peer(chain, peer)
            except Exception:
                LOGGER.warning("BFT peer synchronization failed for %s", peer, exc_info=True)
                continue
        try:
            if (engine.pending_validator_recovery
                    or engine.validator_set_hash != chain.validators_hash
                    or engine.validator_activation_height != chain.validator_activation_height):
                activation = (
                    on_validator_set() if on_validator_set is not None else {
                        "validators": chain.validators, "signer": None,
                        "activation_height": chain.validator_activation_height,
                        "chain_height": len(chain.blocks),
                    }
                )
                engine.activate_validator_set(
                    activation["validators"], activation["signer"],
                    activation["activation_height"], activation["chain_height"],
                )
            with chain.lock:
                committed_snapshot = list(chain.blocks)
            engine.catch_up_chain(committed_snapshot)
        except Exception:
            # Retry from the next snapshot; never advance signer state from an
            # incomplete or unverified synchronization attempt.
            LOGGER.exception("BFT chain catch-up failed; will retry next cycle")
        try:
            engine.retry_pending_finalization()
        except Exception:
            # Finalization is retried on the next cycle after transient I/O
            # or chain-persistence failures.
            LOGGER.exception("BFT pending finalization retry failed; will retry next cycle")
        if stop_event.wait(interval):
            break



def bft_round_timeout_loop(consensus_server, initial_timeout=10.0,
                           maximum_timeout=120.0, stop_event=None):
    """Request certified round changes after inactivity, with bounded backoff.

    A locked or already-voted validator may request a later round, but its
    lock remains intact. Any conflicting prevote still requires a valid-round
    certificate checked and persisted by the signer.
    """
    if (not isinstance(initial_timeout, (int, float))
            or isinstance(initial_timeout, bool)
            or not isinstance(maximum_timeout, (int, float))
            or isinstance(maximum_timeout, bool)):
        raise ValueError("invalid BFT round timeout configuration")
    try:
        initial_timeout = float(initial_timeout)
        maximum_timeout = float(maximum_timeout)
    except (OverflowError, ValueError):
        raise ValueError("invalid BFT round timeout configuration")
    if (not math.isfinite(initial_timeout) or initial_timeout <= 0
            or not math.isfinite(maximum_timeout)
            or maximum_timeout < initial_timeout):
        raise ValueError("invalid BFT round timeout configuration")
    stop_event = stop_event or threading.Event()
    timeout = float(initial_timeout)
    observed = (consensus_server.engine.height, consensus_server.engine.round)
    while not stop_event.wait(timeout):
        engine = consensus_server.engine
        current = (engine.height, engine.round)
        if current != observed:
            observed = current
            timeout = float(initial_timeout)
            continue
        pending = (engine.signer.pending_round_change_targets
                   if engine.active else ())
        target_round = min(pending) if pending else engine.round + 1
        try:
            consensus_server.publish_round_change(target_round)
        except (RuntimeError, ValueError):
            # A prior vote or lock intentionally prevents an unsafe timeout vote.
            pass
        timeout = min(timeout * 2, float(maximum_timeout))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="config.json")
    parser.add_argument("--data", default=None)
    args = parser.parse_args()
    config_path = Path(args.config)
    if not config_path.exists():
        raise SystemExit("Config missing. Supply a BFT configuration JSON file.")
    cfg = json.loads(config_path.read_text(encoding="utf-8"))
    api_host = cfg.get("host", "127.0.0.1")
    if api_host not in ("127.0.0.1", "localhost", "::1"):
        raise SystemExit(
            "The node API is loopback-only; expose it through an authenticated TLS reverse proxy."
        )
    chain = BFTChain(cfg, args.data or f"data-{cfg.get('port', 8333)}.json")
    key = load_validator_key(cfg["validator_private_key_file"])
    base_state_path = cfg.get(
        "validator_state_file", f"data-{cfg.get('port', 8333)}.consensus.json"
    )
    initial_activation = build_validator_activation(key, chain, base_state_path)
    engine_ref = {}

    def persist_finalized(result):
        ok, message = chain.accept_finalized_block(
            result["block"], result["round"], result["commit_votes"],
            result.get("valid_round"), result.get("valid_round_certificate"),
        )
        if not ok:
            raise RuntimeError(message)
        engine = engine_ref.get("engine")
        if engine is not None and (
            engine.validator_set_hash != chain.validators_hash
            or engine.validator_activation_height != chain.validator_activation_height
        ):
            return {
                "validators": chain.validators,
                "activation_height": chain.validator_activation_height,
                "chain_height": len(chain.blocks),
            }
        return None

    def create_current_signer():
        return build_validator_activation(key, chain, base_state_path)["signer"]

    engine = ConsensusEngine(
        initial_activation["signer"],
        chain.validate_proposal_block,
        on_finalized=persist_finalized,
        validators=chain.validators,
        chain_id=chain.id,
        initial_height=len(chain.blocks),
        validator_activation_height=chain.validator_activation_height,
        on_validator_set=create_current_signer,
    )
    engine_ref["engine"] = engine

    def recover_synced_validator_set():
        return build_validator_activation(key, chain, base_state_path)

    try:
        consensus_server = ConsensusHTTPServer(
            engine,
            peers=cfg.get("consensus_peers", []),
            host=cfg.get("consensus_host", "127.0.0.1"),
            port=int(cfg.get("consensus_port", 8334)),
            tls_certfile=cfg.get("consensus_tls_certfile"),
            tls_keyfile=cfg.get("consensus_tls_keyfile"),
            tls_ca_file=cfg.get("consensus_tls_ca_file"),
            tls_client_certfile=cfg.get("consensus_tls_client_certfile"),
            tls_client_keyfile=cfg.get("consensus_tls_client_keyfile"),
            tls_peer_fingerprints=cfg.get("consensus_tls_peer_fingerprints", []),
        )
    except Exception:
        if engine.signer is not None:
            engine.signer.close()
        raise
    BFTAPI.chain = chain
    BFTAPI.peers = chain.peers
    BFTAPI.consensus_server = consensus_server
    BFTAPI.consensus_key = key

    try:
        http_server = ThreadingHTTPServer(
            (api_host, int(cfg.get("port", 8333))), BFTAPI
        )
    except Exception:
        consensus_server.server.server_close()
        if engine.signer is not None:
            engine.signer.close()
        raise

    consensus_thread = threading.Thread(
        target=consensus_server.serve_forever, daemon=True
    )
    consensus_thread.start()
    timeout_stop = threading.Event()
    timeout_thread = threading.Thread(
        target=bft_round_timeout_loop,
        args=(
            consensus_server,
            float(cfg.get("round_timeout_seconds", 10)),
            float(cfg.get("round_timeout_max_seconds", 120)),
            timeout_stop,
        ),
        daemon=True,
    )
    timeout_thread.start()
    peer_sync_stop = threading.Event()
    peer_sync_thread = threading.Thread(
        target=bft_peer_sync_loop,
        args=(chain, engine, 10, peer_sync_stop, recover_synced_validator_set),
        daemon=True,
    )
    peer_sync_thread.start()
    print(f"Milkchain BFT node on {cfg.get('host')}:{cfg.get('port')} "
          f"| chain={chain.id} | height={len(chain.blocks)-1} "
          f"| validators={len(chain.validators)}")
    try:
        http_server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        http_server.server_close()
        timeout_stop.set()
        peer_sync_stop.set()
        consensus_server.shutdown()
        timeout_thread.join(timeout=5)
        peer_sync_thread.join(timeout=5)
        consensus_thread.join(timeout=5)
        if engine.signer is not None:
            engine.signer.close()


if __name__ == "__main__":
    main()
