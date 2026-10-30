#!/usr/bin/env python3
"""Run a Biscuits account-chain node using stake-free BFT finality."""
import argparse
import json
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


class BFTAPI(API):
    consensus_server = None
    consensus_key = None

    def do_POST(self):
        if urlparse(self.path).path != "/propose":
            return super().do_POST()
        try:
            self.body()
            chain = self.chain
            key = self.consensus_key
            signer = self.consensus_server.engine.signer
            proposer = key.public_key().public_bytes_raw().hex()
            selected = select_proposer(chain.validators, signer.height,
                                       self.consensus_server.engine.round)
            if proposer != selected:
                self.sendj(409, {"ok": False, "error": "this validator is not the proposer for the current round",
                                 "selected_proposer": selected})
                return
            block = chain.build_proposal(proposer)
            proposal = make_proposal(
                key, chain.id, signer.height, self.consensus_server.engine.round,
                block["hash"], self.consensus_server.engine.signer.validators_hash,
            )
            self.consensus_server.publish_proposal(proposal, block)
            self.sendj(200, {"ok": True, "proposal": proposal, "block": block})
        except Exception as exc:
            self.sendj(400, {"ok": False, "error": str(exc)})


def load_validator_key(path):
    key_path = Path(path)
    if not key_path.is_file():
        raise ValueError("validator private key file does not exist")
    if hasattr(os, "getuid"):
        mode = stat.S_IMODE(key_path.stat().st_mode)
        if mode & 0o077:
            raise ValueError("validator private key file must have permissions 0600")
    raw = key_path.read_text(encoding="ascii").strip()
    try:
        seed = bytes.fromhex(raw)
    except ValueError:
        raise ValueError("validator private key must be a 32-byte hex seed")
    if len(seed) != 32:
        raise ValueError("validator private key must be a 32-byte hex seed")
    return Ed25519PrivateKey.from_private_bytes(seed)


def bft_peer_sync_loop(chain, signer, interval=10):
    while True:
        for peer in list(chain.peers):
            synchronize_peer(chain, peer)
        if signer.height < len(chain.blocks):
            signer.catch_up(chain.blocks[signer.height:])
        elif signer.height > len(chain.blocks):
            raise RuntimeError("validator signer is ahead of the locally persisted finalized chain")
        time.sleep(interval)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="config.json")
    parser.add_argument("--data", default=None)
    args = parser.parse_args()
    config_path = Path(args.config)
    if not config_path.exists():
        raise SystemExit("Config missing. Supply a BFT configuration JSON file.")
    cfg = json.loads(config_path.read_text(encoding="utf-8"))
    chain = BFTChain(cfg, args.data or f"data-{cfg.get('port', 8333)}.json")
    key = load_validator_key(cfg["validator_private_key_file"])
    signer = ConsensusSigner(
        key, chain.id, chain.validators,
        cfg.get("validator_state_file", f"data-{cfg.get('port', 8333)}.consensus.json"),
        initial_height=len(chain.blocks),
    )
    if signer.height < len(chain.blocks):
        signer.catch_up(chain.blocks[signer.height:])
    if signer.height != len(chain.blocks):
        raise SystemExit("Validator signer height does not match finalized chain height; refusing to sign.")
    def persist_finalized(result):
        ok, message = chain.accept_finalized_block(
            result["block"], result["round"], result["commit_votes"]
        )
        if not ok:
            raise RuntimeError(message)

    engine = ConsensusEngine(
        signer, chain.validate_proposal_block, on_finalized=persist_finalized
    )
    consensus_server = ConsensusHTTPServer(
        engine,
        peers=cfg.get("consensus_peers", []),
        host=cfg.get("consensus_host", "127.0.0.1"),
        port=int(cfg.get("consensus_port", 8334)),
        tls_certfile=cfg.get("consensus_tls_certfile"),
        tls_keyfile=cfg.get("consensus_tls_keyfile"),
    )
    BFTAPI.chain = chain
    BFTAPI.peers = chain.peers
    BFTAPI.consensus_server = consensus_server
    BFTAPI.consensus_key = key

    threading.Thread(target=consensus_server.serve_forever, daemon=True).start()
    threading.Thread(target=bft_peer_sync_loop, args=(chain, signer), daemon=True).start()
    api_host = cfg.get("host", "127.0.0.1")
    if api_host not in ("127.0.0.1", "localhost", "::1"):
        consensus_server.shutdown()
        raise SystemExit(
            "The node API is loopback-only; expose it through an authenticated TLS reverse proxy."
        )
    http_server = ThreadingHTTPServer(
        (api_host, int(cfg.get("port", 8333))), BFTAPI
    )
    print(f"Biscuits BFT node on {cfg.get('host')}:{cfg.get('port')} "
          f"| chain={chain.id} | height={len(chain.blocks)-1} "
          f"| validators={len(chain.validators)}")
    try:
        http_server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        http_server.server_close()
        consensus_server.shutdown()


if __name__ == "__main__":
    main()
