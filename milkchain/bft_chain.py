"""BFT-finalized account chain reusing the existing Biscuits transaction rules."""
import time
import json
import os
import tempfile
from pathlib import Path
from urllib.parse import urlparse
from node import Chain, bhash, canon, sha, MAX_TXS
from consensus import verify_commit_certificate, verify_prevote_certificate, validator_set_hash, select_proposer
from admission import validator_set_from_certificates


class BFTChain(Chain):
    """Account ledger whose blocks are accepted only with a >2/3 BFT certificate."""

    def __init__(self, cfg, path):
        if not isinstance(cfg, dict):
            raise ValueError("configuration must be a JSON object")
        if cfg.get("consensus") != "bft":
            raise ValueError("BFTChain requires consensus='bft'")
        if cfg.get("block_reward") != 0:
            raise ValueError(
                "BFT block rewards are disabled until supply and issuance rules are defined"
            )
        chain_path = Path(path)
        if chain_path.is_symlink():
            raise ValueError("BFT chain data file must not be a symbolic link")
        self.validators = validator_set_from_certificates(
            cfg.get("admission_certificates", []),
            cfg.get("admission_issuers", []),
            cfg.get("chain_id", ""),
            cfg.get("admission_epoch"),
        )
        self.validators_hash = validator_set_hash(self.validators)
        self.consensus_mode = "bft"
        super().__init__(cfg, path)
        for peer in self.peers:
            parsed = urlparse(peer)
            if (parsed.scheme not in ("http", "https") or not parsed.hostname
                    or parsed.username or parsed.password or parsed.path not in ("", "/")
                    or parsed.query or parsed.fragment):
                raise ValueError("invalid BFT chain peer URL")
            try:
                parsed.port
            except ValueError:
                raise ValueError("BFT chain peer URL has an invalid port")
            if parsed.scheme != "https" and parsed.hostname not in ("127.0.0.1", "localhost", "::1"):
                raise ValueError("remote BFT chain peers must use HTTPS")
        # The inherited proof-of-work validator is reused only for transaction
        # execution and structural checks; BFT certificates replace PoW.
        self.diff = 0

    def save(self):
        """Atomically persist BFT chain state before signer finalization."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps({
            "chain_id": self.id,
            "chain": self.blocks,
            "mempool": self.pool,
            "peers": self.peers,
        }, indent=2).encode("utf-8")
        descriptor, temporary = tempfile.mkstemp(
            prefix=self.path.name + ".", suffix=".tmp", dir=self.path.parent
        )
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            try:
                directory_fd = os.open(self.path.parent, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            except OSError:
                pass
        except Exception:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise

    def _verify_recovery_metadata(self, block, height, commit_round):
        fields = {"valid_round", "valid_round_certificate"}
        present = fields & set(block)
        if not present:
            return True
        if present != fields:
            return False
        valid_round = block["valid_round"]
        return (
            isinstance(valid_round, int)
            and not isinstance(valid_round, bool)
            and 0 <= valid_round < commit_round
            and verify_prevote_certificate(
                block["valid_round_certificate"], self.validators, self.id,
                height, valid_round, block["hash"],
            )
        )

    def valid_chain(self, blocks, require_certificates=True):
        try:
            if not isinstance(blocks, list) or not blocks:
                return False
            cleaned = []
            base_fields = {
                "height", "previous_hash", "timestamp", "transactions", "nonce", "hash"
            }
            bft_fields = {"commit_round", "commit_certificate"}
            recovery_fields = {"valid_round", "valid_round_certificate"}
            for index, block in enumerate(blocks):
                if index == 0:
                    cleaned.append(block)
                    continue
                if not isinstance(block, dict):
                    return False
                has_certificate = bft_fields <= set(block)
                has_recovery = recovery_fields <= set(block)
                if (set(block) - base_fields - bft_fields - recovery_fields
                        or bool(recovery_fields & set(block)) != has_recovery
                        or bool(bft_fields & set(block)) != has_certificate):
                    return False
                if require_certificates or index < len(blocks) - 1:
                    if not has_certificate or set(block) not in (
                        base_fields | bft_fields,
                        base_fields | bft_fields | recovery_fields,
                    ):
                        return False
                elif set(block) not in (
                    base_fields,
                    base_fields | bft_fields,
                    base_fields | bft_fields | recovery_fields,
                ):
                    return False
                if has_certificate:
                    round_number = block["commit_round"]
                    if (not isinstance(round_number, int) or isinstance(round_number, bool)
                            or round_number < 0):
                        return False
                    if not verify_commit_certificate(
                        block["commit_certificate"], self.validators, self.id,
                        index, round_number, block["hash"],
                    ):
                        return False
                    # Reward and collected fees are payable only to the
                    # deterministic proposer for this height and commit round.
                    if (not isinstance(block["transactions"], list)
                            or not block["transactions"]
                            or not isinstance(block["transactions"][0], dict)
                            or block["transactions"][0].get("recipient")
                            != select_proposer(self.validators, index, round_number)):
                        return False
                    if not self._verify_recovery_metadata(block, index, round_number):
                        return False
                cleaned.append({key: block[key] for key in base_fields})
            old_diff = self.diff
            self.diff = 0
            try:
                return super().valid_chain(cleaned)
            finally:
                self.diff = old_diff
        except (KeyError, TypeError, ValueError):
            return False

    def validate_proposal_block(self, block):
        """Return the canonical block hash for a valid next-height proposal."""
        with self.lock:
            if not isinstance(block, dict) or "commit_certificate" in block:
                return None
            if not self.valid_chain(self.blocks + [block], require_certificates=False):
                return None
            return bhash(block)

    def build_proposal(self, proposer, round_number=0):
        """Build a candidate for the deterministic proposer of this height/round."""
        expected = select_proposer(self.validators, len(self.blocks), round_number)
        if proposer != expected:
            raise ValueError("proposer is not selected for this height and round")
        with self.lock:
            balances, nonces = self.state()
            chosen, fees = [], 0
            for tx in sorted(self.pool, key=lambda item: (item["sender"], item["nonce"])):
                if len(chosen) >= MAX_TXS:
                    break
                ok, _ = self.check_tx(tx, balances, nonces)
                if not ok:
                    continue
                sender, recipient = tx["sender"], tx["recipient"]
                balances[sender] -= tx["amount"] + tx["fee"]
                balances[recipient] = balances.get(recipient, 0) + tx["amount"]
                nonces[sender] = tx["nonce"]
                nonces.setdefault(recipient, 0)
                chosen.append(tx)
                fees += tx["fee"]
            block = {
                "height": len(self.blocks),
                "previous_hash": self.blocks[-1]["hash"],
                "timestamp": max(int(time.time()), self.blocks[-1]["timestamp"]),
                "transactions": [{"type": "coinbase", "recipient": proposer,
                                 "amount": self.reward + fees}] + chosen,
                "nonce": 0,
            }
            block["hash"] = bhash(block)
            return block

    def mine(self, miner):
        return None, "proof-of-work mining is disabled; BFT validators finalize blocks"

    def accept_block(self, block):
        """Reject the inherited proof-of-work block endpoint in BFT mode."""
        return False, "BFT blocks must be accepted through consensus finality or verified chain synchronization"

    def accept_finalized_block(
        self, block, round_number, commit_votes,
        valid_round=None, valid_round_certificate=None,
    ):
        with self.lock:
            finalized = dict(block)
            finalized["commit_round"] = round_number
            finalized["commit_certificate"] = list(commit_votes)
            if valid_round is not None:
                finalized["valid_round"] = valid_round
                finalized["valid_round_certificate"] = list(valid_round_certificate or [])
            elif valid_round_certificate not in (None, [], ()):
                return False, "valid-round certificate supplied without valid_round"
            if len(self.blocks) > 1 and self.blocks[-1] == finalized:
                return True, "BFT block already finalized"
            if not self.valid_chain(self.blocks + [finalized]):
                return False, "invalid BFT-finalized block or commit certificate"
            previous_blocks = self.blocks
            previous_pool = self.pool
            self.blocks = list(self.blocks) + [finalized]
            included = {sha(canon(tx)) for tx in finalized["transactions"][1:]}
            self.pool = [tx for tx in self.pool if sha(canon(tx)) not in included]
            try:
                self._revalidate_pool()
                self.save()
            except Exception:
                self.blocks = previous_blocks
                self.pool = previous_pool
                raise
            return True, "BFT block finalized"

    def replace(self, blocks):
        """BFT finality forbids silently reorganizing already committed history."""
        with self.lock:
            if not self.valid_chain(blocks):
                return False, "candidate BFT chain invalid"
            if len(blocks) <= len(self.blocks):
                return False, "candidate BFT chain does not extend local finality"
            if blocks[:len(self.blocks)] != self.blocks:
                return False, "candidate conflicts with locally finalized history"
            previous_blocks = self.blocks
            previous_pool = self.pool
            included = {sha(canon(tx)) for block in blocks[1:] for tx in block["transactions"][1:]}
            self.blocks = list(blocks)
            self.pool = [tx for tx in self.pool if sha(canon(tx)) not in included]
            try:
                self._revalidate_pool()
                self.save()
            except Exception:
                self.blocks = previous_blocks
                self.pool = previous_pool
                raise
            return True, "BFT chain extended"
