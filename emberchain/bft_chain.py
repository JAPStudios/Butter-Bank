"""BFT-finalized account chain reusing the existing Biscuits transaction rules."""
from node import Chain, bhash, canon, sha
from consensus import verify_commit_certificate, validator_set_hash
from admission import validator_set_from_certificates


class BFTChain(Chain):
    """Account ledger whose blocks are accepted only with a >2/3 BFT certificate."""

    def __init__(self, cfg, path):
        if cfg.get("consensus") != "bft":
            raise ValueError("BFTChain requires consensus='bft'")
        self.validators = validator_set_from_certificates(
            cfg.get("admission_certificates", []),
            cfg.get("admission_issuers", []),
            cfg.get("chain_id", ""),
            cfg.get("admission_epoch"),
        )
        self.validators_hash = validator_set_hash(self.validators)
        self.consensus_mode = "bft"
        super().__init__(cfg, path)
        # The inherited proof-of-work validator is reused only for transaction
        # execution and structural checks; BFT certificates replace PoW.
        self.diff = 0

    def valid_chain(self, blocks, require_certificates=True):
        try:
            if not isinstance(blocks, list) or not blocks:
                return False
            cleaned = []
            for index, block in enumerate(blocks):
                if index == 0:
                    cleaned.append(block)
                    continue
                if not isinstance(block, dict):
                    return False
                base_fields = {"height", "previous_hash", "timestamp", "transactions", "nonce", "hash"}
                bft_fields = {"commit_round", "commit_certificate"}
                if require_certificates or index < len(blocks) - 1:
                    if set(block) != base_fields | bft_fields:
                        return False
                    round_number = block["commit_round"]
                    if not isinstance(round_number, int) or isinstance(round_number, bool) or round_number < 0:
                        return False
                    if not verify_commit_certificate(
                        block["commit_certificate"], self.validators, self.id,
                        index, round_number, block["hash"],
                    ):
                        return False
                else:
                    if set(block) not in (base_fields, base_fields | bft_fields):
                        return False
                    if bft_fields <= set(block):
                        round_number = block["commit_round"]
                        if not isinstance(round_number, int) or isinstance(round_number, bool) or round_number < 0:
                            return False
                        if not verify_commit_certificate(
                            block["commit_certificate"], self.validators, self.id,
                            index, round_number, block["hash"],
                        ):
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

    def build_proposal(self, proposer):
        """Build a zero-work candidate block; it is not final until BFT commits it."""
        if not any(v["public_key"] == proposer for v in self.validators):
            raise ValueError("proposer is not an admitted validator")
        with self.lock:
            balances, nonces = self.state()
            chosen, fees = [], 0
            for tx in sorted(self.pool, key=lambda item: (item["sender"], item["nonce"])):
                if len(chosen) >= 100:
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
                "timestamp": max(int(__import__("time").time()), self.blocks[-1]["timestamp"]),
                "transactions": [{"type": "coinbase", "recipient": proposer,
                                 "amount": self.reward + fees}] + chosen,
                "nonce": 0,
            }
            block["hash"] = bhash(block)
            return block

    def mine(self, miner):
        return None, "proof-of-work mining is disabled; BFT validators finalize blocks"

    def accept_finalized_block(self, block, round_number, commit_votes):
        with self.lock:
            finalized = dict(block)
            finalized["commit_round"] = round_number
            finalized["commit_certificate"] = list(commit_votes)
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
