"""Event-driven BFT round coordinator.

This is a conservative first state machine, not a full Tendermint implementation.
It deliberately halts round advancement after a lock rather than attempting
unsafe unlock rules. A later protocol revision must implement and test the
complete locked-round/valid-round rules before production use.
"""
from collections import defaultdict
import threading

from consensus import (
    normalize_validator_set,
    verify_proposal,
    verify_vote,
)
from signer import ConsensusSigner


def _synchronized(method):
    def wrapper(self, *args, **kwargs):
        with self._lock:
            return method(self, *args, **kwargs)
    return wrapper


class ConsensusEngine:
    def __init__(self, signer: ConsensusSigner, block_validator, on_finalized=None):
        if not isinstance(signer, ConsensusSigner):
            raise TypeError("signer must be a ConsensusSigner")
        if not callable(block_validator):
            raise TypeError("block_validator must be callable")
        self._lock = threading.RLock()
        self.signer = signer
        self.chain_id = signer.chain_id
        self.validators = [
            {"public_key": key, "voting_power": power}
            for key, power in signer.validators.items()
        ]
        self.total_power = sum(signer.validators.values())
        self.block_validator = block_validator
        if on_finalized is not None and not callable(on_finalized):
            raise TypeError("on_finalized must be callable")
        self.on_finalized = on_finalized
        self.round = signer.current_round
        self.proposals = {}
        self.votes = defaultdict(dict)
        self.finalized = {}

    @property
    def height(self):
        return self.signer.height

    @_synchronized
    def receive_proposal(self, proposal, block):
        """Validate and cache a proposal; return False for any invalid input.

        block_validator(block) must return the canonical 32-byte block hash if
        the block is valid against the current finalized chain, else None.
        """
        if not verify_proposal(proposal, self.validators, self.chain_id):
            return False
        if proposal["height"] != self.height or proposal["round"] != self.round:
            return False
        try:
            calculated_hash = self.block_validator(block)
        except Exception:
            return False
        if calculated_hash != proposal["block_hash"]:
            return False
        self.proposals[proposal["block_hash"]] = block
        return True

    @_synchronized
    def prevote(self, block_hash):
        """Sign a prevote only for a locally validated proposal."""
        if block_hash not in self.proposals:
            raise ValueError("cannot prevote an unknown or invalid proposal")
        if self.signer.locked_block_hash not in (None, block_hash):
            raise ValueError("proposal conflicts with the persisted lock")
        return self.signer.sign_vote(self.round, "prevote", block_hash)

    @_synchronized
    def receive_vote(self, vote):
        """Record one authenticated vote and return a local action if quorum forms.

        Returns None, a signed precommit, or a finalized block record.
        Conflicting votes from one validator in one height/round/step are rejected.
        """
        if not verify_vote(vote, self.validators, self.chain_id):
            return None
        if vote["height"] != self.height or vote["round"] != self.round:
            return None
        slot = (vote["round"], vote["step"])
        prior = self.votes[slot].get(vote["validator"])
        if prior is not None:
            return None
        self.votes[slot][vote["validator"]] = vote
        matching = [
            item for item in self.votes[slot].values()
            if item["block_hash"] == vote["block_hash"]
        ]
        power = sum(self.signer.validators[item["validator"]] for item in matching)
        if power * 3 <= self.total_power * 2:
            return None

        if vote["step"] == "prevote":
            block_hash = vote["block_hash"]
            if block_hash not in self.proposals:
                return None
            try:
                self.signer.lock_from_prevotes(matching, self.round, block_hash)
                return self.signer.sign_vote(self.round, "precommit", block_hash)
            except ValueError:
                return None

        return self.retry_pending_finalization()

    @_synchronized
    def retry_pending_finalization(self):
        """Retry a quorum commit after a transient block-persistence failure."""
        slot = (self.round, "precommit")
        by_hash = defaultdict(list)
        for item in self.votes.get(slot, {}).values():
            by_hash[item["block_hash"]].append(item)
        for block_hash, matching in by_hash.items():
            power = sum(self.signer.validators[item["validator"]] for item in matching)
            if power * 3 <= self.total_power * 2:
                continue
            block = self.proposals.get(block_hash)
            if block is None:
                continue
            result = {
                "height": self.height,
                "round": self.round,
                "block_hash": block_hash,
                "block": block,
                "commit_votes": matching,
            }
            # Persist the finalized block before advancing signer height.
            if self.on_finalized is not None:
                try:
                    self.on_finalized(result)
                except Exception:
                    continue
            try:
                self.signer.finalize(matching, self.round, block_hash)
            except ValueError:
                continue
            self.finalized[result["height"]] = result
            self.round = 0
            self.proposals.clear()
            self.votes.clear()
            return result
        return None

    @_synchronized
    def catch_up(self, finalized_blocks):
        """Apply already-verified committed history and reset round-local state."""
        self.signer.catch_up(finalized_blocks)
        self.round = self.signer.current_round
        self.proposals.clear()
        self.votes.clear()

    @_synchronized
    def advance_round(self):
        """Advance only while unlocked; locked-round unlock rules are not yet safe."""
        if self.signer.locked_block_hash is not None:
            raise RuntimeError(
                "round advancement halted: safe locked-round unlock rules are not implemented"
            )
        self.round = self.signer.advance_round()
        self.proposals.clear()
        self.votes.clear()
        return self.round
