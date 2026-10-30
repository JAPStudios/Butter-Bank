"""Persistent anti-equivocation and conservative locking for BFT validators."""
import json
import os
import tempfile
from pathlib import Path

from consensus import make_vote, normalize_validator_set, validator_set_hash, verify_vote, verify_commit_certificate


class ConsensusSigner:
    """Persist each signed vote before returning it; never unlock within a height."""

    def __init__(self, private_key, chain_id, validators, state_path, initial_height=1):
        if not isinstance(initial_height, int) or isinstance(initial_height, bool) or initial_height < 1:
            raise ValueError("initial_height must be a positive integer")
        self.key = private_key
        self.public_key = private_key.public_key().public_bytes_raw().hex()
        self.chain_id = chain_id
        self.validators = normalize_validator_set(validators)
        if self.public_key not in self.validators:
            raise ValueError("signing key is not a validator")
        self.validators_hash = validator_set_hash(validators)
        self.path = Path(state_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists():
            self.state = json.loads(self.path.read_text())
            if (not isinstance(self.state, dict)
                    or self.state.get("chain_id") != chain_id
                    or self.state.get("validator_set_hash") != self.validators_hash
                    or self.state.get("public_key") != self.public_key):
                raise ValueError("persisted state belongs to another validator or chain")
            height = self.state.get("height")
            if not isinstance(height, int) or isinstance(height, bool) or height < initial_height:
                raise ValueError("invalid persisted consensus height")
            if not isinstance(self.state.get("signed"), dict):
                raise ValueError("invalid persisted signing history")
            lock = self.state.get("lock")
            if lock is not None and (not isinstance(lock, str) or len(lock) != 64):
                raise ValueError("invalid persisted lock")
        else:
            self.state = {"chain_id": chain_id, "validator_set_hash": self.validators_hash,
                          "public_key": self.public_key, "height": initial_height,
                          "lock": None, "locked_round": None, "signed": {}}
            self._save()

    @property
    def height(self):
        return self.state["height"]

    def _save(self):
        data = json.dumps(self.state, sort_keys=True, separators=(",", ":")).encode()
        fd, name = tempfile.mkstemp(dir=self.path.parent, prefix=self.path.name)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(name, self.path)
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
                os.unlink(name)
            except OSError:
                pass
            raise

    def lock_from_prevotes(self, votes, round_number, block_hash):
        if not isinstance(round_number, int) or isinstance(round_number, bool) or round_number < 0:
            raise ValueError("round_number must be a non-negative integer")
        seen, power = set(), 0
        records = [{"public_key": k, "voting_power": v} for k, v in self.validators.items()]
        for vote in votes:
            if not verify_vote(vote, records, self.chain_id):
                raise ValueError("invalid prevote")
            key = vote["validator"]
            if (vote["height"] != self.height or vote["round"] != round_number
                    or vote["step"] != "prevote" or vote["block_hash"] != block_hash
                    or key in seen):
                raise ValueError("prevote does not match lock target or is duplicated")
            seen.add(key)
            power += self.validators[key]
        if power * 3 <= sum(self.validators.values()) * 2:
            raise ValueError("prevote quorum must exceed two-thirds")
        if self.state["lock"] not in (None, block_hash):
            raise ValueError("this signer version never unlocks within a height")
        locked_round = self.state.get("locked_round")
        if locked_round is not None and round_number < locked_round:
            raise ValueError("cannot move a persisted lock to an earlier round")
        self.state["lock"] = block_hash
        self.state["locked_round"] = round_number
        self._save()

    def sign_vote(self, round_number, step, block_hash):
        if step not in ("prevote", "precommit"):
            raise ValueError("invalid vote step")
        if self.state["lock"] not in (None, block_hash):
            raise ValueError("vote conflicts with persisted lock")
        if step == "precommit" and self.state["lock"] != block_hash:
            raise ValueError("precommit requires a persisted prevote quorum lock")
        slot = f"{self.height}:{round_number}:{step}"
        prior = self.state["signed"].get(slot)
        if prior:
            if prior["block_hash"] != block_hash:
                raise ValueError("refusing to double-sign")
            return prior["vote"]
        vote = make_vote(self.key, self.chain_id, self.height, round_number, step,
                         block_hash, self.validators_hash)
        self.state["signed"][slot] = {"block_hash": block_hash, "vote": vote}
        self._save()
        return vote

    def finalize(self, votes, round_number, block_hash):
        records = [{"public_key": k, "voting_power": v} for k, v in self.validators.items()]
        if not verify_commit_certificate(votes, records, self.chain_id,
                                         self.height, round_number, block_hash):
            raise ValueError("invalid commit certificate")
        if self.state["lock"] != block_hash:
            raise ValueError("finalized block does not match local lock")
        self.state["height"] += 1
        self.state["lock"] = None
        self.state["locked_round"] = None
        self._save()
