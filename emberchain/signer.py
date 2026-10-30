"""Persistent anti-equivocation and conservative locking for BFT validators."""
import json
import os
import stat
import fcntl
import tempfile
import threading
from pathlib import Path

from consensus import make_vote, normalize_validator_set, validator_set_hash, verify_vote, verify_commit_certificate, _is_hex


def _synchronized(method):
    def wrapper(self, *args, **kwargs):
        with self._lock:
            return method(self, *args, **kwargs)
    return wrapper


class ConsensusSigner:
    """Persist each signed vote before returning it; never unlock within a height."""

    def __init__(self, private_key, chain_id, validators, state_path, initial_height=1):
        if not isinstance(initial_height, int) or isinstance(initial_height, bool) or initial_height < 1:
            raise ValueError("initial_height must be a positive integer")
        self._lock = threading.RLock()
        self.key = private_key
        self.public_key = private_key.public_key().public_bytes_raw().hex()
        self.chain_id = chain_id
        self.validators = normalize_validator_set(validators)
        if self.public_key not in self.validators:
            raise ValueError("signing key is not a validator")
        self.validators_hash = validator_set_hash(validators)
        self.path = Path(state_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock_path = self.path.with_name(self.path.name + ".lock")
        if self.lock_path.is_symlink():
            raise ValueError("validator state lock path must not be a symbolic link")
        lock_flags = os.O_CREAT | os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            lock_flags |= os.O_NOFOLLOW
        self._lock_fd = os.open(self.lock_path, lock_flags, 0o600)
        os.fchmod(self._lock_fd, 0o600)
        try:
            fcntl.flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(self._lock_fd)
            self._lock_fd = None
            raise RuntimeError("validator state is already in use by another process")
        if self.path.is_symlink():
            raise ValueError("validator state file must not be a symbolic link")
        if self.path.exists():
            metadata = self.path.stat()
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError("validator state path must be a regular file")
            if metadata.st_mode & 0o077:
                raise ValueError("validator state file must have permissions 0600")
            self.state = json.loads(self.path.read_text(encoding="utf-8"))
            if (not isinstance(self.state, dict)
                    or self.state.get("chain_id") != chain_id
                    or self.state.get("validator_set_hash") != self.validators_hash
                    or self.state.get("public_key") != self.public_key):
                raise ValueError("persisted state belongs to another validator or chain")
            height = self.state.get("height")
            if not isinstance(height, int) or isinstance(height, bool) or height < 1:
                raise ValueError("invalid persisted consensus height")
            if not isinstance(self.state.get("signed"), dict):
                raise ValueError("invalid persisted signing history")
            if "round" not in self.state:
                self.state["round"] = 0
            if (not isinstance(self.state["round"], int) or isinstance(self.state["round"], bool)
                    or self.state["round"] < 0):
                raise ValueError("invalid persisted consensus round")
            lock = self.state.get("lock")
            if lock is not None and not _is_hex(lock, 32):
                raise ValueError("invalid persisted lock")
            locked_round = self.state.get("locked_round")
            if lock is None and locked_round is not None:
                raise ValueError("persisted lock round exists without a lock")
            if lock is not None and (
                not isinstance(locked_round, int) or isinstance(locked_round, bool)
                or locked_round < 0 or locked_round > self.state["round"]
            ):
                raise ValueError("invalid persisted lock round")
            for slot, entry in self.state["signed"].items():
                if not isinstance(slot, str) or not isinstance(entry, dict):
                    raise ValueError("invalid persisted signing record")
                parts = slot.split(":")
                if len(parts) != 3:
                    raise ValueError("invalid persisted signing slot")
                try:
                    signed_height, signed_round = int(parts[0]), int(parts[1])
                except ValueError:
                    raise ValueError("invalid persisted signing slot")
                if (signed_height < 1 or signed_round < 0
                        or (signed_height == height and signed_round > self.state["round"])
                        or parts[2] not in ("prevote", "precommit")
                        or not _is_hex(entry.get("block_hash"), 32)
                        or not isinstance(entry.get("vote"), dict)):
                    raise ValueError("invalid persisted signing record")
                vote = entry["vote"]
                if (not verify_vote(vote, [
                        {"public_key": key, "voting_power": power}
                        for key, power in self.validators.items()
                    ], chain_id)
                        or vote.get("validator") != self.public_key
                        or vote.get("height") != signed_height
                        or vote.get("round") != signed_round
                        or vote.get("step") != parts[2]
                        or vote.get("block_hash") != entry["block_hash"]):
                    raise ValueError("persisted signing record failed signature validation")
                if (signed_height == height and parts[2] == "precommit"
                        and (lock is None or entry["block_hash"] != lock)):
                    raise ValueError("persisted precommit conflicts with the current lock")
        else:
            self.state = {"chain_id": chain_id, "validator_set_hash": self.validators_hash,
                          "public_key": self.public_key, "height": initial_height,
                          "round": 0, "lock": None, "locked_round": None, "signed": {}}
            self._save()

    def close(self):
        """Release the exclusive process lock when this validator stops."""
        if getattr(self, "_lock_fd", None) is not None:
            fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
            os.close(self._lock_fd)
            self._lock_fd = None

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    @property
    def height(self):
        with self._lock:
            return self.state["height"]

    @property
    def current_round(self):
        with self._lock:
            return self.state["round"]

    @property
    def locked_block_hash(self):
        with self._lock:
            return self.state["lock"]

    @_synchronized
    def advance_round(self):
        self.state["round"] += 1
        self._save()
        return self.state["round"]

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

    @_synchronized
    def lock_from_prevotes(self, votes, round_number, block_hash):
        if not isinstance(round_number, int) or isinstance(round_number, bool) or round_number < 0:
            raise ValueError("round_number must be a non-negative integer")
        if round_number != self.current_round:
            raise ValueError("prevote quorum is not for the current persisted round")
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

    @_synchronized
    def sign_vote(self, round_number, step, block_hash):
        if round_number != self.current_round:
            raise ValueError("refusing to sign outside the current persisted round")
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

    def _has_conflicting_precommit(self, height, block_hash):
        for slot, entry in self.state["signed"].items():
            parts = slot.split(":")
            if (len(parts) == 3 and parts[2] == "precommit"
                    and parts[0].isdigit() and int(parts[0]) == height
                    and entry.get("block_hash") != block_hash):
                return True
        return False

    @_synchronized
    def catch_up(self, finalized_blocks):
        """Advance over committed blocks, preserving evidence of conflicting local votes."""
        for block in finalized_blocks:
            height = self.height
            if not isinstance(block, dict) or block.get("height") != height:
                raise ValueError("finalized blocks are not contiguous from signer height")
            block_hash = block.get("hash")
            round_number = block.get("commit_round")
            votes = block.get("commit_certificate")
            records = [
                {"public_key": key, "voting_power": power}
                for key, power in self.validators.items()
            ]
            if not verify_commit_certificate(
                votes, records, self.chain_id, height, round_number, block_hash
            ):
                raise ValueError("cannot catch up over an invalid commit certificate")
            if self.state.get("lock") not in (None, block_hash):
                raise ValueError("finalized history conflicts with the persisted lock")
            for slot, entry in self.state["signed"].items():
                try:
                    signed_height = int(slot.split(":", 1)[0])
                except (ValueError, AttributeError):
                    raise ValueError("invalid persisted signing slot")
                if (signed_height == height and slot.split(":")[2] == "precommit"
                        and entry.get("block_hash") != block_hash):
                    raise ValueError("finalized history conflicts with a locally signed precommit")
            self.state["height"] = height + 1
            self.state["round"] = 0
            self.state["lock"] = None
            self.state["locked_round"] = None
            self._save()

    @_synchronized
    def finalize(self, votes, round_number, block_hash):
        records = [{"public_key": k, "voting_power": v} for k, v in self.validators.items()]
        if round_number != self.current_round:
            raise ValueError("commit certificate is not for the current persisted round")
        if not verify_commit_certificate(votes, records, self.chain_id,
                                         self.height, round_number, block_hash):
            raise ValueError("invalid commit certificate")
        if self.state["lock"] not in (None, block_hash):
            raise ValueError("finalized block conflicts with the persisted lock")
        if self._has_conflicting_precommit(self.height, block_hash):
            raise ValueError("finalized block conflicts with a locally signed precommit")
        self.state["height"] += 1
        self.state["round"] = 0
        self.state["lock"] = None
        self.state["locked_round"] = None
        self._save()
