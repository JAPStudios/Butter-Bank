"""Event-driven BFT round coordinator with certificate-gated lock recovery."""
from collections import defaultdict
import threading

from consensus import (
    normalize_validator_set,
    verify_proposal,
    verify_vote,
    verify_round_change,
    verify_round_change_certificate,
    validator_set_hash,
)
from signer import ConsensusSigner


def _synchronized(method):
    def wrapper(self, *args, **kwargs):
        with self._lock:
            return method(self, *args, **kwargs)
    return wrapper


class ConsensusEngine:
    def __init__(
        self, signer: ConsensusSigner | None, block_validator, on_finalized=None,
        *, validators=None, chain_id=None, initial_height=None,
        validator_activation_height=1, on_validator_set=None,
    ):
        if signer is not None and not isinstance(signer, ConsensusSigner):
            raise TypeError("signer must be a ConsensusSigner or None")
        if signer is None and (validators is None or not isinstance(chain_id, str)
                               or not isinstance(initial_height, int)
                               or isinstance(initial_height, bool) or initial_height < 1):
            raise ValueError("observer engines require validators, chain_id and initial_height")
        if not callable(block_validator):
            raise TypeError("block_validator must be callable")
        self._lock = threading.RLock()
        self.signer = signer
        self.chain_id = signer.chain_id if signer is not None else chain_id
        validator_map = normalize_validator_set(
            validators if signer is None else signer.validators
        )
        self.validator_power = validator_map
        self.validators = [
            {"public_key": key, "voting_power": power}
            for key, power in validator_map.items()
        ]
        self.validator_set_hash = validator_set_hash(self.validators)
        if (not isinstance(validator_activation_height, int)
                or isinstance(validator_activation_height, bool)
                or validator_activation_height < 1
                or validator_activation_height > self._height):
            raise ValueError("validator activation height is invalid")
        self.validator_activation_height = validator_activation_height
        self.total_power = sum(validator_map.values())
        self.active = signer is not None
        self._height = signer.height if signer is not None else initial_height
        self.block_validator = block_validator
        if on_finalized is not None and not callable(on_finalized):
            raise TypeError("on_finalized must be callable")
        self.on_finalized = on_finalized
        if on_validator_set is not None and not callable(on_validator_set):
            raise TypeError("on_validator_set must be callable")
        self.on_validator_set = on_validator_set
        self.round = signer.current_round if signer is not None else 0
        self.proposals = {}
        self.proposal_metadata = {}
        self.votes = defaultdict(dict)
        self.round_changes = defaultdict(dict)
        self.finalized = {}

    @property
    def height(self):
        return self._height

    @_synchronized
    def activate_validator_set(
        self, validators, signer=None, activation_height=1, chain_height=None
    ):
        """Switch to the set committed by finalized history without reusing old signer state."""
        normalized = normalize_validator_set(validators)
        target_height = self._height if chain_height is None else chain_height
        if (not isinstance(target_height, int) or isinstance(target_height, bool)
                or target_height < 1
                or not isinstance(activation_height, int)
                or isinstance(activation_height, bool)
                or activation_height < 1 or activation_height > target_height):
            raise ValueError("validator activation height is invalid")
        if signer is not None:
            if not isinstance(signer, ConsensusSigner):
                raise TypeError("replacement signer must be a ConsensusSigner or None")
            if (signer.chain_id != self.chain_id or signer.height != target_height
                    or signer.validators != normalized):
                raise ValueError("replacement signer does not match the active chain state")
        old_signer = self.signer
        self._height = target_height
        self.signer = signer
        self.active = signer is not None
        self.validator_power = normalized
        self.validators = [
            {"public_key": key, "voting_power": power}
            for key, power in normalized.items()
        ]
        self.validator_set_hash = validator_set_hash(self.validators)
        self.validator_activation_height = activation_height
        self.round = signer.current_round if signer is not None else 0
        self.proposals.clear()
        self.proposal_metadata.clear()
        self.votes.clear()
        self.round_changes.clear()
        if old_signer is not None and old_signer is not signer:
            old_signer.close()
        return self.active

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
        # Account-chain coinbase value consists of the configured reward plus
        # transaction fees. It must be paid to the signed proposal's author;
        # otherwise a proposer could redirect block value to an arbitrary key.
        if isinstance(block, dict) and "transactions" in block:
            transactions = block["transactions"]
            if (not isinstance(transactions, list) or not transactions
                    or not isinstance(transactions[0], dict)
                    or transactions[0].get("recipient") != proposal["proposer"]):
                return False
        if self.active and self.signer.locked_block_hash not in (None, proposal["block_hash"]):
            try:
                self.signer.authorize_unlock(
                    proposal["valid_round"], proposal["round"],
                    proposal["block_hash"], proposal["valid_round_certificate"],
                )
            except (ValueError, RuntimeError):
                return False
        self.proposals[proposal["block_hash"]] = block
        incoming_metadata = {
            "valid_round": proposal["valid_round"],
            "valid_round_certificate": proposal["valid_round_certificate"],
        }
        prior_metadata = self.proposal_metadata.get(proposal["block_hash"])
        if (prior_metadata is None
                or (incoming_metadata["valid_round"] is not None
                    and (prior_metadata["valid_round"] is None
                         or incoming_metadata["valid_round"] > prior_metadata["valid_round"]))):
            self.proposal_metadata[proposal["block_hash"]] = incoming_metadata
        return True

    @_synchronized
    def prevote(self, block_hash):
        """Sign a prevote only for a locally validated proposal."""
        if not self.active:
            raise RuntimeError("this node is not a member of the active validator set")
        if block_hash not in self.proposals:
            raise ValueError("cannot prevote an unknown or invalid proposal")
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
            return self.retry_pending_finalization() if vote["step"] == "precommit" else None
        self.votes[slot][vote["validator"]] = vote
        matching = [
            item for item in self.votes[slot].values()
            if item["block_hash"] == vote["block_hash"]
        ]
        power = sum(self.validator_power[item["validator"]] for item in matching)
        if power * 3 <= self.total_power * 2:
            return None

        if vote["step"] == "prevote":
            block_hash = vote["block_hash"]
            if block_hash not in self.proposals:
                return None
            if not self.active:
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
            power = sum(self.validator_power[item["validator"]] for item in matching)
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
                **self.proposal_metadata.get(block_hash, {
                    "valid_round": None, "valid_round_certificate": []
                }),
            }
            # Ensure signer state can accept this commit before persisting the chain.
            if self.active:
                try:
                    self.signer.validate_finalization(matching, self.round, block_hash)
                except ValueError:
                    continue
            # Persist the finalized block before advancing signer height.
            activation = None
            if self.on_finalized is not None:
                try:
                    activation = self.on_finalized(result)
                except Exception:
                    continue
            if self.active:
                try:
                    self.signer.finalize(matching, self.round, block_hash)
                except (ValueError, OSError):
                    continue
                self._height = self.signer.height
            else:
                self._height += 1
            if activation is not None:
                if not isinstance(activation, dict) or set(activation) != {
                    "validators", "activation_height", "chain_height"
                }:
                    raise ValueError("validator activation callback returned an invalid result")
                replacement = None
                if self.on_validator_set is not None:
                    try:
                        replacement = self.on_validator_set()
                    except Exception:
                        # Finality is durable; remain an observer if new signer
                        # state cannot yet be opened safely. The sync loop retries.
                        replacement = None
                self.activate_validator_set(
                    activation["validators"], replacement,
                    activation["activation_height"], activation["chain_height"],
                )
            self.finalized[result["height"]] = result
            self.round = 0
            self.proposals.clear()
            self.proposal_metadata.clear()
            self.votes.clear()
            self.round_changes.clear()
            return result
        return None

    @_synchronized
    def catch_up_chain(self, chain_blocks):
        """Catch up from a chain snapshot without racing concurrent finalization."""
        if self._height >= len(chain_blocks):
            return False
        if self.active:
            self.signer.catch_up(chain_blocks[self._height:])
            self._height = self.signer.height
            self.round = self.signer.current_round
        else:
            self._height = len(chain_blocks)
            self.round = 0
        self.proposals.clear()
        self.proposal_metadata.clear()
        self.votes.clear()
        self.round_changes.clear()
        return True

    @_synchronized
    def request_round_change(self, target_round):
        """Sign and return a persisted local request for a later round."""
        if not self.active:
            raise RuntimeError("this node is not a member of the active validator set")
        message = self.signer.sign_round_change(target_round)
        self.round_changes[target_round][message["validator"]] = message
        return message

    @_synchronized
    def receive_round_change(self, message):
        """Collect authenticated round-change messages; advance on >2/3 power.

        An observer tracks certified rounds without producing validator signatures.
        """
        if not verify_round_change(message, self.validators, self.chain_id):
            return None
        if message["height"] != self.height or message["round"] <= self.round:
            return None
        target = message["round"]
        prior = self.round_changes[target].get(message["validator"])
        if prior is not None:
            return None
        self.round_changes[target][message["validator"]] = message
        certificate = list(self.round_changes[target].values())
        if not verify_round_change_certificate(
            certificate, self.validators, self.chain_id, self.height, target
        ):
            return None
        if self.active:
            try:
                self.round = self.signer.advance_round(certificate)
            except (ValueError, RuntimeError):
                return None
        else:
            self.round = target
        self.proposals.clear()
        self.proposal_metadata.clear()
        self.votes.clear()
        self.round_changes = defaultdict(dict, {
            round_number: entries for round_number, entries in self.round_changes.items()
            if round_number > self.round
        })
        return {"round": self.round, "certificate": certificate}

    @_synchronized
    def advance_round(self, certificate=None):
        """Advance only from a valid distributed certificate; never unlock locally."""
        if certificate is None:
            raise RuntimeError("a >2/3 signed round-change certificate is required")
        if self.active:
            self.round = self.signer.advance_round(certificate)
        else:
            if not isinstance(certificate, list) or not certificate:
                raise ValueError("invalid round-change certificate")
            target = certificate[0].get("round")
            if not verify_round_change_certificate(
                certificate, self.validators, self.chain_id, self.height, target
            ):
                raise ValueError("invalid round-change certificate")
            self.round = target
        self.proposals.clear()
        self.proposal_metadata.clear()
        self.votes.clear()
        self.round_changes.clear()
        return self.round
