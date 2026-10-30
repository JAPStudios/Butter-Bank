use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::{BTreeMap, BTreeSet}, fs, io::Write, path::{Path, PathBuf}};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ChainError {
    #[error("invalid chain configuration: {0}")]
    Configuration(String),
    #[error("invalid proposal or certificate: {0}")]
    Consensus(String),
    #[error("invalid transaction: {0}")]
    Transaction(String),
    #[error("ledger I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("ledger serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Validator {
    pub public_key: String,
    pub power: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Transaction {
    pub chain_id: String,
    pub sender: String,
    pub recipient: String,
    pub amount: u64,
    pub nonce: u64,
    pub signature: String,
}

#[derive(Serialize)]
struct TransactionSignDoc<'a> {
    chain_id: &'a str,
    sender: &'a str,
    recipient: &'a str,
    amount: u64,
    nonce: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockHeader {
    pub chain_id: String,
    pub height: u64,
    pub round: u32,
    pub previous_hash: String,
    pub timestamp: u64,
    pub transactions: Vec<Transaction>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Vote {
    pub validator: String,
    pub chain_id: String,
    pub height: u64,
    pub round: u32,
    pub step: String,
    pub block_hash: String,
    pub signature: String,
}

#[derive(Serialize)]
struct VoteSignDoc<'a> {
    chain_id: &'a str,
    height: u64,
    round: u32,
    step: &'a str,
    block_hash: &'a str,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Block {
    pub header: BlockHeader,
    pub hash: String,
    pub prevotes: Vec<Vote>,
    pub precommits: Vec<Vote>,
}

#[derive(Serialize, Deserialize)]
struct StoredLedger {
    chain_id: String,
    validators: Vec<Validator>,
    genesis_allocations: BTreeMap<String, u64>,
    blocks: Vec<Block>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AccountState {
    pub balances: BTreeMap<String, u64>,
    pub nonces: BTreeMap<String, u64>,
}

pub struct BftChain {
    chain_id: String,
    validators: Vec<Validator>,
    validator_power: BTreeMap<String, u64>,
    total_power: u64,
    genesis_allocations: BTreeMap<String, u64>,
    blocks: Vec<Block>,
    data_path: Option<PathBuf>,
}

fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, ChainError> {
    Ok(serde_json::to_vec(value)?)
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn public_key_hex(key: &VerifyingKey) -> String {
    hex::encode(key.as_bytes())
}

fn parse_verifying_key(value: &str) -> Result<VerifyingKey, ChainError> {
    let raw = hex::decode(value).map_err(|_| ChainError::Configuration("public key is not hex".into()))?;
    let bytes: [u8; 32] = raw.try_into().map_err(|_| ChainError::Configuration("public key must be 32 bytes".into()))?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| ChainError::Configuration("invalid Ed25519 public key".into()))
}

fn verify_hex_signature(key: &VerifyingKey, message: &[u8], encoded: &str) -> bool {
    let Ok(raw) = hex::decode(encoded) else { return false; };
    let Ok(bytes) = <[u8; 64]>::try_from(raw) else { return false; };
    key.verify(message, &Signature::from_bytes(&bytes)).is_ok()
}

pub fn sign_transaction(
    signing_key: &SigningKey, chain_id: &str, recipient: &str, amount: u64, nonce: u64,
) -> Result<Transaction, ChainError> {
    if amount == 0 || nonce == 0 {
        return Err(ChainError::Transaction("amount and nonce must be positive".into()));
    }
    let sender = public_key_hex(&signing_key.verifying_key());
    let doc = TransactionSignDoc { chain_id, sender: &sender, recipient, amount, nonce };
    let signature = signing_key.sign(&canonical(&doc)?);
    Ok(Transaction {
        chain_id: chain_id.into(), sender, recipient: recipient.into(), amount, nonce,
        signature: hex::encode(signature.to_bytes()),
    })
}

pub fn sign_vote(
    signing_key: &SigningKey, chain_id: &str, height: u64, round: u32,
    step: &str, block_hash: &str,
) -> Result<Vote, ChainError> {
    if step != "prevote" && step != "precommit" {
        return Err(ChainError::Consensus("vote step must be prevote or precommit".into()));
    }
    let validator = public_key_hex(&signing_key.verifying_key());
    let doc = VoteSignDoc { chain_id, height, round, step, block_hash };
    let signature = signing_key.sign(&canonical(&doc)?);
    Ok(Vote {
        validator, chain_id: chain_id.into(), height, round, step: step.into(),
        block_hash: block_hash.into(), signature: hex::encode(signature.to_bytes()),
    })
}

impl BftChain {
    pub fn new(
        chain_id: impl Into<String>, validators: Vec<Validator>,
        genesis_allocations: BTreeMap<String, u64>, data_path: Option<PathBuf>,
    ) -> Result<Self, ChainError> {
        let chain_id = chain_id.into();
        if chain_id.trim().is_empty() || validators.is_empty() {
            return Err(ChainError::Configuration("chain ID and validator set must be non-empty".into()));
        }
        let mut power_map = BTreeMap::new();
        let mut total_power: u64 = 0;
        for validator in &validators {
            parse_verifying_key(&validator.public_key)?;
            if validator.power == 0 || power_map.insert(validator.public_key.clone(), validator.power).is_some() {
                return Err(ChainError::Configuration("validator keys must be unique and voting power positive".into()));
            }
            total_power = total_power.checked_add(validator.power)
                .ok_or_else(|| ChainError::Configuration("total validator power overflow".into()))?;
        }
        for address in genesis_allocations.keys() {
            let raw = hex::decode(address).map_err(|_| ChainError::Configuration("genesis address is not hex".into()))?;
            if raw.len() != 32 {
                return Err(ChainError::Configuration("genesis addresses must be 32-byte public keys".into()));
            }
        }
        let mut chain = Self {
            chain_id, validators, validator_power: power_map, total_power,
            genesis_allocations, blocks: Vec::new(), data_path,
        };
        let genesis = chain.genesis_block()?;
        chain.blocks.push(genesis);
        if let Some(path) = chain.data_path.clone() {
            if path.exists() {
                chain.load_existing(&path)?;
            } else {
                chain.save()?;
            }
        }
        Ok(chain)
    }

    fn genesis_block(&self) -> Result<Block, ChainError> {
        let header = BlockHeader {
            chain_id: self.chain_id.clone(), height: 0, round: 0,
            previous_hash: "0".repeat(64), timestamp: 0, transactions: Vec::new(),
        };
        let hash = sha256_hex(&canonical(&header)?);
        Ok(Block { header, hash, prevotes: Vec::new(), precommits: Vec::new() })
    }

    fn load_existing(&mut self, path: &Path) -> Result<(), ChainError> {
        let stored: StoredLedger = serde_json::from_slice(&fs::read(path)?)?;
        if stored.chain_id != self.chain_id || stored.validators != self.validators
            || stored.genesis_allocations != self.genesis_allocations
            || !self.validate_blocks(&stored.blocks) {
            return Err(ChainError::Consensus("persisted ledger does not validate against configured genesis".into()));
        }
        self.blocks = stored.blocks;
        Ok(())
    }

    pub fn height(&self) -> u64 { self.blocks.len() as u64 - 1 }
    pub fn tip(&self) -> &str { &self.blocks.last().expect("genesis always exists").hash }
    pub fn blocks(&self) -> &[Block] { &self.blocks }
    pub fn total_voting_power(&self) -> u64 { self.total_power }

    pub fn state(&self) -> Result<AccountState, ChainError> {
        self.state_for(&self.blocks)
    }

    fn state_for(&self, blocks: &[Block]) -> Result<AccountState, ChainError> {
        let mut state = AccountState { balances: self.genesis_allocations.clone(), nonces: BTreeMap::new() };
        for block in blocks.iter().skip(1) {
            for tx in &block.header.transactions {
                self.apply_transaction(tx, &mut state)?;
            }
        }
        Ok(state)
    }

    fn verify_transaction(&self, tx: &Transaction, state: &AccountState) -> Result<(), ChainError> {
        if tx.chain_id != self.chain_id || tx.amount == 0 || tx.nonce == 0 {
            return Err(ChainError::Transaction("wrong chain or non-positive amount/nonce".into()));
        }
        let sender = parse_verifying_key(&tx.sender)
            .map_err(|_| ChainError::Transaction("invalid sender public key".into()))?;
        let recipient = hex::decode(&tx.recipient)
            .map_err(|_| ChainError::Transaction("recipient must be a 32-byte public key".into()))?;
        if recipient.len() != 32 {
            return Err(ChainError::Transaction("recipient must be a 32-byte public key".into()));
        }
        let expected_nonce = state.nonces.get(&tx.sender).copied().unwrap_or(0)
            .checked_add(1).ok_or_else(|| ChainError::Transaction("nonce overflow".into()))?;
        if tx.nonce != expected_nonce {
            return Err(ChainError::Transaction("incorrect transaction nonce".into()));
        }
        if state.balances.get(&tx.sender).copied().unwrap_or(0) < tx.amount {
            return Err(ChainError::Transaction("insufficient balance".into()));
        }
        let doc = TransactionSignDoc {
            chain_id: &tx.chain_id, sender: &tx.sender, recipient: &tx.recipient,
            amount: tx.amount, nonce: tx.nonce,
        };
        if !verify_hex_signature(&sender, &canonical(&doc)?, &tx.signature) {
            return Err(ChainError::Transaction("invalid Ed25519 transaction signature".into()));
        }
        Ok(())
    }

    fn apply_transaction(&self, tx: &Transaction, state: &mut AccountState) -> Result<(), ChainError> {
        self.verify_transaction(tx, state)?;
        let sender_balance = state.balances.get(&tx.sender).copied().unwrap_or(0);
        state.balances.insert(tx.sender.clone(), sender_balance - tx.amount);
        let recipient_balance = state.balances.get(&tx.recipient).copied().unwrap_or(0);
        state.balances.insert(
            tx.recipient.clone(),
            recipient_balance.checked_add(tx.amount)
                .ok_or_else(|| ChainError::Transaction("recipient balance overflow".into()))?,
        );
        state.nonces.insert(tx.sender.clone(), tx.nonce);
        Ok(())
    }

    pub fn propose(&self, transactions: Vec<Transaction>, timestamp: u64, round: u32) -> Result<BlockHeader, ChainError> {
        if timestamp < self.blocks.last().unwrap().header.timestamp {
            return Err(ChainError::Consensus("timestamp precedes previous block".into()));
        }
        let mut state = self.state()?;
        for tx in &transactions { self.apply_transaction(tx, &mut state)?; }
        Ok(BlockHeader {
            chain_id: self.chain_id.clone(), height: self.height() + 1, round,
            previous_hash: self.tip().into(), timestamp, transactions,
        })
    }

    pub fn block_hash(header: &BlockHeader) -> Result<String, ChainError> {
        Ok(sha256_hex(&canonical(header)?))
    }

    fn certificate_power(&self, votes: &[Vote], step: &str, header: &BlockHeader, hash: &str) -> Result<u64, ChainError> {
        let mut seen = BTreeSet::new();
        let mut power = 0u64;
        for vote in votes {
            if vote.step != step || vote.chain_id != self.chain_id || vote.height != header.height
                || vote.round != header.round || vote.block_hash != hash {
                return Err(ChainError::Consensus("vote does not match chain, height, round, step and block".into()));
            }
            if !seen.insert(vote.validator.clone()) {
                return Err(ChainError::Consensus("duplicate validator vote".into()));
            }
            let validator_power = self.validator_power.get(&vote.validator)
                .ok_or_else(|| ChainError::Consensus("vote from unknown validator".into()))?;
            let key = parse_verifying_key(&vote.validator)
                .map_err(|_| ChainError::Consensus("invalid validator public key".into()))?;
            let doc = VoteSignDoc {
                chain_id: &vote.chain_id, height: vote.height, round: vote.round,
                step: &vote.step, block_hash: &vote.block_hash,
            };
            if !verify_hex_signature(&key, &canonical(&doc)?, &vote.signature) {
                return Err(ChainError::Consensus("invalid validator vote signature".into()));
            }
            power = power.checked_add(*validator_power)
                .ok_or_else(|| ChainError::Consensus("certificate voting power overflow".into()))?;
        }
        Ok(power)
    }

    pub fn commit(&mut self, header: BlockHeader, prevotes: Vec<Vote>, precommits: Vec<Vote>) -> Result<&Block, ChainError> {
        if header.chain_id != self.chain_id || header.height != self.height() + 1
            || header.previous_hash != self.tip()
            || header.timestamp < self.blocks.last().unwrap().header.timestamp {
            return Err(ChainError::Consensus("proposal does not extend current chain tip".into()));
        }
        let mut state = self.state()?;
        for tx in &header.transactions { self.apply_transaction(tx, &mut state)?; }
        let hash = Self::block_hash(&header)?;
        let threshold = ((2u128 * self.total_power as u128 + 2) / 3) as u64;
        if self.certificate_power(&prevotes, "prevote", &header, &hash)? < threshold {
            return Err(ChainError::Consensus("insufficient prevote voting power".into()));
        }
        if self.certificate_power(&precommits, "precommit", &header, &hash)? < threshold {
            return Err(ChainError::Consensus("insufficient precommit voting power".into()));
        }
        self.blocks.push(Block { header, hash, prevotes, precommits });
        self.save()?;
        Ok(self.blocks.last().unwrap())
    }

    pub fn validate_blocks(&self, blocks: &[Block]) -> bool {
        let Ok(genesis) = self.genesis_block() else { return false; };
        if blocks.first() != Some(&genesis) { return false; }
        let mut state = AccountState { balances: self.genesis_allocations.clone(), nonces: BTreeMap::new() };
        for (index, block) in blocks.iter().enumerate().skip(1) {
            let header = &block.header;
            if header.chain_id != self.chain_id || header.height != index as u64
                || header.previous_hash != blocks[index - 1].hash
                || header.timestamp < blocks[index - 1].header.timestamp
                || Self::block_hash(header).ok().as_deref() != Some(block.hash.as_str()) {
                return false;
            }
            for tx in &header.transactions {
                if self.apply_transaction(tx, &mut state).is_err() { return false; }
            }
            let threshold = ((2u128 * self.total_power as u128 + 2) / 3) as u64;
            if self.certificate_power(&block.prevotes, "prevote", header, &block.hash).unwrap_or(0) < threshold
                || self.certificate_power(&block.precommits, "precommit", header, &block.hash).unwrap_or(0) < threshold {
                return false;
            }
        }
        true
    }

    pub fn save(&self) -> Result<(), ChainError> {
        let Some(path) = &self.data_path else { return Ok(()); };
        if let Some(parent) = path.parent() { fs::create_dir_all(parent)?; }
        let stored = StoredLedger {
            chain_id: self.chain_id.clone(), validators: self.validators.clone(),
            genesis_allocations: self.genesis_allocations.clone(), blocks: self.blocks.clone(),
        };
        let bytes = canonical(&stored)?;
        let temp = path.with_extension(format!("tmp-{}", std::process::id()));
        {
            let mut file = fs::File::create(&temp)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
        }
        fs::rename(&temp, path)?;
        if let Some(parent) = path.parent() {
            if let Ok(dir) = fs::File::open(parent) { let _ = dir.sync_all(); }
        }
        Ok(())
    }
}
