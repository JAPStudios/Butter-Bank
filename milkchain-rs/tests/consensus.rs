use ed25519_dalek::SigningKey;
use milkchain::{sign_transaction, sign_vote, BftChain, ChainError, Validator};
use rand::rngs::OsRng;
use std::collections::BTreeMap;

fn key() -> SigningKey { SigningKey::generate(&mut OsRng) }
fn validators(keys: &[SigningKey]) -> Vec<Validator> {
    keys.iter().map(|k| Validator {
        public_key: hex::encode(k.verifying_key().as_bytes()), power: 1
    }).collect()
}
fn certs(keys: &[SigningKey], chain: &BftChain, header: &milkchain::BlockHeader) -> (Vec<milkchain::Vote>, Vec<milkchain::Vote>) {
    let hash = BftChain::block_hash(header).unwrap();
    let prevotes = keys[..3].iter().map(|k| sign_vote(k, "milkchain-test", header.height, header.round, "prevote", &hash).unwrap()).collect();
    let precommits = keys[..3].iter().map(|k| sign_vote(k, "milkchain-test", header.height, header.round, "precommit", &hash).unwrap()).collect();
    let _ = chain;
    (prevotes, precommits)
}

#[test]
fn three_of_four_validators_commit_signed_transfer() {
    let keys: Vec<_> = (0..4).map(|_| key()).collect();
    let sender = key();
    let recipient = key();
    let sender_address = hex::encode(sender.verifying_key().as_bytes());
    let recipient_address = hex::encode(recipient.verifying_key().as_bytes());
    let mut allocations = BTreeMap::new();
    allocations.insert(sender_address.clone(), 1000);
    let mut chain = BftChain::new("milkchain-test", validators(&keys), allocations, None).unwrap();
    let tx = sign_transaction(&sender, "milkchain-test", &recipient_address, 125, 1).unwrap();
    let header = chain.propose(vec![tx], 1, 0).unwrap();
    let (pre, prec) = certs(&keys, &chain, &header);
    chain.commit(header, pre, prec).unwrap();
    let state = chain.state().unwrap();
    assert_eq!(state.balances[&sender_address], 875);
    assert_eq!(state.balances[&recipient_address], 125);
    assert_eq!(state.nonces[&sender_address], 1);
}

#[test]
fn two_of_four_cannot_commit() {
    let keys: Vec<_> = (0..4).map(|_| key()).collect();
    let chain = BftChain::new("milkchain-test", validators(&keys), BTreeMap::new(), None).unwrap();
    let header = chain.propose(vec![], 1, 0).unwrap();
    let hash = BftChain::block_hash(&header).unwrap();
    let votes: Vec<_> = keys[..2].iter().map(|k| sign_vote(k, "milkchain-test", 1, 0, "prevote", &hash).unwrap()).collect();
    let commits: Vec<_> = keys[..2].iter().map(|k| sign_vote(k, "milkchain-test", 1, 0, "precommit", &hash).unwrap()).collect();
    let mut chain = chain;
    assert!(matches!(chain.commit(header, votes, commits), Err(ChainError::Consensus(_))));
}

#[test]
fn votes_cannot_be_replayed_for_a_different_round() {
    let keys: Vec<_> = (0..4).map(|_| key()).collect();
    let mut chain = BftChain::new("milkchain-test", validators(&keys), BTreeMap::new(), None).unwrap();
    let header = chain.propose(vec![], 1, 0).unwrap();
    let (prevotes, precommits) = certs(&keys, &chain, &header);
    let other = chain.propose(vec![], 1, 1).unwrap();
    assert!(chain.commit(other, prevotes, precommits).is_err());
}

#[test]
fn persisted_chain_reloads_and_revalidates() {
    let keys: Vec<_> = (0..4).map(|_| key()).collect();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("ledger.json");
    let mut chain = BftChain::new("milkchain-test", validators(&keys), BTreeMap::new(), Some(path.clone())).unwrap();
    let header = chain.propose(vec![], 1, 0).unwrap();
    let (prevotes, precommits) = certs(&keys, &chain, &header);
    chain.commit(header, prevotes, precommits).unwrap();
    let restored = BftChain::new("milkchain-test", validators(&keys), BTreeMap::new(), Some(path)).unwrap();
    assert_eq!(restored.height(), 1);
    assert!(restored.validate_blocks(restored.blocks()));
}
