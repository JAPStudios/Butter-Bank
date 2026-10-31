#!/usr/bin/env python3
"""Sign and submit a Milkchain transaction."""
import argparse,json,urllib.request,urllib.error
from pathlib import Path
from wallet import read_wallet

MAX_NODE_RESPONSE_BYTES = 4 * 1024 * 1024


def read_limited_response(response, max_bytes=MAX_NODE_RESPONSE_BYTES):
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 1:
        raise ValueError('response size limit must be a positive integer')
    headers = response.headers
    lengths = headers.get_all('Content-Length', [])
    if len(lengths) > 1:
        raise ValueError('duplicate response Content-Length')
    if lengths:
        raw_length = lengths[0]
        if not raw_length.isascii() or not raw_length.isdecimal():
            raise ValueError('invalid response Content-Length')
        if int(raw_length) > max_bytes:
            raise ValueError('node response exceeds size limit')
    raw = response.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise ValueError('node response exceeds size limit')
    if lengths and len(raw) != int(lengths[0]):
        raise ValueError('incomplete node response')
    return raw

def canon(x): return json.dumps(x,sort_keys=True,separators=(',',':')).encode()
def get_json(url):
    req=urllib.request.Request(url,headers={'Accept':'application/json'})
    with urllib.request.urlopen(req,timeout=5) as r: return json.loads(read_limited_response(r))
def main():
    p=argparse.ArgumentParser()
    p.add_argument('--wallet',required=True)
    p.add_argument('--node',default='http://127.0.0.1:8333')
    p.add_argument('--chain-id')
    p.add_argument('--to',required=True)
    p.add_argument('--amount',type=int,required=True)
    p.add_argument('--fee',type=int,default=0)
    p.add_argument('--nonce',type=int)
    a=p.parse_args()
    if a.amount<=0: p.error('--amount must be greater than zero')
    if a.fee<0: p.error('--fee cannot be negative')
    try: recipient=bytes.fromhex(a.to)
    except ValueError: p.error('--to must be a 32-byte hexadecimal public key')
    if len(recipient)!=32: p.error('--to must be a 32-byte hexadecimal public key')
    try:
        key, public_hex = read_wallet(a.wallet)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        p.error(f'invalid wallet file: {exc}')
    node=a.node.rstrip('/')
    try:
        status=get_json(node+'/status')
        balances=get_json(node+'/balances')
        mempool=get_json(node+'/mempool')
    except Exception as e:
        p.error(f'cannot read node status and balances: {e}')
    chain_id=status.get('chain_id')
    if not isinstance(chain_id,str) or not chain_id: p.error('node returned an invalid chain ID')
    if a.chain_id and a.chain_id!=chain_id: p.error('provided chain ID does not match the node')
    nonce=a.nonce
    if nonce is None:
        try:
            nonce=balances['nonces'].get(public_hex,0)+1
            pending=[item['nonce'] for item in mempool['transactions'] if item.get('sender')==public_hex and isinstance(item.get('nonce'),int) and not isinstance(item.get('nonce'),bool)]
            if pending: nonce=max(nonce,max(pending)+1)
        except (KeyError,TypeError): p.error('node returned invalid nonce or mempool data')
    if not isinstance(nonce,int) or isinstance(nonce,bool) or nonce<1: p.error('--nonce must be a positive integer')
    tx={'chain_id':chain_id,'sender':public_hex,'recipient':a.to.lower(),'amount':a.amount,'fee':a.fee,'nonce':nonce}
    tx['signature']=key.sign(canon(tx)).hex()
    req=urllib.request.Request(node+'/tx',data=canon(tx),headers={'Content-Type':'application/json','Accept':'application/json'},method='POST')
    try:
        with urllib.request.urlopen(req,timeout=5) as r: print(read_limited_response(r).decode())
    except urllib.error.HTTPError as e:
        print(read_limited_response(e).decode())
        raise SystemExit(1)
    except OSError as e:
        p.error(f'cannot submit transaction: {e}')
if __name__=='__main__': main()
