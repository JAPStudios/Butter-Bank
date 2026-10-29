#!/usr/bin/env python3
"""Sign and submit an Emberchain transaction."""
import argparse,json,urllib.request
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

def canon(x):return json.dumps(x,sort_keys=True,separators=(',',':')).encode()
def main():
 p=argparse.ArgumentParser();p.add_argument('--wallet',required=True);p.add_argument('--node',default='http://127.0.0.1:8333');p.add_argument('--chain-id',required=True);p.add_argument('--to',required=True);p.add_argument('--amount',type=int,required=True);p.add_argument('--fee',type=int,default=0);p.add_argument('--nonce',type=int,required=True);a=p.parse_args()
 w=json.loads(Path(a.wallet).read_text());tx={'chain_id':a.chain_id,'sender':w['public_key'],'recipient':a.to,'amount':a.amount,'fee':a.fee,'nonce':a.nonce};tx['signature']=Ed25519PrivateKey.from_private_bytes(bytes.fromhex(w['private_key'])).sign(canon(tx)).hex()
 req=urllib.request.Request(a.node.rstrip('/')+'/tx',data=canon(tx),headers={'Content-Type':'application/json'},method='POST')
 with urllib.request.urlopen(req,timeout=5) as r:print(r.read().decode())
if __name__=='__main__':main()
