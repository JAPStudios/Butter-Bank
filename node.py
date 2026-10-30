#!/usr/bin/env python3
"""Minimal account-based proof-of-work cryptocurrency node. Educational only."""
import argparse, hashlib, json, threading, time, urllib.request
from pathlib import Path
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

MAX_TXS=100

def canon(x): return json.dumps(x,sort_keys=True,separators=(',',':')).encode()
def sha(b): return hashlib.sha256(b).hexdigest()
def bhash(b): return sha(canon({k:b[k] for k in ('height','previous_hash','timestamp','transactions','nonce')}))
def ishex(s,n):
    try: return isinstance(s,str) and len(s)==2*n and len(bytes.fromhex(s))==n
    except (ValueError,TypeError): return False
def signing_bytes(tx): return canon({k:tx[k] for k in ('chain_id','sender','recipient','amount','fee','nonce')})

def get(url):
    with urllib.request.urlopen(url,timeout=3) as r: return json.loads(r.read())
def post(url,obj):
    req=urllib.request.Request(url,data=canon(obj),headers={'Content-Type':'application/json'},method='POST')
    with urllib.request.urlopen(req,timeout=3) as r: return json.loads(r.read())

def broadcast(peers,path,obj):
    for p in list(peers):
        try: post(p+path,obj)
        except Exception: pass

class Chain:
    def genesis_block(self):
        alloc=self.cfg.get('genesis_allocations',{})
        g={'height':0,'previous_hash':'0'*64,'timestamp':0,'transactions':[{'type':'genesis','allocations':alloc}],'nonce':0}
        g['hash']=bhash(g)
        return g
    def __init__(self,cfg,path):
        if not isinstance(cfg,dict): raise ValueError('configuration must be a JSON object')
        if not isinstance(cfg.get('chain_id'),str) or not cfg['chain_id'].strip(): raise ValueError('chain_id must be a non-empty string')
        if not isinstance(cfg.get('difficulty'),int) or isinstance(cfg.get('difficulty'),bool) or not 1<=cfg['difficulty']<=6: raise ValueError('difficulty must be an integer from 1..6')
        if not isinstance(cfg.get('block_reward'),int) or isinstance(cfg.get('block_reward'),bool) or cfg['block_reward']<0: raise ValueError('block_reward must be a non-negative integer')
        alloc=cfg.get('genesis_allocations',{})
        if not isinstance(alloc,dict) or any(not ishex(a,32) or not isinstance(v,int) or isinstance(v,bool) or v<0 for a,v in alloc.items()): raise ValueError('invalid genesis allocations')
        self.cfg,self.path=cfg,Path(path); self.id=cfg['chain_id']; self.diff=cfg['difficulty']; self.reward=cfg['block_reward']; self.lock=threading.RLock()
        if self.path.exists():
            d=json.loads(self.path.read_text())
            if not isinstance(d,dict) or d.get('chain_id')!=self.id: raise ValueError('data file belongs to a different chain or has an invalid format')
            self.blocks,self.pool=d.get('chain'),d.get('mempool',[])
            if not isinstance(self.pool,list) or not self.valid_chain(self.blocks): raise ValueError('stored chain or mempool is invalid')
            self._revalidate_pool()
        else:
            self.blocks=[self.genesis_block()]; self.pool=[]; self.save()
    def save(self):
        tmp=self.path.with_suffix('.tmp'); tmp.write_text(json.dumps({'chain_id':self.id,'chain':self.blocks,'mempool':self.pool},indent=2)); tmp.replace(self.path)
    def state(self,blocks=None):
        bs=self.blocks if blocks is None else blocks; bal=dict(bs[0]['transactions'][0]['allocations']); nonce={a:0 for a in bal}
        for b in bs[1:]:
            for tx in b['transactions']:
                if tx.get('type')=='coinbase': bal[tx['recipient']]=bal.get(tx['recipient'],0)+tx['amount']; nonce.setdefault(tx['recipient'],0)
                else:
                    s,r=tx['sender'],tx['recipient']; bal[s]=bal.get(s,0)-tx['amount']-tx['fee']; bal[r]=bal.get(r,0)+tx['amount']; nonce[s]=nonce.get(s,0)+1; nonce.setdefault(r,0)
        return bal,nonce
    def check_tx(self,tx,bal,nonces):
        fields={'chain_id','sender','recipient','amount','fee','nonce','signature'}
        if not isinstance(tx,dict) or set(tx)!=fields: return False,'wrong transaction fields'
        if tx['chain_id']!=self.id: return False,'wrong chain_id'
        if not ishex(tx['sender'],32) or not ishex(tx['recipient'],32): return False,'addresses must be 32-byte public keys in hex'
        for k in ('amount','fee','nonce'):
            if not isinstance(tx[k],int) or isinstance(tx[k],bool) or tx[k]<0: return False,k+' must be a non-negative integer'
        if tx['amount']<=0: return False,'amount must be positive'
        if not ishex(tx['signature'],64): return False,'invalid signature encoding'
        if tx['nonce']!=nonces.get(tx['sender'],0)+1: return False,'incorrect nonce'
        if bal.get(tx['sender'],0)<tx['amount']+tx['fee']: return False,'insufficient balance'
        try: Ed25519PublicKey.from_public_bytes(bytes.fromhex(tx['sender'])).verify(bytes.fromhex(tx['signature']),signing_bytes(tx))
        except Exception: return False,'signature verification failed'
        return True,'ok'
    def valid_chain(self,bs):
        try:
            if not isinstance(bs,list) or not bs or bs[0] != self.genesis_block(): return False
            bal=dict(bs[0]['transactions'][0]['allocations']); nonces={a:0 for a in bal}
            for i,b in enumerate(bs[1:],1):
                if not isinstance(b,dict) or set(b)!={'height','previous_hash','timestamp','transactions','nonce','hash'}: return False
                for field in ('height','timestamp','nonce'):
                    if not isinstance(b[field],int) or isinstance(b[field],bool) or b[field]<0: return False
                if b['height']!=i or b['previous_hash']!=bs[i-1]['hash'] or b['timestamp']<bs[i-1]['timestamp'] or b['timestamp']>int(time.time())+120: return False
                if not ishex(b['hash'],32) or b['hash']!=bhash(b) or not b['hash'].startswith('0'*self.diff): return False
                txs=b['transactions']
                if not isinstance(txs,list) or not txs or len(txs)>MAX_TXS+1: return False
                cb=txs[0]
                if not isinstance(cb,dict) or set(cb)!={'type','recipient','amount'} or cb['type']!='coinbase' or not ishex(cb['recipient'],32): return False
                if not isinstance(cb['amount'],int) or isinstance(cb['amount'],bool) or cb['amount']<0: return False
                fees=0
                for tx in txs[1:]:
                    if not isinstance(tx,dict) or not isinstance(tx.get('fee'),int) or isinstance(tx.get('fee'),bool) or tx['fee']<0: return False
                    fees+=tx['fee']
                if cb['amount']!=self.reward+fees: return False
                bal[cb['recipient']]=bal.get(cb['recipient'],0)+cb['amount']; nonces.setdefault(cb['recipient'],0)
                for tx in txs[1:]:
                    ok,_=self.check_tx(tx,bal,nonces)
                    if not ok: return False
                    s,r=tx['sender'],tx['recipient']; bal[s]-=tx['amount']+tx['fee']; bal[r]=bal.get(r,0)+tx['amount']; nonces[s]=tx['nonce']; nonces.setdefault(r,0)
            return True
        except (KeyError,TypeError,ValueError,OverflowError): return False
    def add_tx(self,tx):
        with self.lock:
            bal,nonces=self.state()
            for q in sorted([x for x in self.pool if x['sender']==tx.get('sender')],key=lambda x:x['nonce']):
                bal[q['sender']]-=q['amount']+q['fee']; bal[q['recipient']]=bal.get(q['recipient'],0)+q['amount']; nonces[q['sender']]=q['nonce']; nonces.setdefault(q['recipient'],0)
            ok,msg=self.check_tx(tx,bal,nonces)
            if not ok:return False,msg
            if any(x['sender']==tx['sender'] and x['nonce']==tx['nonce'] for x in self.pool):return False,'pending nonce already exists'
            self.pool.append(tx); self.save(); return True,'accepted'
    def mine(self,miner):
        if not ishex(miner,32): return None,'miner must be a public key in hex'
        with self.lock:
            bal,nonces=self.state(); chosen=[]; fees=0
            for tx in sorted(self.pool,key=lambda x:(x['sender'],x['nonce'])):
                if len(chosen)>=MAX_TXS: break
                ok,_=self.check_tx(tx,bal,nonces)
                if not ok: continue
                s,r=tx['sender'],tx['recipient']; bal[s]-=tx['amount']+tx['fee']; bal[r]=bal.get(r,0)+tx['amount']; nonces[s]=tx['nonce']; nonces.setdefault(r,0); chosen.append(tx); fees+=tx['fee']
            b={'height':len(self.blocks),'previous_hash':self.blocks[-1]['hash'],'timestamp':max(int(time.time()),self.blocks[-1]['timestamp']),'transactions':[{'type':'coinbase','recipient':miner,'amount':self.reward+fees}]+chosen,'nonce':0}
            while True:
                b['hash']=bhash(b)
                if b['hash'].startswith('0'*self.diff):break
                b['nonce']+=1
            self.blocks.append(b); chosen_ids={sha(canon(t)) for t in chosen}; self.pool=[t for t in self.pool if sha(canon(t)) not in chosen_ids]; self.save(); return b,'mined'
    def accept_block(self,b):
        with self.lock:
            candidate=self.blocks+[b]
            if not self.valid_chain(candidate):return False,'invalid block'
            self.blocks=candidate; included={sha(canon(t)) for t in b['transactions'][1:]}; self.pool=[t for t in self.pool if sha(canon(t)) not in included]; self.save(); return True,'accepted'
    def _revalidate_pool(self):
        bal,nonces=self.state(); accepted=[]
        for tx in sorted(self.pool,key=lambda x:(str(x.get('sender','')),x.get('nonce',0) if isinstance(x.get('nonce'),int) else 0)):
            ok,_=self.check_tx(tx,bal,nonces)
            if not ok: continue
            s,r=tx['sender'],tx['recipient']; bal[s]-=tx['amount']+tx['fee']; bal[r]=bal.get(r,0)+tx['amount']; nonces[s]=tx['nonce']; nonces.setdefault(r,0); accepted.append(tx)
        self.pool=accepted
    def replace(self,bs):
        with self.lock:
            if not self.valid_chain(bs):return False,'candidate chain invalid'
            if len(bs)<=len(self.blocks):return False,'candidate has no greater cumulative work'
            old_pool=list(self.pool); self.blocks=bs; self.pool=old_pool
            included={sha(canon(t)) for block in bs[1:] for t in block['transactions'][1:]}
            self.pool=[t for t in self.pool if sha(canon(t)) not in included]
            self._revalidate_pool(); self.save(); return True,'replaced'

class API(BaseHTTPRequestHandler):
    chain=None; peers=[]
    def log_message(self,*args): pass
    def sendj(self,code,obj):
        b=canon(obj); self.send_response(code); self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(b))); self.end_headers(); self.wfile.write(b)
    def body(self):
        n=int(self.headers.get('Content-Length','0'))
        if n<1 or n>1000000: raise ValueError('invalid body size')
        return json.loads(self.rfile.read(n))
    def do_GET(self):
        p=urlparse(self.path).path
        if p=='/status': self.sendj(200,{'chain_id':self.chain.id,'height':len(self.chain.blocks)-1,'tip':self.chain.blocks[-1]['hash'],'difficulty':self.chain.diff,'mempool_size':len(self.chain.pool),'symbol':self.chain.cfg.get('symbol','COIN')})
        elif p=='/chain': self.sendj(200,{'chain':self.chain.blocks})
        elif p=='/balances':
            b,n=self.chain.state(); self.sendj(200,{'balances':b,'nonces':n})
        elif p=='/mempool': self.sendj(200,{'transactions':self.chain.pool})
        elif p=='/peers': self.sendj(200,{'peers':self.peers})
        else:self.sendj(404,{'error':'not found'})
    def do_POST(self):
        try:
            d=self.body(); p=urlparse(self.path).path
            if p in ('/tx','/receive-tx'):
                ok,msg=self.chain.add_tx(d)
                if ok and p=='/tx':broadcast(self.peers,'/receive-tx',d)
                self.sendj(200 if ok else 400,{'ok':ok,'message':msg})
            elif p in ('/mine',):
                b,msg=self.chain.mine(d.get('miner',''))
                if b: broadcast(self.peers,'/receive-block',b); self.sendj(200,{'ok':True,'block':b})
                else:self.sendj(400,{'ok':False,'message':msg})
            elif p=='/receive-block':
                ok,msg=self.chain.accept_block(d); self.sendj(200 if ok else 400,{'ok':ok,'message':msg})
            elif p=='/connect':
                peer=d.get('peer','').rstrip('/')
                if not peer.startswith(('http://','https://')):self.sendj(400,{'error':'peer must be an HTTP(S) URL'});return
                status=get(peer+'/status')
                if status['chain_id']!=self.chain.id:self.sendj(400,{'error':'different chain_id'});return
                if peer not in self.peers:self.peers.append(peer)
                try:self.chain.replace(get(peer+'/chain')['chain'])
                except Exception:pass
                self.sendj(200,{'ok':True,'peer':peer,'status':status})
            else:self.sendj(404,{'error':'not found'})
        except Exception as e:self.sendj(400,{'error':str(e)})

def main():
    p=argparse.ArgumentParser();p.add_argument('--config',default='config.json');p.add_argument('--data',default=None);a=p.parse_args()
    cp=Path(a.config)
    if not cp.exists():raise SystemExit('Config missing. Copy config.example.json to config.json and configure it.')
    cfg=json.loads(cp.read_text()); c=Chain(cfg,a.data or f"data-{cfg.get('port',8333)}.json")
    API.chain=c;API.peers=[x.rstrip('/') for x in cfg.get('peers',[])]
    srv=ThreadingHTTPServer((cfg.get('host','127.0.0.1'),int(cfg.get('port',8333))),API)
    print(f"Emberchain node on {cfg.get('host')}:{cfg.get('port')} | chain={c.id} | height={len(c.blocks)-1}")
    try:srv.serve_forever()
    except KeyboardInterrupt:pass
    finally:srv.server_close()
if __name__=='__main__':main()
