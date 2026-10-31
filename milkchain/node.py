#!/usr/bin/env python3
"""Minimal account-based proof-of-work cryptocurrency node. Educational only."""
import argparse, hashlib, json, threading, time, urllib.request
from pathlib import Path
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

MAX_TXS=100
MAX_TX_BYTES=4096
MAX_MEMPOOL_TXS=900

def canon(x): return json.dumps(x,sort_keys=True,separators=(',',':')).encode()
def sha(b): return hashlib.sha256(b).hexdigest()
def bhash(b): return sha(canon({k:b[k] for k in ('height','previous_hash','timestamp','transactions','nonce')}))

def block_work(difficulty):
    # Current proof-of-work target requires N leading hexadecimal zeroes.
    # Its expected work is 16**N, represented exactly as an integer.
    return 1 << (4*difficulty)

def chain_work(blocks,difficulty):
    return sum(block_work(difficulty) for _ in blocks[1:])
def ishex(s,n):
    try: return isinstance(s,str) and len(s)==2*n and len(bytes.fromhex(s))==n
    except (ValueError,TypeError): return False
def signing_bytes(tx): return canon({k:tx[k] for k in ('chain_id','sender','recipient','amount','fee','nonce')})

MAX_PEER_RESPONSE_BYTES=16*1024*1024
MAX_CHAIN_PAGE_BLOCKS=100


def get(url, max_bytes=MAX_PEER_RESPONSE_BYTES):
    if not isinstance(max_bytes,int) or isinstance(max_bytes,bool) or max_bytes<1:
        raise ValueError('response size limit must be a positive integer')
    with urllib.request.urlopen(url,timeout=3) as r:
        lengths=r.headers.get_all('Content-Length', [])
        if len(lengths)>1:
            raise ValueError('duplicate response Content-Length')
        if lengths:
            raw_length=lengths[0]
            if not raw_length.isascii() or not raw_length.isdecimal():
                raise ValueError('invalid response Content-Length')
            if int(raw_length)>max_bytes:
                raise ValueError('peer response exceeds size limit')
        raw=r.read(max_bytes+1)
        if len(raw)>max_bytes:
            raise ValueError('peer response exceeds size limit')
        if lengths and len(raw)!=int(lengths[0]):
            raise ValueError('incomplete peer response')
        return json.loads(raw)
def post(url,obj):
    req=urllib.request.Request(url,data=canon(obj),headers={'Content-Type':'application/json'},method='POST')
    with urllib.request.urlopen(req,timeout=3) as r: return json.loads(r.read())

def broadcast(peers,path,obj):
    for p in list(peers):
        try: post(p+path,obj)
        except Exception: pass

def fetch_peer_chain(peer, status):
    """Download a peer chain in bounded pages so history can grow indefinitely."""
    height=status.get('height') if isinstance(status,dict) else None
    if not isinstance(height,int) or isinstance(height,bool) or height<0:
        raise ValueError('peer status has an invalid chain height')
    total=height+1
    blocks=[]
    start=0
    while start<total:
        limit=min(MAX_CHAIN_PAGE_BLOCKS,total-start)
        page=get(f'{peer}/chain?start={start}&limit={limit}')
        if (not isinstance(page,dict) or page.get('start')!=start
                or not isinstance(page.get('chain'),list)
                or not page['chain'] or len(page['chain'])>limit):
            raise ValueError('peer returned an invalid chain page')
        blocks.extend(page['chain'])
        if len(blocks)!=start+len(page['chain']):
            raise ValueError('peer chain page sequence is inconsistent')
        start=len(blocks)
    if len(blocks)!=total:
        raise ValueError('peer chain does not match its reported height')
    return blocks


def synchronize_peer(chain, peer):
    """Fetch and validate a peer's chain; adopt it only if it has more work."""
    try:
        status=get(peer+'/status')
        expected={'chain_id':chain.id,'genesis_hash':chain.blocks[0]['hash'],'difficulty':chain.diff,'block_reward':chain.reward,'consensus':getattr(chain,'consensus_mode','pow')}
        if getattr(chain,'validators_hash',None):
            expected['validator_set_hash']=chain.validators_hash
        if any(status.get(k)!=v for k,v in expected.items()):
            return False
        candidate=fetch_peer_chain(peer,status)
        if not chain.valid_chain(candidate):
            return False
        return chain.replace(candidate)[0]
    except Exception:
        return False

def peer_sync_loop(chain, interval=10):
    """Periodically catch up with configured and discovered peers."""
    while True:
        for peer in list(chain.peers):
            synchronize_peer(chain, peer)
        time.sleep(interval)

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
        configured_peers=cfg.get('peers',[])
        if not isinstance(configured_peers,list) or any(not isinstance(p,str) for p in configured_peers): raise ValueError('peers must be a list of URLs')
        self.peers=list(dict.fromkeys(p.rstrip('/') for p in configured_peers if p.strip()))
        if self.path.exists():
            d=json.loads(self.path.read_text())
            if not isinstance(d,dict) or d.get('chain_id')!=self.id: raise ValueError('data file belongs to a different chain or has an invalid format')
            self.blocks,self.pool=d.get('chain'),d.get('mempool',[])
            stored_peers=d.get('peers',[])
            if not isinstance(stored_peers,list) or any(not isinstance(p,str) for p in stored_peers): raise ValueError('stored peer list is invalid')
            self.peers=list(dict.fromkeys([p.rstrip('/') for p in stored_peers if p.strip()]+self.peers))
            if (not isinstance(self.pool,list) or len(self.pool)>MAX_MEMPOOL_TXS
                    or not self.valid_chain(self.blocks)):
                raise ValueError('stored chain or mempool is invalid or exceeds the mempool limit')
            self._revalidate_pool()
        else:
            self.blocks=[self.genesis_block()]; self.pool=[]; self.save()
    def save(self):
        tmp=self.path.with_suffix('.tmp'); tmp.write_text(json.dumps({'chain_id':self.id,'chain':self.blocks,'mempool':self.pool,'peers':self.peers},indent=2)); tmp.replace(self.path)
    def state(self,blocks=None):
        bs=self.blocks if blocks is None else blocks
        bal=dict(bs[0]['transactions'][0]['allocations'])
        nonce={a:0 for a in bal}
        for b in bs[1:]:
            # Transactions execute against the state at the start of the block.
            # The block reward and collected fees are credited only after them.
            for tx in b['transactions'][1:]:
                s,r=tx['sender'],tx['recipient']
                bal[s]=bal.get(s,0)-tx['amount']-tx['fee']
                bal[r]=bal.get(r,0)+tx['amount']
                nonce[s]=nonce.get(s,0)+1
                nonce.setdefault(r,0)
            cb=b['transactions'][0]
            bal[cb['recipient']]=bal.get(cb['recipient'],0)+cb['amount']
            nonce.setdefault(cb['recipient'],0)
        return bal,nonce
    def check_tx(self,tx,bal,nonces):
        if not isinstance(tx,dict): return False,'transaction must be a JSON object'
        try:
            if len(canon(tx))>MAX_TX_BYTES: return False,'transaction exceeds serialized size limit'
        except (TypeError,ValueError,OverflowError):
            return False,'transaction cannot be canonically encoded'
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
                # Validate and apply ordinary transactions before crediting
                # this block's coinbase, preventing same-block reward spending.
                for tx in txs[1:]:
                    ok,_=self.check_tx(tx,bal,nonces)
                    if not ok: return False
                    s,r=tx['sender'],tx['recipient']
                    bal[s]-=tx['amount']+tx['fee']
                    bal[r]=bal.get(r,0)+tx['amount']
                    nonces[s]=tx['nonce']
                    nonces.setdefault(r,0)
                bal[cb['recipient']]=bal.get(cb['recipient'],0)+cb['amount']
                nonces.setdefault(cb['recipient'],0)
            return True
        except (KeyError,TypeError,ValueError,OverflowError): return False
    def add_tx(self,tx):
        if not isinstance(tx,dict): return False,'transaction must be a JSON object'
        with self.lock:
            if len(self.pool)>=MAX_MEMPOOL_TXS:
                return False,'mempool is full'
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
            self.blocks.append(b); chosen_ids={sha(canon(t)) for t in chosen}; self.pool=[t for t in self.pool if sha(canon(t)) not in chosen_ids]; self._revalidate_pool(); self.save(); return b,'mined'
    def accept_block(self,b):
        with self.lock:
            candidate=self.blocks+[b]
            if not self.valid_chain(candidate):return False,'invalid block'
            self.blocks=candidate; included={sha(canon(t)) for t in b['transactions'][1:]}; self.pool=[t for t in self.pool if sha(canon(t)) not in included]; self._revalidate_pool(); self.save(); return True,'accepted'
    def _revalidate_pool(self):
        bal,nonces=self.state(); accepted=[]
        candidates=[tx for tx in self.pool if isinstance(tx,dict)]
        for tx in sorted(candidates,key=lambda x:(str(x.get('sender','')),x.get('nonce',0) if isinstance(x.get('nonce'),int) and not isinstance(x.get('nonce'),bool) else 0)):
            ok,_=self.check_tx(tx,bal,nonces)
            if not ok: continue
            s,r=tx['sender'],tx['recipient']; bal[s]-=tx['amount']+tx['fee']; bal[r]=bal.get(r,0)+tx['amount']; nonces[s]=tx['nonce']; nonces.setdefault(r,0); accepted.append(tx)
        self.pool=accepted
    def replace(self,bs):
        with self.lock:
            if not self.valid_chain(bs):return False,'candidate chain invalid'
            if chain_work(bs,self.diff)<=chain_work(self.blocks,self.diff):return False,'candidate has no greater cumulative work'
            # Transactions from blocks orphaned by this reorganization are not
            # lost: return them to the mempool unless the new chain includes
            # them or they are no longer valid against the replacement state.
            included={sha(canon(t)) for block in bs[1:] for t in block['transactions'][1:]}
            new_pool=list(self.pool)
            for block in self.blocks[1:]:
                for tx in block['transactions'][1:]:
                    if sha(canon(tx)) not in included:
                        new_pool.append(tx)
            unique_pool={}
            for tx in new_pool:
                unique_pool[sha(canon(tx))]=tx
            self.blocks=list(bs)
            self.pool=[tx for tx in unique_pool.values() if sha(canon(tx)) not in included]
            self._revalidate_pool(); self.save(); return True,'replaced'

class API(BaseHTTPRequestHandler):
    chain=None; peers=[]
    def log_message(self,*args): pass
    def sendj(self,code,obj):
        b=canon(obj); self.send_response(code); self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(b))); self.end_headers(); self.wfile.write(b)
    def body(self):
        lengths=self.headers.get_all('Content-Length', [])
        if len(lengths)!=1: raise ValueError('exactly one Content-Length is required')
        if self.headers.get_all('Transfer-Encoding', []):
            raise ValueError('Transfer-Encoding is not supported')
        raw_length=lengths[0]
        if not isinstance(raw_length,str) or not raw_length.isascii() or not raw_length.isdecimal():
            raise ValueError('invalid Content-Length')
        n=int(raw_length)
        if n<1 or n>1000000: raise ValueError('invalid body size')
        raw=self.rfile.read(n)
        if len(raw)!=n: raise ValueError('incomplete request body')
        value=json.loads(raw)
        if not isinstance(value,dict): raise ValueError('JSON request body must be an object')
        return value
    def do_GET(self):
        p=urlparse(self.path).path
        if p=='/status':
            with self.chain.lock:
                status={'chain_id':self.chain.id,'genesis_hash':self.chain.blocks[0]['hash'],'height':len(self.chain.blocks)-1,'tip':self.chain.blocks[-1]['hash'],'difficulty':self.chain.diff,'block_reward':self.chain.reward,'mempool_size':len(self.chain.pool),'symbol':self.chain.cfg.get('symbol','COIN'),'consensus':getattr(self.chain,'consensus_mode','pow')}
                if getattr(self.chain,'validators_hash',None):
                    status['validator_set_hash']=self.chain.validators_hash
                self.sendj(200,status)
        elif p=='/chain':
            query=parse_qs(urlparse(self.path).query,keep_blank_values=True)
            if not query:
                with self.chain.lock: self.sendj(200,{'chain':list(self.chain.blocks)})
                return
            if (set(query)!={'start','limit'} or len(query['start'])!=1 or len(query['limit'])!=1
                    or not query['start'][0].isascii() or not query['start'][0].isdecimal()
                    or not query['limit'][0].isascii() or not query['limit'][0].isdecimal()):
                self.sendj(400,{'error':'chain page requires one non-negative start and positive limit'})
                return
            start,limit=int(query['start'][0]),int(query['limit'][0])
            if limit<1 or limit>MAX_CHAIN_PAGE_BLOCKS:
                self.sendj(400,{'error':'chain page limit is outside the allowed range'})
                return
            with self.chain.lock:
                page=list(self.chain.blocks[start:start+limit])
            self.sendj(200,{'start':start,'chain':page})
        elif p=='/balances':
            with self.chain.lock: b,n=self.chain.state()
            self.sendj(200,{'balances':b,'nonces':n})
        elif p=='/mempool':
            with self.chain.lock: self.sendj(200,{'transactions':list(self.chain.pool)})
        elif p=='/peers': self.sendj(200,{'peers':list(self.peers)})
        else:self.sendj(404,{'error':'not found'})
    def do_POST(self):
        try:
            d=self.body(); p=urlparse(self.path).path
            if p in ('/tx','/receive-tx'):
                ok,msg=self.chain.add_tx(d)
                if ok: broadcast(self.peers,'/receive-tx',d)
                self.sendj(200 if ok else 400,{'ok':ok,'message':msg})
            elif p in ('/mine',):
                b,msg=self.chain.mine(d.get('miner',''))
                if b: broadcast(self.peers,'/receive-block',b); self.sendj(200,{'ok':True,'block':b})
                else:self.sendj(400,{'ok':False,'message':msg})
            elif p=='/receive-block':
                ok,msg=self.chain.accept_block(d)
                if ok: broadcast(self.peers,'/receive-block',d)
                self.sendj(200 if ok else 400,{'ok':ok,'message':msg})
            elif p=='/receive-chain':
                candidate=d.get('chain')
                if not isinstance(candidate,list):
                    self.sendj(400,{'ok':False,'message':'chain must be a list'});return
                ok,msg=self.chain.replace(candidate)
                if ok:
                    with self.chain.lock: accepted_chain=list(self.chain.blocks)
                    broadcast(self.peers,'/receive-chain',{'chain':accepted_chain})
                self.sendj(200 if ok else 400,{'ok':ok,'message':msg})
            elif p=='/connect':
                raw_peer=d.get('peer')
                if not isinstance(raw_peer,str): self.sendj(400,{'error':'peer must be an HTTP(S) URL'});return
                parsed=urlparse(raw_peer)
                if parsed.scheme not in ('http','https') or not parsed.hostname or parsed.username or parsed.password or parsed.path not in ('','/') or parsed.query or parsed.fragment:
                    self.sendj(400,{'error':'peer must be a base HTTP(S) URL without credentials, path, query, or fragment'});return
                try: parsed.port
                except ValueError: self.sendj(400,{'error':'peer URL has an invalid port'});return
                if (getattr(self.chain,'consensus_mode','pow')=='bft'
                        and parsed.scheme!='https'
                        and parsed.hostname not in ('127.0.0.1','localhost','::1')):
                    self.sendj(400,{'error':'remote BFT chain peers must use HTTPS'});return
                peer=raw_peer.rstrip('/')
                status=get(peer+'/status')
                expected={'chain_id':self.chain.id,'genesis_hash':self.chain.blocks[0]['hash'],'difficulty':self.chain.diff,'block_reward':self.chain.reward,'consensus':getattr(self.chain,'consensus_mode','pow')}
                if getattr(self.chain,'validators_hash',None):
                    expected['validator_set_hash']=self.chain.validators_hash
                if any(status.get(k)!=v for k,v in expected.items()):
                    self.sendj(400,{'error':'peer is on a different network configuration'});return
                remote_chain=fetch_peer_chain(peer,status)
                if not self.chain.valid_chain(remote_chain):
                    self.sendj(400,{'error':'peer supplied an invalid chain'});return
                if len(remote_chain)>len(self.chain.blocks):
                    self.chain.replace(remote_chain)
                if peer not in self.peers:
                    with self.chain.lock:
                        self.peers.append(peer)
                        self.chain.save()
                self.sendj(200,{'ok':True,'peer':peer,'status':status})
            else:self.sendj(404,{'error':'not found'})
        except Exception as e:self.sendj(400,{'error':str(e)})

def main():
    p=argparse.ArgumentParser();p.add_argument('--config',default='config.json');p.add_argument('--data',default=None);a=p.parse_args()
    cp=Path(a.config)
    if not cp.exists():raise SystemExit('Config missing. Copy config.example.json to config.json and configure it.')
    cfg=json.loads(cp.read_text()); c=Chain(cfg,a.data or f"data-{cfg.get('port',8333)}.json")
    API.chain=c;API.peers=c.peers
    threading.Thread(target=peer_sync_loop,args=(c,),daemon=True).start()
    srv=ThreadingHTTPServer((cfg.get('host','127.0.0.1'),int(cfg.get('port',8333))),API)
    print(f"Milkchain node on {cfg.get('host')}:{cfg.get('port')} | chain={c.id} | height={len(c.blocks)-1}")
    try:srv.serve_forever()
    except KeyboardInterrupt:pass
    finally:srv.server_close()
if __name__=='__main__':main()
