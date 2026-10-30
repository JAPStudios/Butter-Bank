#!/usr/bin/env python3
"""Create and inspect Ed25519 wallets for Emberchain."""
import argparse, json, os
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

def public_hex(key):
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()

def read_wallet(path):
    data=json.loads(Path(path).read_text())
    if not isinstance(data,dict) or set(data)!={'private_key','public_key'}:
        raise ValueError('wallet file must contain private_key and public_key')
    try:
        private=bytes.fromhex(data['private_key'])
        public=bytes.fromhex(data['public_key'])
    except (TypeError,ValueError):
        raise ValueError('wallet keys must be hexadecimal')
    if len(private)!=32 or len(public)!=32:
        raise ValueError('wallet keys must each be 32 bytes')
    key=Ed25519PrivateKey.from_private_bytes(private)
    if public_hex(key)!=public.hex():
        raise ValueError('wallet public key does not match its private key')
    return key,public.hex()

def main():
    p=argparse.ArgumentParser()
    sub=p.add_subparsers(dest='cmd',required=True)
    c=sub.add_parser('create'); c.add_argument('file')
    a=sub.add_parser('address'); a.add_argument('file')
    x=p.parse_args()
    if x.cmd=='create':
        target=Path(x.file)
        if target.exists(): raise SystemExit('Refusing to overwrite an existing wallet file.')
        k=Ed25519PrivateKey.generate()
        priv=k.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption()).hex()
        pub=public_hex(k)
        flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL
        fd=os.open(str(target),flags,0o600)
        with os.fdopen(fd,'w') as out:
            out.write(json.dumps({'private_key':priv,'public_key':pub},indent=2)+'\\n')
        try: target.chmod(0o600)
        except OSError: pass
        print('Public address:',pub)
        print('Keep the wallet file secret; anyone with its private key can spend funds.')
    else:
        _,pub=read_wallet(x.file)
        print(pub)

if __name__=='__main__': main()
