#!/usr/bin/env python3
"""Create Ed25519 wallets for Emberchain. Private keys are stored unencrypted."""
import argparse, json
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

def main():
    p=argparse.ArgumentParser(); sub=p.add_subparsers(dest='cmd',required=True)
    c=sub.add_parser('create'); c.add_argument('file')
    a=sub.add_parser('address'); a.add_argument('file')
    x=p.parse_args()
    if x.cmd=='create':
        k=Ed25519PrivateKey.generate()
        priv=k.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption()).hex()
        pub=k.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()
        Path(x.file).write_text(json.dumps({'private_key':priv,'public_key':pub},indent=2)+'\n')
        try: Path(x.file).chmod(0o600)
        except OSError: pass
        print('Public address:',pub); print('Keep the wallet file secret; anyone with its private key can spend funds.')
    else: print(json.loads(Path(x.file).read_text())['public_key'])
if __name__=='__main__': main()
