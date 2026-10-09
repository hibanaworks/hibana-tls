#!/usr/bin/env python3
"""Independent OpenSSL X25519 and Python integer field oracles, test-only."""
from pathlib import Path
from hashlib import sha256
import cryptography
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey,X25519PublicKey
root=Path(__file__).resolve().parents[1]
rows=[f'// cryptography {cryptography.__version__}; tools/x25519_vectors.py','&[']
for i in range(256):
 k=sha256(b'hibana-scalar'+i.to_bytes(4,'big')).digest();u=sha256(b'hibana-peer'+i.to_bytes(4,'big')).digest()
 out=X25519PrivateKey.from_private_bytes(k).exchange(X25519PublicKey.from_public_bytes(u))
 rows.append(f'("{k.hex()}","{u.hex()}","{out.hex()}"),')
rows.append(']');(root/'tests/x25519_vectors.in').write_text('\n'.join(rows)+'\n')
p=2**255-19
values=[0,1,2,18,19,20,p-2,p-1,p,p+1,2**255-1]+[int.from_bytes(sha256(b'field'+i.to_bytes(4,'big')).digest(),'little')%(2**255) for i in range(40)]
rows=['// Python arbitrary-precision field oracle; tools/x25519_vectors.py','&[']
for a in values:
 for b in values:
  fields=[a,b,(a+b)%p,(a-b)%p,(a*b)%p]
  rows.append('('+','.join('"'+x.to_bytes(32,'little').hex()+'"' for x in fields)+'),')
rows.append(']');(root/'tests/x25519_field_vectors.in').write_text('\n'.join(rows)+'\n')
