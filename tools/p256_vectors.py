"""Independent P-256 qualification data: Python integers + cryptography/OpenSSL.
All keys are public synthetic test fixtures, not credentials.
RFC6979 nonce generation uses Python's hmac; nonce*G uses OpenSSL.
"""
from pathlib import Path
import hashlib,hmac
from cryptography.hazmat.primitives.asymmetric import ec,utils
from cryptography.hazmat.primitives import hashes,serialization
P=2**256-2**224+2**192+2**96-1
N=int('ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551',16)
ROOT=Path(__file__).resolve().parents[1]/'tests/vectors';ROOT.mkdir(parents=True,exist_ok=True)
def b(x):return x.to_bytes(32,'big')
def rawkey(key):return key.public_key().public_bytes(serialization.Encoding.X962,serialization.PublicFormat.UncompressedPoint)
def deterministic(d,digest):
 h=b(int.from_bytes(digest,'big')%N);v=bytes([1])*32;k=bytes(32)
 def mac(k,x):return hmac.new(k,x,hashlib.sha256).digest()
 for c in (0,1):k=mac(k,v+bytes([c])+b(d)+h);v=mac(k,v)
 while True:
  v=mac(k,v);nonce=int.from_bytes(v,'big')
  if 0<nonce<N:
   r=ec.derive_private_key(nonce,ec.SECP256R1()).public_key().public_numbers().x%N
   s=(pow(nonce,-1,N)*(int.from_bytes(h,'big')+r*d))%N
   if r and s:return b(r)+b(s)
  k=mac(k,v+b'\0');v=mac(k,v)
records=bytearray();ders=bytearray()
for i in range(128):
 d=([1,2,N-1,N-2][i] if i<4 else int.from_bytes(hashlib.sha256(b'p256 private'+b(i)).digest(),'big')%(N-1)+1)
 e=int.from_bytes(hashlib.sha256(b'p256 peer'+b(i)).digest(),'big')%(N-1)+1
 key=ec.derive_private_key(d,ec.SECP256R1());peer=ec.derive_private_key(e,ec.SECP256R1())
 digest=([bytes(32),b(N),b(N-1),bytes([255])*32][i] if i<4 else hashlib.sha256(b'p256 message'+b(i)).digest())
 own=deterministic(d,digest);key.public_key().verify(utils.encode_dss_signature(int.from_bytes(own[:32],'big'),int.from_bytes(own[32:],'big')),digest,ec.ECDSA(utils.Prehashed(hashes.SHA256())))
 r,s=utils.decode_dss_signature(key.sign(digest,ec.ECDSA(utils.Prehashed(hashes.SHA256()))))
 records+=b(d)+rawkey(key)+rawkey(peer)+key.exchange(ec.ECDH(),peer.public_key())+digest+own+b(r)+b(s)
 if i<8:
  for fmt in [serialization.PrivateFormat.PKCS8,serialization.PrivateFormat.TraditionalOpenSSL]:
   der=key.private_bytes(serialization.Encoding.DER,fmt,serialization.NoEncryption());ders+=len(der).to_bytes(2,'big')+der+rawkey(key)
(ROOT/'p256-openssl.bin').write_bytes(records);(ROOT/'p256-key-der.bin').write_bytes(ders)
records=bytearray()
for m in [P,N]:
 values=[0,1,2,m-1,m-2,2**128-1,2**192,2**255]+[(2**i)%m for i in range(256)]
 values += [int.from_bytes(hashlib.sha256(b'p256 modular'+b(i)).digest(),'big')%m for i in range(256)]
 for i,a in enumerate(values):
  c=values[(i*71+137)%len(values)]
  for x in [a,c,(a+c)%m,(a-c)%m,(a*c)%m,pow(a,m-2,m)]:records+=b(x)
(ROOT/'p256-modular.bin').write_bytes(records)
print('128 OpenSSL key/ECDH/deterministic+random signature cases; 16 DER keys;',len(values)*2,'Python modular records')
