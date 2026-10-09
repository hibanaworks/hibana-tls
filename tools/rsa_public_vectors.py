"""Independent public modular exponentiation cases using Python integers."""
from pathlib import Path
import hashlib
out=bytearray()
for width in [256,384,512]:
 for i in range(48):
  n=int.from_bytes(hashlib.shake_256(b'RSA public modulus '+bytes([i])).digest(width),'big')|(1<<(8*width-1))|1
  if i==0:n=(1<<(8*width))-1
  if i==1:n=(1<<(8*width-1))+1
  e=[3,17,65537,2**32-1][i%4]
  s=int.from_bytes(hashlib.shake_256(b'RSA public signature '+bytes([i])).digest(width),'big')%n
  if i in [0,1,2,3]:s=[0,1,n-1,n-2][i]
  out+=width.to_bytes(2,'big')+e.to_bytes(4,'big')+n.to_bytes(width,'big')+s.to_bytes(width,'big')+pow(s,e,n).to_bytes(width,'big')
p=Path(__file__).resolve().parents[1]/'tests/vectors/rsa-public-python.bin';p.write_bytes(out)
print('144 independent public modular exponentiation cases')
