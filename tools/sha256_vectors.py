"""Independent Python hashlib SHA-256 known answers for incremental boundary cases."""
from pathlib import Path
import hashlib
out=bytearray()
lengths=list(range(261))+[511,512,513,1023,1024,1025,4095,4096,4097]
for seed in [0,17,255]:
 for n in lengths:
  message=bytes(((i*73+seed)^(i>>3))&255 for i in range(n))
  out+=n.to_bytes(4,'big')+bytes([seed])+hashlib.sha256(message).digest()
p=Path(__file__).resolve().parents[1]/'tests/vectors/sha256-hashlib.bin';p.write_bytes(out)
print(len(lengths)*3,'hashlib known answers')
