"""Compile independently downloaded Wycheproof JSON into dependency-free test data.
No upstream code is executed. Run with a directory containing the four JSON files.
Unsupported AEAD key/nonce/tag profiles are recorded, never counted as passes.
"""
from pathlib import Path
import sys,json,hashlib,struct,collections
source=Path(sys.argv[1]);dest=Path(__file__).resolve().parents[1]/'tests/vectors/wycheproof'
dest.mkdir(exist_ok=True);report={}
def field(b):return struct.pack('>I',len(b))+b
for name in ['aes_gcm_test.json','chacha20_poly1305_test.json','x25519_test.json','ecdsa_secp256r1_sha256_test.json']:
 raw=(source/name).read_bytes();data=json.loads(raw);records=[];excluded=[];counts=collections.Counter()
 for group in data['testGroups']:
  for test in group['tests']:
   if name in ['aes_gcm_test.json','chacha20_poly1305_test.json']:
    if group['keySize']!=(128 if name.startswith('aes') else 256) or group['ivSize']!=96 or group['tagSize']!=128:
     excluded.append(test['tcId']);continue
    values=[bytes.fromhex(test[k]) for k in ['key','iv','aad','msg','ct','tag']]
   elif name.startswith('x25519'):
    values=[bytes.fromhex(test[k]) for k in ['private','public','shared']]
   else:
    values=[bytes.fromhex(group['publicKey']['uncompressed']),bytes.fromhex(test['msg']),bytes.fromhex(test['sig'])]
   result={'invalid':0,'valid':1,'acceptable':2}[test['result']];counts[test['result']]+=1
   records.append(struct.pack('>IB',test['tcId'],result)+b''.join(field(v) for v in values))
 output=b'WYCP0001'+struct.pack('>I',len(records))+b''.join(records);out=name.replace('.json','.bin');(dest/out).write_bytes(output)
 report[name]={'source':'https://raw.githubusercontent.com/C2SP/wycheproof/main/testvectors_v1/'+name,'source_sha256':hashlib.sha256(raw).hexdigest(),'selected':len(records),'classification':dict(counts),'excluded_outside_profile_ids':excluded,'output_sha256':hashlib.sha256(output).hexdigest()}
(dest/'PROVENANCE.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
