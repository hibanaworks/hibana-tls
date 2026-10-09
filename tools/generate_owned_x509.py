#!/usr/bin/env python3
"""Generate public OpenSSL fixtures; ephemeral private keys stay in a temporary directory."""
import subprocess,pathlib,tempfile
temporary=tempfile.TemporaryDirectory(prefix='hibana-x509-fixtures-')
p=pathlib.Path(temporary.name)
out=pathlib.Path(__file__).resolve().parents[1]/'tests/vectors/x509-owned'
out.mkdir(parents=True,exist_ok=True)
def run(*args): subprocess.run(['openssl',*args],cwd=p,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
def key(name):run('genpkey','-algorithm','EC','-pkeyopt','ec_paramgen_curve:P-256','-out',name+'.key')
def req(name): run('req','-new','-key',name+'.key','-subj','/CN='+name,'-out',name+'.csr')
def sign(name,parent,ext,serial):
 (p/(name+'.ext')).write_text(ext)
 run('x509','-req','-in',name+'.csr','-CA',parent+'.pem','-CAkey',parent+'.key','-set_serial',str(serial),'-days','3650','-sha256','-extfile',name+'.ext','-out',name+'.pem')
 run('x509','-in',name+'.pem','-outform','DER','-out',str(out/(name+'.der')))
key('root');run('req','-new','-x509','-key','root.key','-subj','/CN=Owned Test Root','-days','3650','-sha256','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign','-out','root.pem');run('x509','-in','root.pem','-outform','DER','-out',str(out/'root.der'))
serial=1
for mode,extra in [('permitted','nameConstraints=critical,permitted;DNS:allowed.test'),('excluded','nameConstraints=critical,excluded;DNS:allowed.test'),('pathzero','basicConstraints=critical,CA:TRUE,pathlen:0'),('unknown','1.2.3.4=critical,DER:05:00')]:
 parent='root'
 for depth in range(2):
  name=mode+'-ca'+str(depth);key(name);req(name)
  ext='basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n'
  if depth==0:
   if mode=='pathzero':ext=extra+'\nkeyUsage=critical,keyCertSign\n'
   else:ext+=extra+'\n'
  sign(name,parent,ext,serial);serial+=1;parent=name
 name=mode+'-leaf';key(name);req(name);sign(name,parent,'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:server.allowed.test\n',serial);serial+=1
for mode,extra in [('valid',''),('clientonly','extendedKeyUsage=clientAuth'),('unknown','1.2.3.4=critical,DER:05:00'),('ip','subjectAltName=IP:127.0.0.1'),('wildcard','subjectAltName=DNS:*.allowed.test')]:
 name='direct-'+mode;key(name);req(name)
 ext='basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:server.allowed.test\n'
 if extra:ext+='\n'+extra+'\n'
 sign(name,'root',ext,serial);serial+=1
(out/'README.md').write_text('Public certificate-only fixtures generated with OpenSSL 3 on 2026-10-08. Private ephemeral keys are not distributed. Tests inject Unix time 1800000000. Modes cover DNS permitted/excluded subtrees, pathlen, unknown critical extensions, EKU, direct trust, wildcard DNS and IP SAN. Not a security qualification.\n')

temporary.cleanup()
