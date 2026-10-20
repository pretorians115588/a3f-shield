import os, secrets,stat,subprocess,sys,socket,time
from pathlib import Path
import pytest
from threefish_native import Threefish1024
from threefish1024_ref import Threefish1024 as ThreefishReference
from a3f_v4 import HEADER,_parse_header,encrypt_file,decrypt_file,MAGIC,VERSION,FormatError,_keygen
from rollback_ledger import Ledger,ReplayError,digest_file
from remote_witness import call_witness

A=bytes(range(32)); T=bytes(range(32,64))

def mkfile(tmp,doc,version,content):
    src=tmp/f'raw{version}'; dst=tmp/f'enc{version}'
    src.write_bytes(content)
    encrypt_file(src,dst,mode='hybrid',aes_key=A,tf_key=T,
                 document_id=doc,generation=version,chunk_kib=1)
    return dst

@pytest.mark.parametrize('i',range(30))
def test_native_and_reference_independent_encryption(i):
    key=secrets.token_bytes(128);tweak=secrets.token_bytes(16);block=secrets.token_bytes(128)
    reference=ThreefishReference(key,tweak)
    native=Threefish1024(key,tweak)
    expected=reference.encrypt_block(block)
    assert native.encrypt_block(block)==expected
    assert native.decrypt_block(expected)==block

@pytest.mark.parametrize('size',[0,1,127,128,129,1234,65536])
def test_native_ctr_matches_python_reference(size):
    from a3f_v4 import TF_CTR_DOMAIN
    key=secrets.token_bytes(128);siv=secrets.token_bytes(32);content=secrets.token_bytes(size)
    native=Threefish1024(key)
    ref=ThreefishReference(key)
    expected=bytearray(content)
    for c in range((size+127)//128):
        stream=ref.encrypt_block(TF_CTR_DOMAIN+siv+c.to_bytes(8,'big')+bytes(72))
        for j in range(min(128,size-c*128)):expected[c*128+j]^=stream[j]
    assert native.xor_ctr(content,siv)==bytes(expected)
    assert native.xor_ctr(bytes(expected),siv)==content


def test_rollback_of_valid_copyright_file_detected_by_ledger(tmp_path):
    doc=secrets.token_bytes(16);ledger=tmp_path/'ledger.db';key=secrets.token_bytes(32)
    one=mkfile(tmp_path,doc,1,b'legitimate old version'*63)
    two=mkfile(tmp_path,doc,2,b'legitimate new version'*63)
    with Ledger(ledger,key) as witness:
        witness.register(doc,1,digest_file(one))
        witness.verify(doc,1,digest_file(one))
        witness.register(doc,2,digest_file(two))
        with pytest.raises(ReplayError):witness.verify(doc,1,digest_file(one))
        witness.verify(doc,2,digest_file(two))
    # Important: the old ciphertext is STILL cryptographically valid. The
    # external trusted state, not AEAD, is what detects the rollback.
    end=tmp_path/'old-is-still-decryptable'
    decrypt_file(one,end,aes_key=A,tf_key=T)
    assert end.read_bytes().startswith(b'legitimate old version')


def test_ledger_rejects_version_skipping_and_fake_latest(tmp_path):
    doc=secrets.token_bytes(16);key=secrets.token_bytes(32)
    with Ledger(tmp_path/'ledger.db',key) as w:
        with pytest.raises(ReplayError):w.register(doc,2,bytes(32))
        w.register(doc,1,b'a'*32)
        with pytest.raises(ReplayError):w.register(doc,1,b'b'*32)
        with pytest.raises(ReplayError):w.register(doc,3,b'b'*32)
        with pytest.raises(ReplayError):w.verify(doc,1,b'b'*32)


def test_ledger_authentication_against_db_patch(tmp_path):
    import sqlite3
    path=tmp_path/'ledger.db';key=secrets.token_bytes(32);doc=secrets.token_bytes(16)
    with Ledger(path,key) as w:w.register(doc,1,bytes(32))
    con=sqlite3.connect(path)
    con.execute('UPDATE latest SET digest=?',(bytes([1])*32,));con.commit();con.close()
    with Ledger(path,key) as w:
        with pytest.raises(ReplayError):w.verify(doc,1,bytes(32))


def test_windows_key_wrapper_not_silently_portable_on_linux(tmp_path):
    if os.name!='nt':
        from win_dpapi import generate_dpapi_key
        with pytest.raises(OSError):generate_dpapi_key(tmp_path/'key')


def test_output_files_private_owner_posix(tmp_path):
    doc=secrets.token_bytes(16)
    ct=mkfile(tmp_path,doc,1,b'nonsecret example')
    if os.name!='nt':
        assert (stat.S_IMODE(ct.stat().st_mode)&0o077)==0


def test_cli_requires_witness_and_random_keys(tmp_path):
    src=tmp_path/'plain'; src.write_bytes(b'test')
    ct=tmp_path/'cipher'
    a=tmp_path/'a';t=tmp_path/'t';a.write_bytes(A);t.write_bytes(T)
    cmd=[sys.executable,'a3f_v4.py','encrypt',str(src),str(ct),
         '--mode','hybrid','--aes-keyfile',str(a),'--tf-keyfile',str(t)]
    r=subprocess.run(cmd,cwd=Path(__file__).resolve().parents[1],capture_output=True,text=True)
    assert r.returncode!=0 and 'Anti-rollback ledger required' in r.stderr
    assert not ct.exists()


def test_remote_witness_same_document_version_rollback(tmp_path):
    secret=secrets.token_bytes(32)
    secretfile=tmp_path/'secret';secretfile.write_bytes(secret)
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    cmd=[sys.executable,'remote_witness.py','--db',str(tmp_path/'remote.db'),
         '--secret-file',str(secretfile),'--port',str(port)]
    p=subprocess.Popen(cmd,cwd=Path(__file__).resolve().parents[1],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try:
        for _ in range(40):
            with socket.socket() as sock:
                if sock.connect_ex(('127.0.0.1',port))==0:break
            time.sleep(0.05)
        url=f'http://127.0.0.1:{port}'
        doc=secrets.token_bytes(16);d1=secrets.token_bytes(32);d2=secrets.token_bytes(32)
        assert call_witness(url,secret,'register',doc,1,d1)
        assert call_witness(url,secret,'verify',doc,1,d1)
        assert call_witness(url,secret,'register',doc,2,d2)
        with pytest.raises(ReplayError):call_witness(url,secret,'verify',doc,1,d1)
        assert call_witness(url,secret,'verify',doc,2,d2)
    finally:
        p.terminate();p.wait(timeout=5)

def test_revalidate_witness_before_releasing_plaintext(tmp_path):
    doc=secrets.token_bytes(16);key=secrets.token_bytes(32)
    one=mkfile(tmp_path,doc,1,b'finality-test-old-data')
    two=mkfile(tmp_path,doc,2,b'finality-test-new-data')
    witness_path=tmp_path/'ledger.db'
    with Ledger(witness_path,key) as witness:
        witness.register(doc,1,digest_file(one))
    def become_stale():
        with Ledger(witness_path,key) as witness:
            witness.register(doc,2,digest_file(two))
            witness.verify(doc,1,digest_file(one))
    final=tmp_path/'output'
    with pytest.raises(ReplayError):
        decrypt_file(one,final,aes_key=A,tf_key=T,prepublish_check=become_stale)
    assert not final.exists()
