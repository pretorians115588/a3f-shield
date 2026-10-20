"""v5 engine additions against the v4 file format; no new format version."""
import os
import secrets
import subprocess
import sys
from pathlib import Path

import pytest
from a3f_v4 import (
    HEADER, CHUNK_MAX, _parse_header, _ordered_transform, benchmark,
    encrypt_file, decrypt_file, FormatError,
)

AES = bytes(range(32))
TF = bytes(range(32,64))

@pytest.mark.parametrize('mode', ['aes', 'threefish', 'hybrid'])
@pytest.mark.parametrize('size', [0, 1, 1023, 1024, 1025, 8191, 8192, 8193, 32768])
@pytest.mark.parametrize('workers', [1, 2, 4])
def test_pipeline_roundtrip_v4(mode, size, workers, tmp_path):
    plain = secrets.token_bytes(size)
    src, ct, result = (tmp_path / name for name in ('plain', 'cipher', 'out'))
    src.write_bytes(plain)
    kwargs = dict(aes_key=AES if mode != 'threefish' else None,
                  tf_key=TF if mode != 'aes' else None)
    encrypt_file(src, ct, mode=mode, chunk_kib=1, workers=workers, **kwargs)
    with open(ct,'rb') as f: p=_parse_header(f.read(HEADER.size))
    assert p['chunk_size'] == 1024
    decrypt_file(ct, result, workers=workers, **kwargs)
    assert result.read_bytes() == plain
    assert not list(tmp_path.glob('.a3f4-partial-*'))

@pytest.mark.parametrize('workers',[1,2,4,8])
def test_pipeline_corruption_no_release(workers, tmp_path):
    src,ct,out=(tmp_path/x for x in ['plain','cipher','out'])
    src.write_bytes(secrets.token_bytes(8210))
    encrypt_file(src,ct,mode='hybrid',chunk_kib=1,aes_key=AES,tf_key=TF,workers=4)
    data=bytearray(ct.read_bytes());data[-1]^=0x01;ct.write_bytes(data)
    with pytest.raises(FormatError):
        decrypt_file(ct,out,aes_key=AES,tf_key=TF,workers=workers)
    assert not out.exists()
    assert not list(tmp_path.glob('.a3f4-partial-*'))

@pytest.mark.parametrize('workers',[1,2,4,8])
def test_pipeline_prepublish_failure_keeps_plaintext_private(workers, tmp_path):
    src,ct,out=(tmp_path/x for x in ['plain','cipher','out'])
    src.write_bytes(secrets.token_bytes(9100))
    encrypt_file(src,ct,mode='hybrid',chunk_kib=1,aes_key=AES,tf_key=TF,workers=workers)
    def fail(): raise RuntimeError('witness changed at prepublish')
    with pytest.raises(RuntimeError):
        decrypt_file(ct,out,aes_key=AES,tf_key=TF,workers=workers,prepublish_check=fail)
    assert not out.exists()
    assert not list(tmp_path.glob('.a3f4-partial-*'))

def test_bounded_ordered_executor_fails_without_late_publication():
    jobs=((i,) for i in range(16))
    assert list(_ordered_transform(jobs,lambda i:i*i,4)) == [i*i for i in range(16)]
    def fail(i):
        if i==3: raise FormatError('deliberate')
        return i
    with pytest.raises(FormatError):
        list(_ordered_transform(((i,) for i in range(16)),fail,4))

@pytest.mark.parametrize('workers',[0,-1,9,100])
def test_workers_fail_closed(workers,tmp_path):
    src=tmp_path/'plain';src.write_bytes(b'data')
    with pytest.raises(ValueError):
        encrypt_file(src,tmp_path/'cipher',mode='hybrid',aes_key=AES,tf_key=TF,workers=workers)
    with pytest.raises(ValueError):
        decrypt_file(src,tmp_path/'out',aes_key=AES,tf_key=TF,workers=workers)

@pytest.mark.parametrize('kib', [1,1024,2048,8192])
def test_multichunk_benchmark_supported(kib):
    r=benchmark(kib,1)
    assert len(r)==3
    assert all(x['encrypt_MiB_per_s']>0 and x['decrypt_MiB_per_s']>0 for x in r)
    assert all(x['chunks_per_iteration']==(kib+1023)//1024 for x in r)

@pytest.mark.parametrize('kib,repeat',[(0,10),(65537,1),(64,101),(65536,100)])
def test_benchmark_resource_boundaries(kib,repeat):
    with pytest.raises(ValueError):benchmark(kib,repeat)

def test_cli_pipeline_flags(tmp_path):
    base=Path(__file__).resolve().parents[1]
    src,ct,out=(tmp_path/x for x in ['plain','cipher','out'])
    src.write_bytes(secrets.token_bytes(3000))
    (tmp_path/'aes.key').write_bytes(AES)
    (tmp_path/'tf.key').write_bytes(TF)
    cmd=[sys.executable,str(base/'a3f_v4.py')]
    creds=['--aes-keyfile',str(tmp_path/'aes.key'),'--tf-keyfile',str(tmp_path/'tf.key')]
    def run(args):
        p=subprocess.run(cmd+args+creds+['--allow-no-replay-protection','--workers','3'],capture_output=True,text=True)
        assert p.returncode==0,p.stderr
    run(['encrypt',str(src),str(ct),'--mode','hybrid','--chunk-kib','1'])
    run(['decrypt',str(ct),str(out)])
    assert out.read_bytes()==src.read_bytes()

def test_parallel_ciphertext_identical_to_single_thread(tmp_path, monkeypatch):
    # All file header entropy controlled so identical inputs/keys are comparable.
    # This is TEST-ONLY deterministic RNG: never use fixed salts/IDs/nonces in real encryption.
    import random
    import a3f_v4
    source=tmp_path/'plain';source.write_bytes(secrets.token_bytes(36877))
    def encrypt_to(path,workers):
        rng=random.Random(20261020)
        monkeypatch.setattr(a3f_v4.secrets,'token_bytes',lambda n:rng.randbytes(n))
        encrypt_file(source,path,mode='hybrid',aes_key=AES,tf_key=TF,chunk_kib=1,workers=workers)
    one=tmp_path/'one';four=tmp_path/'four'
    encrypt_to(one,1)
    encrypt_to(four,4)
    assert one.read_bytes()==four.read_bytes()
    decrypt_file(one,tmp_path/'out',aes_key=AES,tf_key=TF,workers=8)
    assert (tmp_path/'out').read_bytes()==source.read_bytes()

@pytest.mark.parametrize('workers',[1,4])
def test_pipeline_worker_fails_cleanup(tmp_path, monkeypatch, workers):
    import a3f_v4
    original=a3f_v4.Engine.encrypt
    def raise_on_second(self,index,plain):
        if index==2:raise RuntimeError('synthetic engine error')
        return original(self,index,plain)
    monkeypatch.setattr(a3f_v4.Engine,'encrypt',raise_on_second)
    src=tmp_path/'plain';ct=tmp_path/'cipher'
    src.write_bytes(secrets.token_bytes(8000))
    with pytest.raises(RuntimeError):
        encrypt_file(src,ct,mode='hybrid',aes_key=AES,tf_key=TF,chunk_kib=1,workers=workers)
    assert not ct.exists()
    assert not list(tmp_path.glob('.a3f4-partial-*'))

@pytest.mark.parametrize('workers',[1,4])
def test_parallel_decrypt_worker_fails_cleanup(tmp_path, monkeypatch, workers):
    import a3f_v4
    src=tmp_path/'plain';ct=tmp_path/'cipher';out=tmp_path/'out'
    src.write_bytes(secrets.token_bytes(8000))
    encrypt_file(src,ct,mode='hybrid',aes_key=AES,tf_key=TF,chunk_kib=1,workers=4)
    original=a3f_v4.Engine.decrypt
    def raise_on_second(self,index,payload,want):
        if index==2:raise RuntimeError('synthetic decryption error')
        return original(self,index,payload,want)
    monkeypatch.setattr(a3f_v4.Engine,'decrypt',raise_on_second)
    with pytest.raises(RuntimeError):
        decrypt_file(ct,out,aes_key=AES,tf_key=TF,workers=workers)
    assert not out.exists()
    assert not list(tmp_path.glob('.a3f4-partial-*'))

@pytest.mark.parametrize('workers',[1,4])
def test_authenticated_format_tampered_frame_rejected(tmp_path,workers):
    src=tmp_path/'plain';ct=tmp_path/'cipher';out=tmp_path/'out'
    src.write_bytes(secrets.token_bytes(2900))
    encrypt_file(src,ct,mode='hybrid',aes_key=AES,tf_key=TF,chunk_kib=1,workers=4)
    data=bytearray(ct.read_bytes());data[HEADER.size+10]^=1
    ct.write_bytes(data)
    with pytest.raises(FormatError):
        decrypt_file(ct,out,aes_key=AES,tf_key=TF,workers=workers)
    assert not out.exists()
