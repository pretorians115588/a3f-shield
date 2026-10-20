"""A3F v4-compatible v5 engine diagnostic (NO real secret files).

Report isolated stage throughput and full-file wall time on the *local* host.
Stage costs are intentionally not added together: caches and allocation differ.
"""
import argparse
import json
import os
from pathlib import Path
import secrets
import statistics
import tempfile
import time
import platform
import hashlib
import hmac
import sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV

BASE=Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE / 'src'))
from a3f_v4 import encrypt_file, decrypt_file
from threefish_native import Threefish1024

MiB=1048576

def speed(fn, mb=1, repeat=8):
    fn()
    samples=[]
    for _ in range(repeat):
        t=time.perf_counter()
        fn()
        samples.append(mb/(time.perf_counter()-t))
    return {'median_MiB_s':round(statistics.median(samples),2),
            'min_MiB_s':round(min(samples),2), 'max_MiB_s':round(max(samples),2)}

def run(mib=16, workers=4):
    if not 1<=mib<=256 or not 1<=workers<=8:
        raise ValueError('mib must be 1..256 and workers 1..8')
    key=secrets.token_bytes(128)
    chunk=secrets.token_bytes(MiB)
    iv=secrets.token_bytes(32)
    tf=Threefish1024(key)
    aes=AESGCMSIV(secrets.token_bytes(32))
    aesnonce=secrets.token_bytes(12)
    aad=b'A3F/PROFILE/v5'
    enc=aes.encrypt(aesnonce,chunk,aad)
    mac_key=secrets.token_bytes(32)
    items={
        'native_threefish_ctr_encrypt':speed(lambda:tf.xor_ctr(chunk,iv)),
        'native_threefish_ctr_decrypt':speed(lambda:tf.xor_ctr(chunk,iv)),
        'aes_gcm_siv_encrypt':speed(lambda:aes.encrypt(aesnonce,chunk,aad)),
        'aes_gcm_siv_decrypt':speed(lambda:aes.decrypt(aesnonce,enc,aad)),
        'hmac_sha256_one_pass':speed(lambda:hmac.new(mac_key,chunk,hashlib.sha256).digest()),
        'sha256_one_pass':speed(lambda:hashlib.sha256(chunk).digest()),
        'python_ctypes_input_copy':speed(lambda:bytes(bytearray(chunk))),
    }
    with tempfile.TemporaryDirectory(prefix='a3f-profile-') as td:
        source=Path(td)/'plain'
        with open(source,'wb') as f:
            for _ in range(mib):f.write(chunk)
            f.flush();os.fsync(f.fileno())
        aes_master=secrets.token_bytes(32);tf_master=secrets.token_bytes(32)
        file_results={}
        for w in dict.fromkeys((1,workers)):
            ct=Path(td)/f'encrypted_{w}.a3f4'
            dest=Path(td)/f'restored_{w}'
            t=time.perf_counter()
            encrypt_file(source,ct,mode='hybrid',aes_key=aes_master,tf_key=tf_master,chunk_kib=1024,workers=w)
            enc_s=time.perf_counter()-t
            t=time.perf_counter()
            decrypt_file(ct,dest,aes_key=aes_master,tf_key=tf_master,workers=w)
            dec_s=time.perf_counter()-t
            if dest.stat().st_size!=source.stat().st_size or hashlib.sha256(dest.read_bytes()).digest()!=hashlib.sha256(source.read_bytes()).digest():
                raise RuntimeError('File round-trip mismatch')
            file_results[str(w)]={'encrypt_wall_seconds':round(enc_s,4),'decrypt_wall_seconds':round(dec_s,4),
                                  'encrypt_MiB_s':round(mib/enc_s,2),'decrypt_MiB_s':round(mib/dec_s,2)}
        # The checksum read uses page cache; report without claiming physical-disk I/O.
        t=time.perf_counter()
        with open(source,'rb') as f:
            while f.read(MiB):pass
        cache_read_s=time.perf_counter()-t
    return {'environment':platform.platform(),'python':platform.python_version(),
            'file_size_MiB':mib,'default_chunk_MiB':1,'workers_tested':list(map(int,file_results)),
            'isolated_stage_MiB_s':items,'file_pipeline':file_results,
            'cached_file_read_MiB_s':round(mib/cache_read_s,2),
            'caveats':['Stages cannot be summed to infer exact elapsed-time shares',
                       'Cached file reading is not a storage benchmark',
                       'Synthetic input and available CPU may not match production hardware',
                       'Thread-based parallelism must be remeasured on Windows/MSVC']}

if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--mib',type=int,default=16)
    p.add_argument('--workers',type=int,default=4)
    args=p.parse_args()
    print(json.dumps(run(args.mib,args.workers),indent=2))
