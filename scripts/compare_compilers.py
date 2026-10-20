"""Build temporary native candidates, check against independent Threefish ref,
then compare native CTR on the local CPU. Never overwrites installed DLL/SO.
Run from x64 Native Tools Command Prompt for VS 2022 on Windows.
"""
import ctypes
import json
import os
import platform
from pathlib import Path
import secrets
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
BASE=Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE / 'src'))
from threefish1024_ref import Threefish1024 as Reference

SRC=BASE/'native'/'threefish1024.c'

def measure_candidate(dll, mib, repetitions):
    """Run in a child process so Windows unloads the DLL before cleanup."""
    key=secrets.token_bytes(128)
    siv=secrets.token_bytes(32)
    block=secrets.token_bytes(128)
    tweak=secrets.token_bytes(16)
    expected=Reference(key,tweak).encrypt_block(block)
    tf_reference=Reference(key)
    lib=ctypes.CDLL(str(dll))
    encryption=lib.a3f_tf_crypt128_tweak
    encryption.argtypes=[ctypes.c_void_p]*4+[ctypes.c_int]
    encryption.restype=ctypes.c_int
    k=(ctypes.c_uint8*128).from_buffer_copy(key)
    t=(ctypes.c_uint8*16).from_buffer_copy(tweak)
    b=(ctypes.c_uint8*128).from_buffer_copy(block)
    dst=(ctypes.c_uint8*128)()
    if encryption(k,t,b,dst,0)!=0 or bytes(dst)!=expected:
        raise RuntimeError('Threefish vector check failed')
    back=(ctypes.c_uint8*128)()
    if encryption(k,t,dst,back,1)!=0 or bytes(back)!=block:
        raise RuntimeError('Threefish inverse check failed')
    ctr=lib.a3f_tf_ctr_xor
    ctr.argtypes=[ctypes.c_void_p]*3+[ctypes.c_size_t]
    ctr.restype=ctypes.c_int
    iv=(ctypes.c_uint8*32).from_buffer_copy(siv)
    for n in (1,127,128,129,287):
        buf=(ctypes.c_uint8*n)()
        if ctr(k,iv,buf,n)!=0:
            raise RuntimeError(f'CTR returned failure at size {n}')
        expected_stream=b''.join(tf_reference.encrypt_block(
            b'A3FSHIELDv4-TFCT'+siv+i.to_bytes(8,'big')+bytes(72))
            for i in range((n+127)//128))[:n]
        if bytes(buf)!=expected_stream:
            raise RuntimeError(f'CTR vector mismatch at size {n}')
    n=mib*1024*1024
    buf=(ctypes.c_uint8*n)()
    if ctr(k,iv,buf,n)!=0:
        raise RuntimeError('CTR warmup failed')
    values=[]
    for _ in range(repetitions):
        tic=time.perf_counter()
        if ctr(k,iv,buf,n)!=0:
            raise RuntimeError('CTR benchmark failed')
        values.append(mib/(time.perf_counter()-tic))
    return {'vectors':'passed', 'median_MiB_s':round(statistics.median(values),2),
            'min_MiB_s':round(min(values),2),'max_MiB_s':round(max(values),2)}


def run(mib=2, repetitions=8):
    if not 1<=mib<=32 or not 3<=repetitions<=30:
        raise ValueError('mib=1..32, repetitions=3..30')
    msvc=os.name=='nt' and shutil.which('cl')
    if msvc:
        candidates={'MSVC_O1': ['/O1'], 'MSVC_O2':['/O2'], 'MSVC_O2_GL_LTCG':['/O2','/GL']}
    else:
        compiler=shutil.which('cc') or shutil.which('gcc')
        if not compiler: raise OSError('No C compiler found')
        candidates={'C_O2':['-O2'],'C_O3':['-O3'], 'C_O3_unroll':['-O3','-funroll-loops']}
    report={'platform':platform.platform(),'compiler_family':'MSVC' if msvc else 'GCC/Clang',
            'MiB_per_sample':mib,'repetitions':repetitions,'candidates':{}}
    with tempfile.TemporaryDirectory(prefix='a3f-native-variants-') as td:
        temp=Path(td)
        for name,options in candidates.items():
            dll=temp/(name+('.dll' if msvc else '.so'))
            if msvc:
                cmd=['cl','/nologo',*options,'/LD','/W3',str(SRC),f'/Fe:{dll}']
                if '/GL' in options:cmd+=['/link','/LTCG']
            else:
                cmd=[compiler,'-fPIC','-std=c11','-Wall','-Wextra',*options,'-shared',str(SRC),'-o',str(dll)]
            comp=subprocess.run(cmd,cwd=temp,capture_output=True,text=True)
            if comp.returncode:
                report['candidates'][name]={'compile_error':comp.stderr[-1500:] or comp.stdout[-1500:]}
                continue
            # Only the child loads the DLL; its exit precedes directory cleanup.
            probe=subprocess.run([sys.executable,str(Path(__file__).resolve()),
                                  '--candidate-dll',str(dll),'--mib',str(mib),
                                  '--repetitions',str(repetitions)],cwd=BASE,
                                 capture_output=True,text=True,timeout=300)
            if probe.returncode:
                report['candidates'][name]={'probe_error':probe.stderr[-1500:] or probe.stdout[-1500:]}
                continue
            report['candidates'][name]=json.loads(probe.stdout)
    report['note']='Local screening only; timing leakage and Windows CPU dispatch are not certified'
    return report

if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser()
    p.add_argument('--mib',type=int,default=2)
    p.add_argument('--repetitions',type=int,default=8)
    p.add_argument('--candidate-dll',help=argparse.SUPPRESS)
    args=p.parse_args()
    if not 1<=args.mib<=32 or not 3<=args.repetitions<=30:
        p.error('mib=1..32, repetitions=3..30')
    if args.candidate_dll:
        print(json.dumps(measure_candidate(Path(args.candidate_dll).resolve(),args.mib,args.repetitions)))
    else:
        report=run(args.mib,args.repetitions)
        print(json.dumps(report,indent=2))
        raise SystemExit(0 if report['candidates'] and all(
            x.get('vectors')=='passed' for x in report['candidates'].values()) else 1)
