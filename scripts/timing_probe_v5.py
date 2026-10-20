"""Simple leakage screening, NOT a constant-time certificate.\n
Compares equal-length fixed/random key material (secret variation) and
fixed/random plaintext with randomized labels. Uses ctypes invocation through
Python and is sensitive to noise, CPU power management, compiler flags.
"""
import argparse
import json
import math
import platform
import random
import secrets
import statistics
import sys
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from threefish_native import Threefish1024


def probe(samples=10000):
    if not (100<=samples<=1000000):
        raise ValueError('samples must be 100..1000000')
    key0=bytes(128)
    key1=secrets.token_bytes(128)
    cipher0=Threefish1024(key0)
    cipher1=Threefish1024(key1)
    block0=bytes(128)
    block1=secrets.token_bytes(128)
    results={}
    for experiment in ('key_variation', 'plaintext_variation'):
        groups=[[],[]]
        labels=[0,1]*samples
        random.SystemRandom().shuffle(labels)
        for label in labels:
            cipher=(cipher0,cipher1)[label] if experiment=='key_variation' else cipher0
            data=block0 if (experiment=='key_variation' or label==0) else block1
            start=time.perf_counter_ns()
            cipher.encrypt_block(data)
            groups[label].append(time.perf_counter_ns()-start)
        a,b=groups
        t=(statistics.mean(a)-statistics.mean(b))/math.sqrt(statistics.variance(a)/len(a)+statistics.variance(b)/len(b))
        results[experiment]={ 'mean_ns':[round(statistics.mean(x),2) for x in groups],
                              'welch_t':round(t,4),'abs_t_above_4_5':abs(t)>4.5}
    return {'samples_per_class':samples,'environment':platform.platform(),
            'experiments':results,'interpretation':'Any result is ONLY a statistical screen, NOT proof of constant time'}

if __name__=='__main__':
    ap=argparse.ArgumentParser()
    ap.add_argument('--samples',type=int,default=10000)
    args=ap.parse_args()
    print(json.dumps(probe(args.samples),indent=2))
