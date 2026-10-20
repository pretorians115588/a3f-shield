"""Non-destructive local Windows validation runner. Never reads user A3F keys.
Run after install_windows.cmd from x64 Native Tools Command Prompt:
  .venv\\Scripts\\python.exe validate_windows_v6.py --full
Produces reports in a user-selected directory; default ./validation_reports.
"""
from __future__ import annotations
import argparse,hashlib,json,os,platform,secrets,shutil,subprocess,sys,tempfile,time
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]

def run(label, argv, *, cwd=None, timeout=900):
    start=time.perf_counter()
    try:
        p=subprocess.run([str(x) for x in argv],cwd=cwd or ROOT,capture_output=True,
                         text=True,errors='replace',timeout=timeout,stdin=subprocess.DEVNULL)
        return dict(name=label,ok=p.returncode==0,returncode=p.returncode,
                    elapsed_s=round(time.perf_counter()-start,3),
                    stdout_tail=p.stdout[-16000:],stderr_tail=p.stderr[-16000:])
    except (subprocess.TimeoutExpired,OSError) as e:
        return dict(name=label,ok=False,elapsed_s=round(time.perf_counter()-start,3),error=str(e))

def cmdrun(label,*argv,expect_success=True, cwd=None,timeout=900):
    r=run(label,argv,cwd=cwd,timeout=timeout)
    if not expect_success:
        error_output=(r.get('stderr_tail','')+'\n'+r.get('stdout_tail','')).lower()
        expected_errors=('authentication failed','manifest','replay','substituted', 'integrity')
        r['ok'] = r.get('returncode') not in (None,0) and any(t in error_output for t in expected_errors)
        r['expectation']='nonzero return code AND explicit authentication/replay error'
    return r

def main():
    arg=argparse.ArgumentParser()
    arg.add_argument('--full',action='store_true',help='add compiler AB, full profiling and timing screen')
    arg.add_argument('--report-dir',default=str(ROOT/'validation_reports'))
    args=arg.parse_args()
    if os.name!='nt':
        print('ERROR: Windows-native validation must be run on Windows with MSVC; no false Linux PASS.',file=sys.stderr)
        return 2
    output=Path(args.report_dir).resolve();output.mkdir(parents=True,exist_ok=True)
    report={'status':'running','started_at':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),
            'os':platform.platform(),'python':sys.version,'arch':platform.machine(),
            'binary_sha256':{},'results':[],'scope':'Windows local tests; not independent audit'}
    for rel in ('native/threefish_native.dll','native/threefish1024.c','src/a3f_v4.py','experimental/witness-v6/witness_v6.py'):
        f=ROOT/rel
        if f.is_file():report['binary_sha256'][rel]=hashlib.sha256(f.read_bytes()).hexdigest()
    add=report['results'].append
    add(run('MSVC compiler lookup',['where.exe','cl']))
    add(run('MSVC compiler version/help',['cl','/?']))
    add(run('Python pytest suite',[sys.executable,'-m','pytest','-q','tests'],timeout=900))
    add(run('in-memory benchmark',[sys.executable,'a3f_v4.py','benchmark','--kib','8192','--repeat','5'],timeout=600))
    # Strictly isolated throwaway keyfiles, database, plaintext and ciphertext.
    with tempfile.TemporaryDirectory(prefix='a3f-v6-win-validation-') as td:
        tmp=Path(td)
        src=tmp/'plain.bin';src.write_bytes(secrets.token_bytes(4103))
        aes=tmp/'aes.dpapi';tf=tmp/'tf.dpapi';wk=tmp/'witness.key';db=tmp/'witness.sqlite'
        out=tmp/'sealed.a3f4';plain=tmp/'restored.bin';tampered=tmp/'tampered.a3f4'
        cmd=[sys.executable,'a3f_v4.py']
        add(run('DPAPI AES key generation',cmd+['keygen',str(aes),'--dpapi']))
        add(run('DPAPI Threefish key generation',cmd+['keygen',str(tf),'--dpapi']))
        add(run('Witness key generation',cmd+['keygen',str(wk),'--raw']))
        opts=['--ledger',str(db),'--ledger-keyfile',str(wk)]
        if all(r['ok'] for r in report['results'][-3:]):
            add(run('hybrid DPAPI encrypt',cmd+['encrypt',str(src),str(out),'--mode','hybrid',
                                                 '--aes-dpapi',str(aes),'--tf-dpapi',str(tf),
                                                 '--workers','4','--chunk-kib','1']+opts))
            if out.is_file():
                add(run('hybrid DPAPI decrypt',cmd+['decrypt',str(out),str(plain),
                                                      '--aes-dpapi',str(aes),'--tf-dpapi',str(tf),
                                                      '--workers','4']+opts))
                add(dict(name='byte-level roundtrip',ok=plain.exists() and src.read_bytes()==plain.read_bytes()))
                data=bytearray(out.read_bytes());data[-1]^=1;tampered.write_bytes(data)
                add(cmdrun('reject tampering with witness',*(cmd+['decrypt',str(tampered),str(tmp/'reject1'),
                          '--aes-dpapi',str(aes),'--tf-dpapi',str(tf)]+opts),expect_success=False))
                add(cmdrun('reject tampering without witness',*(cmd+['decrypt',str(tampered),str(tmp/'reject2'),
                          '--aes-dpapi',str(aes),'--tf-dpapi',str(tf),'--allow-no-replay-protection']),expect_success=False))
                add(dict(name='no plaintext file on authenticated failure',ok=not (tmp/'reject1').exists() and not (tmp/'reject2').exists()))
    if args.full:
        add(run('MSVC compiler A/B benchmark',[sys.executable,str(ROOT/'scripts'/'compare_compilers.py'),
                                                    '--mib','4','--repetitions','10'],timeout=1800))
        add(run('100 MiB file profile',[sys.executable,str(ROOT/'scripts'/'profile_v5.py'),'--mib','100','--workers','4'],timeout=1800))
        add(run('statistical timing screening',[sys.executable,str(ROOT/'scripts'/'timing_probe_v5.py'),'--samples','10000'],timeout=1800))
    report['status']='PASS' if report['results'] and all(x['ok'] for x in report['results']) else 'FAIL_OR_INCOMPLETE'
    report['completed_at']=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())
    # Warning: reports contain environment paths and machine/compiler details, never key bytes.
    path=output/('a3f_validation_'+time.strftime('%Y%m%d_%H%M%S',time.gmtime())+'.json')
    path.write_text(json.dumps(report,indent=2,ensure_ascii=False),encoding='utf-8')
    print('VALIDATION STATUS:',report['status'])
    for r in report['results']:
        print('PASS' if r['ok'] else 'FAIL',r['name'],r.get('elapsed_s',''))
    print('Saved report:',path)
    return 0 if report['status']=='PASS' else 1
if __name__=='__main__':raise SystemExit(main())
