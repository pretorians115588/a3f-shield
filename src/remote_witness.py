"""Remote trusted replay witness prototype.

Author: pretorians115588/Andrw

The server must run on an INDEPENDENT TRUSTED host using TLS. The client's
shared key authenticates requests; server state must not be rolled back.
NOT a consensus protocol, HSM, or certified secure timestamp service.
"""
from __future__ import annotations
import argparse,hashlib,hmac,http.server,json,secrets,ssl,sys,time,urllib.request
from pathlib import Path
from rollback_ledger import Ledger,ReplayError

MAX_REQUEST=2048

def _reqmac(key,req):
    message='|'.join(str(req[x]) for x in ('op','doc','generation','digest','time')).encode('ascii')
    return hmac.new(key,b'A3F4/REMOTE/WITNESS\0'+message,hashlib.sha256).hexdigest()

def _payload(key,op,doc,version,digest):
    req={'op':op,'doc':doc.hex(),'generation':version,'digest':digest.hex(),'time':int(time.time())}
    req['mac']=_reqmac(key,req)
    return req

def call_witness(url,key,op,doc,version,digest,cafile=None):
    if len(key)!=32:raise ReplayError('Remote witness shared key must be 32 bytes')
    if not url.startswith('https://') and not url.startswith('http://127.0.0.1:'):
        raise ReplayError('Remote witness transport requires HTTPS; plaintext allowed only for localhost tests')
    data=json.dumps(_payload(key,op,doc,version,digest),sort_keys=True).encode()
    req=urllib.request.Request(url.rstrip('/')+'/v1/witness',data=data,headers={'Content-Type':'application/json'},method='POST')
    ctx=ssl.create_default_context(cafile=cafile) if url.startswith('https://') else None
    try:
        with urllib.request.urlopen(req,timeout=15,context=ctx) as r:
            response=json.load(r)
            if r.status!=200 or response.get('ok') is not True:raise ReplayError('witness rejected request')
    except Exception as e:
        raise ReplayError(f'witness unavailable or rejected: {type(e).__name__}') from e
    return True

def serve(addr,port,dbpath,key,certfile=None,sslkey=None):
    if len(key)!=32:raise ValueError('witness secret must be 32 bytes')
    if not certfile and addr not in ('127.0.0.1','::1','localhost'):
        raise ValueError('Cannot listen on non-loopback address without TLS')
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self,*args):pass # avoid secrets in access logs
        def do_POST(self):
            if self.path!='/v1/witness':self.send_error(404);return
            try:
                n=int(self.headers.get('Content-Length','0'))
                if not 0<n<=MAX_REQUEST:raise ValueError('request too large')
                obj=json.loads(self.rfile.read(n))
                if set(obj)!=set(('op','doc','generation','digest','time','mac')):raise ValueError('bad fields')
                if obj['op'] not in ('verify','register'):raise ValueError('bad op')
                if type(obj['generation']) is not int or type(obj['time']) is not int:raise ValueError('bad integer')
                if abs(time.time()-obj['time'])>60:raise ValueError('stale auth')
                if not hmac.compare_digest(obj['mac'],_reqmac(key,obj)):
                    raise ValueError('failed auth')
                doc=bytes.fromhex(obj['doc']);d=bytes.fromhex(obj['digest'])
                if len(doc)!=16 or len(d)!=32:raise ValueError('bad lengths')
                with Ledger(dbpath,key) as ledger:
                    if obj['op']=='register':ledger.register(doc,obj['generation'],d)
                    else:ledger.verify(doc,obj['generation'],d)
                payload=b'{"ok":true}'
                self.send_response(200)
            except (ReplayError,ValueError,KeyError,TypeError):
                payload=b'{"ok":false}'
                self.send_response(403)
            except Exception:
                payload=b'{"ok":false}'
                self.send_response(503)
            self.send_header('Content-Type','application/json')
            self.send_header('Content-Length',str(len(payload)))
            self.end_headers();self.wfile.write(payload)
    server=http.server.ThreadingHTTPServer((addr,port),Handler)
    if certfile:
        if not sslkey:raise ValueError('missing TLS key')
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version=ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certfile,sslkey)
        server.socket=context.wrap_socket(server.socket,server_side=True)
    server.serve_forever()

def main():
    p=argparse.ArgumentParser(description='A3F v4 independently hosted witness prototype')
    p.add_argument('--db',required=True)
    p.add_argument('--secret-file',required=True)
    p.add_argument('--bind',default='127.0.0.1')
    p.add_argument('--port',type=int,default=8855)
    p.add_argument('--cert');p.add_argument('--cert-key')
    args=p.parse_args()
    serve(args.bind,args.port,args.db,Path(args.secret_file).read_bytes(),args.cert,args.cert_key)
if __name__=='__main__':main()
