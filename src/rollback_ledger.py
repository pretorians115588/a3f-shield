"""Authenticated *external-state* latest-version ledger.

Security: rejects ciphertext-file rollback provided ledger database AND secret
cannot be rolled back/modified by the adversary. A DB on the same user-owned
machine is NOT independent trusted state. Deploy witness on separately managed
host / protected device for adversaries with filesystem or machine control.
"""
from __future__ import annotations
import hashlib, hmac, os, sqlite3
from pathlib import Path

class ReplayError(ValueError):pass

def digest_file(path):
    h=hashlib.sha256()
    with open(path,'rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
    return h.digest()

def _tag(key,doc,version,digest):
    return hmac.new(key,b'A3F-v4-ledger\0'+doc+version.to_bytes(8,'big')+digest,hashlib.sha256).digest()

class Ledger:
    def __init__(self,path,key):
        if len(key)!=32:raise ReplayError('ledger HMAC key must be 32 bytes')
        self.path=str(path);self.key=key
        parent=Path(path).parent
        if not parent.is_dir():raise ReplayError('ledger parent folder absent')
        # SQLite transactions prevent concurrent version updates from racing.
        self.db=sqlite3.connect(self.path,timeout=15,isolation_level=None)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('CREATE TABLE IF NOT EXISTS latest '
                        '(doc BLOB PRIMARY KEY, version INTEGER NOT NULL, digest BLOB NOT NULL, tag BLOB NOT NULL)')
    def close(self):self.db.close()
    def __enter__(self):return self
    def __exit__(self,*args):self.close()
    def register(self,doc,version,digest):
        if len(doc)!=16 or len(digest)!=32 or not (1<=version<2**63):raise ReplayError('invalid witness input')
        self.db.execute('BEGIN IMMEDIATE')
        try:
            row=self.db.execute('SELECT version,digest,tag FROM latest WHERE doc=?',(doc,)).fetchone()
            if row:
                old,d,t=row
                if not hmac.compare_digest(t,_tag(self.key,doc,old,d)):
                    raise ReplayError('witness ledger authenticated record corrupted')
                if version!=old+1:raise ReplayError(f'expected generation {old+1}, received {version}')
            elif version!=1:raise ReplayError('new document must start with generation 1')
            self.db.execute('INSERT OR REPLACE INTO latest VALUES (?,?,?,?)',
                            (doc,version,digest,_tag(self.key,doc,version,digest)))
            self.db.execute('COMMIT')
        except BaseException:
            self.db.execute('ROLLBACK');raise
    def verify(self,doc,version,digest):
        row=self.db.execute('SELECT version,digest,tag FROM latest WHERE doc=?',(doc,)).fetchone()
        if not row:raise ReplayError('document unknown to witness')
        old,d,t=row
        if not hmac.compare_digest(t,_tag(self.key,doc,old,d)):
            raise ReplayError('witness record authentication failed')
        if version!=old or not hmac.compare_digest(digest,d):
            raise ReplayError(f'replay or substituted file: latest generation is {old}')
        return True
