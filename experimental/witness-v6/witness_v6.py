"""A3F experimental external monotonic witness v6 (standalone; not wired to v4 CLI).

Author: pretorians115588/Andrw

Security assumptions: independently trusted, non-rollbackable server and signing key;
Any future network transport requires TLS, a pinned Ed25519 verification key,
and independently authenticated writer requests; no HTTP server is supplied by
this module. A DB+secret restored from one snapshot CANNOT distinguish a
complete historical rollback without an independent non-rollbackable checkpoint.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

DOMAIN = b'A3F/WITNESS/V6/CHAIN\0'
AUTH = b'A3F/WITNESS/V6/RECORD\0'
RECEIPT = b'A3F/WITNESS/V6/RECEIPT\0'
GENESIS = hashlib.sha256(b'A3F/WITNESS/V6/GENESIS').digest()
MAX_SEQ = 2**63 - 1

class WitnessError(ValueError):
    pass

def canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')

def _inputs(doc: bytes, generation: int, digest: bytes):
    if (type(doc) is not bytes or len(doc) != 16 or type(digest) is not bytes
            or len(digest) != 32 or type(generation) is not int or not 1 <= generation < MAX_SEQ):
        raise WitnessError('invalid doc, digest or generation')

def _entry_hash(previous: bytes, seq: int, doc: bytes, generation: int, digest: bytes) -> bytes:
    return hashlib.sha256(DOMAIN + previous + seq.to_bytes(8, 'big') + doc
                          + generation.to_bytes(8, 'big') + digest).digest()

def _record_mac(key: bytes, seq: int, doc: bytes, generation: int, digest: bytes, chain: bytes) -> bytes:
    return hmac.digest(key, AUTH + seq.to_bytes(8, 'big') + doc
                       + generation.to_bytes(8, 'big') + digest + chain, 'sha256')

class WitnessStore:
    def __init__(self, db_path, record_key: bytes, signing_seed: bytes):
        if len(record_key) != 32 or len(signing_seed) != 32:
            raise WitnessError('32-byte independent record and Ed25519 signing keys required')
        self.record_key = record_key
        self.signer = Ed25519PrivateKey.from_private_bytes(signing_seed)
        self.db = sqlite3.connect(str(db_path), timeout=20, isolation_level=None)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('PRAGMA busy_timeout=20000')
        self.db.execute('CREATE TABLE IF NOT EXISTS log ('
                        'seq INTEGER PRIMARY KEY, doc BLOB NOT NULL, gen INTEGER NOT NULL, '
                        'digest BLOB NOT NULL, chain BLOB NOT NULL, tag BLOB NOT NULL, '
                        'UNIQUE(doc,gen))')
        self.db.execute('CREATE TABLE IF NOT EXISTS heads ('
                        'doc BLOB PRIMARY KEY, seq INTEGER NOT NULL, gen INTEGER NOT NULL, '
                        'digest BLOB NOT NULL, FOREIGN KEY(seq) REFERENCES log(seq))')
    def __enter__(self): return self
    def __exit__(self, *args): self.db.close()
    def public_key(self) -> bytes:
        return self.signer.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    def _latest_global(self):
        row = self.db.execute('SELECT seq,chain FROM log ORDER BY seq DESC LIMIT 1').fetchone()
        return row if row else (0, GENESIS)
    def _check_record(self, row):
        seq, doc, gen, digest, chain, tag = row
        if not hmac.compare_digest(tag, _record_mac(self.record_key, seq, doc, gen, digest, chain)):
            raise WitnessError('witness log record authentication failed')
    def _current(self, doc):
        """Return the latest authenticated log record for *doc*.

        ``heads`` is only a cache/index.  It is checked against the log but is
        never trusted to decide which generation is current; otherwise an
        attacker could roll back one unsigned head row while leaving the
        authenticated global log and checkpoint untouched.
        """
        row = self.db.execute(
            'SELECT seq,doc,gen,digest,chain,tag FROM log '
            'WHERE doc=? ORDER BY gen DESC, seq DESC LIMIT 1', (doc,)).fetchone()
        if row is None:
            return None
        self._check_record(row)
        seq, row_doc, gen, digest, _chain, _tag = row
        head = self.db.execute('SELECT seq,gen,digest FROM heads WHERE doc=?', (doc,)).fetchone()
        if head != (seq, gen, digest):
            raise WitnessError('witness head/history disagreement')
        return seq, gen, digest

    def _audit_locked(self):
        """Audit the complete chain while the caller owns a transaction."""
        last = GENESIS
        sequence = 0
        latest = {}
        for row in self.db.execute('SELECT seq,doc,gen,digest,chain,tag FROM log ORDER BY seq'):
            seq, doc, gen, digest, chain, tag = row
            if seq != sequence + 1:
                raise WitnessError('gap in global witness sequence')
            self._check_record(row)
            if not hmac.compare_digest(chain, _entry_hash(last, seq, doc, gen, digest)):
                raise WitnessError('invalid witness chain')
            previous = latest[doc][1] if doc in latest else 0
            if gen != previous + 1:
                raise WitnessError('generation gap or duplicate')
            latest[doc] = (seq, gen, digest)
            last, sequence = chain, seq
        heads = list(self.db.execute('SELECT doc,seq,gen,digest FROM heads'))
        if len(heads) != len(latest):
            raise WitnessError('witness head count mismatch')
        for doc, seq, gen, digest in heads:
            if latest.get(doc) != (seq, gen, digest):
                raise WitnessError('witness head/history disagreement')
        return {'events': sequence, 'documents': len(heads), 'head_hash': last.hex()}
    def register(self, doc: bytes, generation: int, digest: bytes) -> int:
        """Strict generation+1 CAS. Idempotent same-generation/same-digest retry."""
        _inputs(doc, generation, digest)
        self.db.execute('BEGIN IMMEDIATE')
        try:
            self._audit_locked()
            current = self._current(doc)
            if current is not None and current[1] == generation and hmac.compare_digest(current[2], digest):
                self.db.execute('COMMIT')
                return current[0]
            expected = 1 if current is None else current[1] + 1
            if generation != expected:
                raise WitnessError(f'expected generation {expected}, got {generation}')
            last_seq, last_chain = self._latest_global()
            if last_seq >= MAX_SEQ-1: raise WitnessError('witness sequence exhausted')
            # Check and extend authenticated chain (does not prevent full DB rollback).
            if last_seq:
                last = self.db.execute('SELECT seq,doc,gen,digest,chain,tag FROM log WHERE seq=?',(last_seq,)).fetchone()
                if last is None: raise WitnessError('witness global chain missing')
                self._check_record(last)
            seq = last_seq + 1
            chain = _entry_hash(last_chain, seq, doc, generation, digest)
            tag = _record_mac(self.record_key, seq, doc, generation, digest, chain)
            self.db.execute('INSERT INTO log VALUES (?,?,?,?,?,?)',
                            (seq, doc, generation, digest, chain, tag))
            self.db.execute('INSERT OR REPLACE INTO heads VALUES (?,?,?,?)',
                            (doc, seq, generation, digest))
            self.db.execute('COMMIT')
            return seq
        except BaseException:
            self.db.execute('ROLLBACK')
            raise
    def verify(self, doc: bytes, generation: int, digest: bytes, *,
               challenge: bytes, min_checkpoint: int = 0) -> dict:
        """Produce challenge-bound Ed25519 receipt, no untrusted plaintext."""
        _inputs(doc, generation, digest)
        if type(challenge) is not bytes or len(challenge) != 32:
            raise WitnessError('32-byte fresh challenge required')
        if type(min_checkpoint) is not int or not 0 <= min_checkpoint < MAX_SEQ:
            raise WitnessError('invalid independently trusted checkpoint floor')
        self.db.execute('BEGIN')
        try:
            self._audit_locked()
            current = self._current(doc)
            if current is None: raise WitnessError('unknown document')
            seq, gen, d = current
            if gen != generation or not hmac.compare_digest(d, digest):
                raise WitnessError(f'stale or substituted generation (latest {gen})')
            global_seq, root = self._latest_global()
            if global_seq < min_checkpoint:
                raise WitnessError('witness state rolled back below independently trusted floor')
            if global_seq:
                last = self.db.execute('SELECT seq,doc,gen,digest,chain,tag FROM log WHERE seq=?',(global_seq,)).fetchone()
                self._check_record(last)
            record = {'protocol':'A3F-WITNESS-V6','doc':doc.hex(),'generation':gen,'digest':d.hex(),
                      'document_seq':seq,'global_seq':global_seq,'head_hash':root.hex(),
                      'challenge':challenge.hex()}
            signature = self.signer.sign(RECEIPT + canonical(record))
            self.db.execute('COMMIT')
            return {'record':record,'signature':signature.hex()}
        except BaseException:
            self.db.execute('ROLLBACK')
            raise
    def audit(self) -> dict:
        """Full chain + per-document head verification; no rollback protection by itself."""
        self.db.execute('BEGIN')
        try:
            result = self._audit_locked()
            self.db.execute('COMMIT')
            return result
        except BaseException:
            self.db.execute('ROLLBACK')
            raise

def verify_receipt(receipt: dict, pinned_public_key: bytes, *, doc: bytes,
                   generation: int, digest: bytes, challenge: bytes, min_checkpoint: int = 0) -> int:
    """Verify remote receipt including challenge, expected file and checkpoint floor."""
    _inputs(doc, generation, digest)
    if len(pinned_public_key)!=32 or len(challenge)!=32:
        raise WitnessError('invalid verifier input')
    try:
        record = receipt['record']
        signature = bytes.fromhex(receipt['signature'])
        Ed25519PublicKey.from_public_bytes(pinned_public_key).verify(signature, RECEIPT+canonical(record))
        if (record['protocol'] != 'A3F-WITNESS-V6'
                or record['doc'] != doc.hex() or record['generation'] != generation
                or record['digest'] != digest.hex() or record['challenge'] != challenge.hex()
                or type(record['global_seq']) is not int or record['global_seq'] < min_checkpoint
                or type(record['document_seq']) is not int
                or not 1 <= record['document_seq'] <= record['global_seq'] < MAX_SEQ
                or len(bytes.fromhex(record['head_hash'])) != 32):
            raise WitnessError('receipt binding/checkpoint mismatch')
    except (ValueError, TypeError, KeyError, OverflowError) as e:
        raise WitnessError('malformed or mismatched witness receipt') from e
    except Exception as e:
        raise WitnessError('witness signature verification failed') from e
    return record['global_seq']
