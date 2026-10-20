"""A3F Shield v4: native Threefish with independent authenticated replay witness. RESEARCH ONLY.

Author: pretorians115588/Andrw
Independent passwords (AES and Threefish); chunked authenticated encryption;
file-wide authenticated manifest. Uses cryptography AESGCMSIV, native C Threefish.
Python 3.11+. No compatibility with previous A3F encrypted formats.
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import struct
import sys
import tempfile
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from time import perf_counter

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag
from threefish_native import Threefish1024
from file_hardening import restrict_owner

MAGIC = b'A3FSH004'
VERSION = 4
MODES = {'aes': 1, 'threefish': 2, 'hybrid': 3}
AES_RAW = 1
TF_RAW = 2
NAMES = {x: k for k, x in MODES.items()}
# magic, version, mode, chunk_bytes, Argon2 memKiB, passes, lanes,
# plaintext bytes, chunk count, unique file id, separate salts, AES nonce seed
HEADER = struct.Struct('>8sBBBIIIIQQ16s16s16s12s16sQ')
FRAME = struct.Struct('>QI') # index, exact encoded payload length
TRAILER_PREFIX = struct.Struct('>8sQQ32s')
TRAILER_MAGIC = b'A3FEND04'
TRAILER_LEN = TRAILER_PREFIX.size + 32
MAC_LEN = 32
SIV_LEN = 32
GCM_TAG_LEN = 16
CHUNK_MIN = 1024
CHUNK_MAX = 1024 * 1024
MAX_FILE_SIZE = (1 << 63) - 1
# Fixed 16 byte domain, then 32-byte SIV, 8-byte block counter, 72 zero bytes.
TF_CTR_DOMAIN = b'A3FSHIELDv4-TFCT'  # 16
assert len(TF_CTR_DOMAIN) == 16

class FormatError(ValueError):
    """Authentication, version, truncation or structural error (no plaintext released)."""


def _mac(key: bytes, *parts: bytes) -> bytes:
    hm = hmac.new(key, digestmod=hashlib.sha256)
    for part in parts:
        hm.update(part)
    return hm.digest()


def _hkdf(master: bytes, file_id: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    return HKDF(algorithm=hashes.SHA512(), length=length,
                salt=b'A3F4/HKDF/'+file_id+salt, info=b'A3F4/'+info).derive(master)


def _derive_password(password: str, salt: bytes, file_id: bytes, memory: int, passes: int, lanes: int) -> bytes:
    if not isinstance(password, str) or not password:
        raise ValueError('Nonempty password required for each layer')
    master = hash_secret_raw(password.encode('utf-8'), salt, passes, memory, lanes, 32, Type.ID)
    return _hkdf(master, file_id, salt, b'MASTER', 32)


def _keys(mode: int, aes_password: str | None, tf_password: str | None,
          file_id: bytes, aes_salt: bytes, tf_salt: bytes,
          memory: int, passes: int, lanes: int, *,
          aes_key: bytes | None = None, tf_key: bytes | None = None) -> dict:
    if mode not in NAMES:
        raise FormatError('Unknown cryptographic mode')
    if mode == 3 and aes_password is not None and tf_password is not None:
        if hmac.compare_digest(aes_password.encode(), tf_password.encode()):
            raise ValueError('Hybrid mode requires two different passphrases')
    if aes_key is not None and tf_key is not None and len(aes_key) == 32 and len(tf_key) == 32:
        if hmac.compare_digest(aes_key, tf_key):
            raise ValueError('Hybrid mode requires distinct raw master keys')
    if aes_key is not None and (not isinstance(aes_key, bytes) or len(aes_key) != 32):
        raise ValueError('AES raw key must be exactly 32 bytes')
    if tf_key is not None and (not isinstance(tf_key, bytes) or len(tf_key) != 32):
        raise ValueError('Threefish raw master key must be exactly 32 bytes')
    aes_secret = (_hkdf(aes_key, file_id, aes_salt, b'RAW-MASTER', 32) if aes_key is not None else
                  _derive_password(aes_password, aes_salt, file_id, memory, passes, lanes)) if mode in (1, 3) else None
    tf_secret = (_hkdf(tf_key, file_id, tf_salt, b'RAW-MASTER', 32) if tf_key is not None else
                 _derive_password(tf_password, tf_salt, file_id, memory, passes, lanes)) if mode in (2, 3) else None
    derived = {}
    if aes_secret is not None:
        derived['aes'] = _hkdf(aes_secret, file_id, aes_salt, b'AES256-GCMSIV', 32)
        derived['aes_manifest'] = _hkdf(aes_secret, file_id, aes_salt, b'AES-MANIFEST', 32)
    if tf_secret is not None:
        derived['threefish'] = _hkdf(tf_secret, file_id, tf_salt, b'THREEFISH-1024', 128)
        derived['siv'] = _hkdf(tf_secret, file_id, tf_salt, b'TF-SIV-HMAC', 32)
        derived['tf_mac'] = _hkdf(tf_secret, file_id, tf_salt, b'TF-ETM-HMAC', 32)
        derived['tf_manifest'] = _hkdf(tf_secret, file_id, tf_salt, b'TF-MANIFEST', 32)
    if mode == 1:
        derived['manifest'] = derived['aes_manifest']
    elif mode == 2:
        derived['manifest'] = derived['tf_manifest']
    else:
        derived['manifest'] = _hkdf(derived['aes_manifest'] + derived['tf_manifest'],
                                    file_id, aes_salt + tf_salt, b'COMBINED-MANIFEST', 32)
    return derived


def _parse_header(raw: bytes) -> dict:
    if len(raw) != HEADER.size:
        raise FormatError('Truncated header')
    magic, version, mode, flags, chunk_size, mem, passes, lanes, size, count, file_id, asalt, tsalt, nonce, doc_id, generation = HEADER.unpack(raw)
    if magic != MAGIC or version != VERSION or mode not in NAMES:
        raise FormatError('Not an A3F v4 file')
    if len(doc_id)!=16 or not (1<=generation<2**63):
        raise FormatError('Invalid document generation')
    if flags & ~3 or (mode == 1 and flags & TF_RAW) or (mode == 2 and flags & AES_RAW):
        raise FormatError('Unknown or inconsistent credential flags')
    if not (CHUNK_MIN <= chunk_size <= CHUNK_MAX and chunk_size % 1024 == 0):
        raise FormatError('Invalid chunk size')
    if not (8192 <= mem <= 262144 and 1 <= passes <= 8 and 1 <= lanes <= 4):
        raise FormatError('Unsafe or unsupported KDF parameters')
    if not (0 <= size <= MAX_FILE_SIZE):
        raise FormatError('Invalid plaintext size')
    expected_count = (size + chunk_size - 1) // chunk_size
    if count != expected_count:
        raise FormatError('Inconsistent chunk count')
    return dict(mode=mode, flags=flags, chunk_size=chunk_size, mem=mem, passes=passes, lanes=lanes,
                size=size, count=count, file_id=file_id, asalt=asalt, tsalt=tsalt, nonce=nonce, doc_id=doc_id, generation=generation)


def _nonce12(seed: bytes, idx: int) -> bytes:
    if len(seed) != 12 or not (0 <= idx < (1<<64)):
        raise FormatError('Invalid nonce or chunk index')
    return seed[:4] + idx.to_bytes(8, 'big')


def _aad(header: bytes, idx: int, clearlen: int) -> bytes:
    return b'A3F4/CHUNK/AAD\0' + header + struct.pack('>QI', idx, clearlen)


def _payload_size(mode: int, length: int) -> int:
    return length + (GCM_TAG_LEN if mode in (1, 3) else 0) + (SIV_LEN + MAC_LEN if mode in (2, 3) else 0)


def _xor_threefish_ctr(cipher: Threefish1024, data: bytes, siv: bytes) -> bytes:
    # Key schedule and all 80 rounds execute inside fixed-operation native C.
    return cipher.xor_ctr(data, siv)


class Engine:
    """Stateless per-chunk API: tolerates repeated chunk nonce, leaks equality for repeats.
    AES-GCM-SIV and keyed synthetic IV are intentionally deterministic on exact replay.
    """
    def __init__(self, header: bytes, keys: dict):
        self.params = _parse_header(header)
        self.header = header
        self.keys = keys
        self.mode = self.params['mode']
        self.aes = AESGCMSIV(keys['aes']) if self.mode in (1, 3) else None
        self.tf = Threefish1024(keys['threefish']) if self.mode in (2, 3) else None

    def _check_chunk(self, index: int, plain_length: int):
        p = self.params
        if not (0 <= index < p['count']):
            raise FormatError('Chunk index outside file')
        expected = min(p['chunk_size'], p['size']-index*p['chunk_size'])
        if plain_length != expected:
            raise FormatError('Wrong plaintext length for chunk')

    def encrypt(self, index: int, plain: bytes) -> bytes:
        self._check_chunk(index, len(plain))
        aad = _aad(self.header, index, len(plain))
        inner = self.aes.encrypt(_nonce12(self.params['nonce'], index), plain, aad) if self.aes else plain
        if not self.tf:
            return inner
        siv = _mac(self.keys['siv'], b'A3F4/SYNTHETIC-IV\0', len(aad).to_bytes(4, 'big'), aad,
                   len(inner).to_bytes(8, 'big'), inner)
        body = _xor_threefish_ctr(self.tf, inner, siv)
        tag = _mac(self.keys['tf_mac'], b'A3F4/ETM\0', len(aad).to_bytes(4, 'big'), aad,
                   siv, len(body).to_bytes(8, 'big'), body)
        return siv + body + tag

    def decrypt(self, index: int, encoded: bytes, plain_length: int) -> bytes:
        self._check_chunk(index, plain_length)
        if len(encoded) != _payload_size(self.mode, plain_length):
            raise FormatError('Invalid ciphertext length')
        aad = _aad(self.header, index, plain_length)
        inner = encoded
        if self.tf:
            siv, body, tag = encoded[:32], encoded[32:-32], encoded[-32:]
            expected = _mac(self.keys['tf_mac'], b'A3F4/ETM\0', len(aad).to_bytes(4, 'big'), aad,
                            siv, len(body).to_bytes(8, 'big'), body)
            if not hmac.compare_digest(tag, expected):
                raise FormatError('Authentication failed')
            inner = _xor_threefish_ctr(self.tf, body, siv)
            check = _mac(self.keys['siv'], b'A3F4/SYNTHETIC-IV\0', len(aad).to_bytes(4, 'big'), aad,
                         len(inner).to_bytes(8, 'big'), inner)
            if not hmac.compare_digest(siv, check):
                raise FormatError('Authentication failed')
        if self.aes:
            try:
                plain = self.aes.decrypt(_nonce12(self.params['nonce'], index), inner, aad)
            except (InvalidTag, ValueError) as exc:
                raise FormatError('Authentication failed') from exc
        else:
            plain = inner
        if len(plain) != plain_length:
            raise FormatError('Authentication failed')
        return plain


def _manifest_start(header: bytes):
    d = hashlib.sha256()
    d.update(b'A3F4/FULL-FILE-MANIFEST\0')
    d.update(header)
    return d


def _trailer_prefix(nchunks: int, original_bytes: int, manifest_hash: bytes) -> bytes:
    return TRAILER_PREFIX.pack(TRAILER_MAGIC, nchunks, original_bytes, manifest_hash)


def _manifest_mac(key: bytes, header: bytes, prefix: bytes) -> bytes:
    return _mac(key, b'A3F4/FULL-FILE-MANIFEST-MAC\0', header, prefix)


def _read_exact(stream, count: int) -> bytes:
    result = stream.read(count)
    if len(result) != count:
        raise FormatError('Truncated file')
    return result


def _verify_manifest(stream, header: bytes, params: dict, manifest_key: bytes):
    """First full pass authenticates every chunk and layout before creating output."""
    digest = _manifest_start(header)
    size = params['size']
    chunk = params['chunk_size']
    mode = params['mode']
    for i in range(params['count']):
        plain_len = min(chunk, size-i*chunk)
        meta = _read_exact(stream, FRAME.size)
        index, length = FRAME.unpack(meta)
        if index != i or length != _payload_size(mode, plain_len):
            raise FormatError('Invalid chunk frame')
        data = _read_exact(stream, length)
        digest.update(meta)
        digest.update(data)
    prefix = _read_exact(stream, TRAILER_PREFIX.size)
    magic, count, actual_size, root = TRAILER_PREFIX.unpack(prefix)
    if magic != TRAILER_MAGIC or count != params['count'] or actual_size != size:
        raise FormatError('Missing or malformed file manifest')
    digest.update(TRAILER_MAGIC + struct.pack('>QQ', count, actual_size))
    if not hmac.compare_digest(root, digest.digest()):
        raise FormatError('File manifest contents mismatch')
    tag = _read_exact(stream, 32)
    if not hmac.compare_digest(tag, _manifest_mac(manifest_key, header, prefix)):
        raise FormatError('File manifest authentication failed')
    if stream.read(1):
        raise FormatError('Trailing bytes after file manifest')


def _temp_output(destination: Path):
    if destination.exists():
        raise FileExistsError(f'Destination already exists: {destination}')
    if not destination.parent.is_dir():
        raise FileNotFoundError(f'Destination directory does not exist: {destination.parent}')
    f = tempfile.NamedTemporaryFile(dir=destination.parent, prefix='.a3f4-partial-',
                                    suffix='.tmp', delete=False)
    try:
        restrict_owner(f.name)
    except BaseException:
        f.close();Path(f.name).unlink(missing_ok=True);raise
    return f, Path(f.name)


def _publish(tmp: Path, dest: Path):
    # hardlink avoids accidental overwrite, on same filesystem; windows NTFS supported
    os.link(tmp, dest)
    tmp.unlink()


def _credentials(mode: int, aes_password: str | None, tf_password: str | None,
                 aes_key: bytes | None = None, tf_key: bytes | None = None):
    if mode in (1, 3) and bool(aes_password) == bool(aes_key):
        raise ValueError('Provide exactly one AES credential: password OR 32-byte key')
    if mode in (2, 3) and bool(tf_password) == bool(tf_key):
        raise ValueError('Provide exactly one Threefish credential: password OR 32-byte key')
    if aes_key is not None and len(aes_key) != 32:
        raise ValueError('AES raw key requires 32 bytes')
    if tf_key is not None and len(tf_key) != 32:
        raise ValueError('Threefish raw master key requires 32 bytes')


def _ordered_transform(jobs, function, workers: int):
    """Bounded ordered pipeline: at most 2*workers in-flight tasks.

    Threads, not processes: no serialized keys sent to subprocesses. Caller
    must provide independent per-chunk nonce / AAD, immutable shared engine,
    and publish output only after the file-wide integrity checks complete.
    """
    if not (1 <= workers <= 8):
        raise ValueError('workers must be between 1 and 8')
    if workers == 1:
        for item in jobs:
            yield function(*item)
        return
    pending = deque()
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix='a3f-crypto') as executor:
        try:
            for item in jobs:
                pending.append(executor.submit(function, *item))
                if len(pending) >= 2 * workers:
                    yield pending.popleft().result()
            while pending:
                yield pending.popleft().result()
        finally:
            for future in pending:
                future.cancel()


def encrypt_file(source, destination, *, mode='hybrid', aes_password=None,
                 tf_password=None, aes_key=None, tf_key=None, chunk_kib=64, argon_mem_kib=65536,
                 argon_time=2, argon_lanes=1, document_id=None, generation=1, workers=1):
    if mode not in MODES:
        raise ValueError('Unknown encryption mode')
    if not (1 <= workers <= 8):
        raise ValueError('workers must be 1..8')
    m = MODES[mode]
    _credentials(m, aes_password, tf_password, aes_key, tf_key)
    flags = (AES_RAW if aes_key is not None else 0) | (TF_RAW if tf_key is not None else 0)
    src, dst = Path(source), Path(destination)
    if not src.is_file():
        raise FileNotFoundError(src)
    if not (1 <= chunk_kib <= 1024 and 8192 <= argon_mem_kib <= 262144
            and 1 <= argon_time <= 8 and 1 <= argon_lanes <= 4):
        raise ValueError('Unsupported KDF or chunk parameters')
    nbytes = src.stat().st_size
    if nbytes > MAX_FILE_SIZE:
        raise ValueError('Input too large')
    chunk_size = chunk_kib*1024
    count = (nbytes + chunk_size-1)//chunk_size
    if dst.exists():
        raise FileExistsError(dst)
    file_id, asalt, tsalt, nonce = (secrets.token_bytes(16), secrets.token_bytes(16),
                                   secrets.token_bytes(16), secrets.token_bytes(12))
    if document_id is None:
        document_id = secrets.token_bytes(16)
    if not isinstance(document_id, bytes) or len(document_id)!=16 or not (1<=generation<2**63):
        raise ValueError('document_id must be 16 bytes and generation must be positive <2^63')
    header = HEADER.pack(MAGIC, VERSION, m, flags, chunk_size, argon_mem_kib, argon_time,
                         argon_lanes, nbytes, count, file_id, asalt, tsalt, nonce, document_id, generation)
    keys = _keys(m, aes_password, tf_password, file_id, asalt, tsalt,
                 argon_mem_kib, argon_time, argon_lanes, aes_key=aes_key, tf_key=tf_key)
    engine = Engine(header, keys)
    fo, tmp = _temp_output(dst)
    try:
        with open(src, 'rb') as fi, fo:
            fo.write(header)
            digest = _manifest_start(header)
            def jobs():
                for i in range(count):
                    want = min(chunk_size, nbytes-i*chunk_size)
                    data = fi.read(want)
                    if len(data) != want:
                        raise OSError('Source shortened during encryption')
                    yield i, data
                if fi.read(1):
                    raise OSError('Source grew during encryption')
            for i, payload in enumerate(_ordered_transform(jobs(), engine.encrypt, workers)):
                meta = FRAME.pack(i, len(payload))
                fo.write(meta)
                fo.write(payload)
                digest.update(meta)
                digest.update(payload)
            digest.update(TRAILER_MAGIC + struct.pack('>QQ', count, nbytes))
            prefix = _trailer_prefix(count, nbytes, digest.digest())
            fo.write(prefix)
            fo.write(_manifest_mac(keys['manifest'], header, prefix))
            fo.flush()
            os.fsync(fo.fileno())
        _publish(tmp, dst)
        return {'mode':mode,'plaintext_bytes':nbytes,'chunks':count,'ciphertext_bytes':dst.stat().st_size,
                'document_id':document_id.hex(),'generation':generation}
    finally:
        fo.close()
        tmp.unlink(missing_ok=True)


def decrypt_file(source, destination, *, aes_password=None, tf_password=None,
                 aes_key=None, tf_key=None, prepublish_check=None, workers=1):
    if not (1 <= workers <= 8):
        raise ValueError('workers must be 1..8')
    src, dst = Path(source), Path(destination)
    if not src.is_file():
        raise FileNotFoundError(src)
    if dst.exists():
        raise FileExistsError(dst)
    with open(src, 'rb') as fi:
        header = _read_exact(fi, HEADER.size)
        params = _parse_header(header)
        expected_disk_bytes = (HEADER.size + params['size'] + params['count'] *
                               (FRAME.size + _payload_size(params['mode'], 0)) + TRAILER_LEN)
        if os.fstat(fi.fileno()).st_size != expected_disk_bytes:
            raise FormatError('Invalid total encrypted file length')
        _credentials(params['mode'], aes_password, tf_password, aes_key, tf_key)
        expected_flags = (AES_RAW if aes_key is not None else 0) | (TF_RAW if tf_key is not None else 0)
        if params['flags'] != expected_flags:
            raise FormatError('Wrong credential type for encrypted file')
        keys = _keys(params['mode'], aes_password, tf_password,
                     params['file_id'], params['asalt'], params['tsalt'],
                     params['mem'], params['passes'], params['lanes'], aes_key=aes_key, tf_key=tf_key)
        _verify_manifest(fi, header, params, keys['manifest'])
        # No plaintext output file until entire ciphertext+manifest verified.
        fi.seek(HEADER.size)
        engine = Engine(header, keys)
        fo, tmp = _temp_output(dst)
        try:
            with fo:
                second_digest = _manifest_start(header)
                def jobs():
                    for i in range(params['count']):
                        want = min(params['chunk_size'], params['size']-i*params['chunk_size'])
                        meta = _read_exact(fi, FRAME.size)
                        ix, n = FRAME.unpack(meta)
                        if ix != i or n != _payload_size(params['mode'],want):
                            raise FormatError('Inconsistent frame during second pass')
                        payload = _read_exact(fi, n)
                        second_digest.update(meta)
                        second_digest.update(payload)
                        yield i, payload, want
                for plain in _ordered_transform(jobs(), engine.decrypt, workers):
                    fo.write(plain)
                suffix = _read_exact(fi, TRAILER_LEN)
                magic, num, original_bytes, verified_root = TRAILER_PREFIX.unpack(suffix[:TRAILER_PREFIX.size])
                second_digest.update(TRAILER_MAGIC + struct.pack('>QQ', num, original_bytes))
                if (magic != TRAILER_MAGIC or num != params['count'] or original_bytes != params['size']
                    or not hmac.compare_digest(second_digest.digest(), verified_root)
                    or not hmac.compare_digest(suffix[TRAILER_PREFIX.size:],
                        _manifest_mac(keys['manifest'], header, suffix[:TRAILER_PREFIX.size]))
                    or fi.read(1)):
                    raise FormatError('File changed during decryption')
                fo.flush()
                os.fsync(fo.fileno())
            if prepublish_check is not None:
                # Narrow time-of-check window; NOT a serializable witness lease.
                prepublish_check()
            _publish(tmp, dst)
            return {'plaintext_bytes':params['size'],'chunks':params['count'],
                    'document_id':params['doc_id'].hex(),'generation':params['generation']}
        finally:
            fo.close()
            tmp.unlink(missing_ok=True)


def benchmark(kib=32, repeat=3):
    """Bounded-volume benchmark; on-disk v4 chunk limit remains 1 MiB.

    A larger --kib value is processed as *multiple* independent indexed v4
    chunks; file format, nonce policy and per-frame sizes remain unchanged.
    Same data may be reused during benchmarking only, never as file content
    under repeated nonce/key in real encryption.
    """
    if not (1 <= kib <= 65536 and 1 <= repeat <= 100 and kib * repeat <= 1048576):
        raise ValueError('Unsupported benchmark parameters (kib<=65536, repeat<=100, product<=1048576)')
    total = kib*1024
    chunk_size = min(total, CHUNK_MAX)
    count = (total + chunk_size - 1)//chunk_size
    data = secrets.token_bytes(chunk_size)
    results = []
    for name, m in MODES.items():
        header = HEADER.pack(MAGIC,VERSION,m,0,chunk_size,8192,1,1,
                             total,count,secrets.token_bytes(16),secrets.token_bytes(16),
                             secrets.token_bytes(16),secrets.token_bytes(12),secrets.token_bytes(16),1)
        p = _parse_header(header)
        keys = _keys(m, 'benchmark-aes-only', 'benchmark-tf-only',p['file_id'],
                     p['asalt'],p['tsalt'],p['mem'],p['passes'],p['lanes'])
        eng = Engine(header, keys)
        # Warmup, excluded from timing.
        eng.decrypt(0, eng.encrypt(0, data), len(data))
        enc, dec = [], []
        for _ in range(repeat):
            ciphertext = []
            start = perf_counter()
            for i in range(count):
                plain = data if i < count-1 else data[:total - i*chunk_size]
                ciphertext.append(eng.encrypt(i, plain))
            enc.append(perf_counter()-start)
            start = perf_counter()
            for i, payload in enumerate(ciphertext):
                want = min(chunk_size, total-i*chunk_size)
                if eng.decrypt(i, payload, want) != (data if i < count-1 else data[:want]):
                    raise RuntimeError('Benchmark decrypt mismatch')
            dec.append(perf_counter()-start)
        results.append({'mode':name,'KiB':kib,'repeats':repeat,'chunks_per_iteration':count,
                        'encrypt_MiB_per_s':round(kib/1024/(sum(enc)/repeat),4),
                        'decrypt_MiB_per_s':round(kib/1024/(sum(dec)/repeat),4)})
    return results


def _keyfile_read(filename: str) -> bytes:
    key = Path(filename).read_bytes()
    if len(key) != 32:
        raise ValueError('Raw master keyfile must be 32 bytes')
    return key


def _keygen(filename: str):
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, 'O_BINARY'):
        flags |= os.O_BINARY
    handle = os.open(filename, flags, 0o600)
    try:
        with os.fdopen(handle, 'wb') as f:
            restrict_owner(filename)
            f.write(secrets.token_bytes(32))
            f.flush()
            os.fsync(f.fileno())
    except BaseException:
        Path(filename).unlink(missing_ok=True)
        raise


def main(argv=None):
    p=argparse.ArgumentParser(description='A3F Shield v4 EXPERIMENTAL ONLY. Do not use with sensitive data.')
    subs=p.add_subparsers(dest='action',required=True)
    enc=subs.add_parser('encrypt');enc.add_argument('input');enc.add_argument('output')
    enc.add_argument('--mode', choices=MODES, default='hybrid')
    enc.add_argument('--document-id',help='16-byte hex id to version the same logical document')
    enc.add_argument('--generation',type=int,default=1)
    enc.add_argument('--supersede',help='existing A3F4 file: reuse logical document ID, increment generation')
    enc.add_argument('--aes-keyfile')
    enc.add_argument('--aes-dpapi')
    enc.add_argument('--tf-keyfile')
    enc.add_argument('--tf-dpapi')
    enc.add_argument('--chunk-kib',type=int,default=64)
    enc.add_argument('--workers',type=int,choices=range(1,9),default=1,help='Bounded ordered worker threads (1-8)')
    enc.add_argument('--argon-mem-kib',type=int,default=65536)
    enc.add_argument('--argon-time',type=int,default=2)
    dec=subs.add_parser('decrypt');dec.add_argument('input');dec.add_argument('output')
    dec.add_argument('--aes-keyfile')
    dec.add_argument('--aes-dpapi')
    dec.add_argument('--tf-keyfile')
    dec.add_argument('--tf-dpapi')
    dec.add_argument('--workers',type=int,choices=range(1,9),default=1,help='Bounded ordered worker threads (1-8)')
    keysub=subs.add_parser('keygen');keysub.add_argument('output');keysub.add_argument('--dpapi',action='store_true');keysub.add_argument('--raw',action='store_true',help='unsafe portable raw key file; protect externally')
    ben=subs.add_parser('benchmark');ben.add_argument('--kib',type=int,default=32)
    ben.add_argument('--repeat',type=int,default=3)
    for cmd in (enc,dec):
        cmd.add_argument('--ledger', help='demo: local trusted witness SQLite state')
        cmd.add_argument('--witness-url',help='HTTPS external version witness, recommended')
        cmd.add_argument('--witness-secret-keyfile',help='32 byte HMAC secret shared with witness server')
        cmd.add_argument('--witness-ca', help='custom trusted CA PEM for witness TLS')
        cmd.add_argument('--ledger-keyfile', help='32-byte ledger HMAC secret (keep separately)')
        cmd.add_argument('--allow-no-replay-protection',action='store_true',
                         help='EXPERIMENTAL: skip independent anti-rollback witness')
        cmd.add_argument('--allow-password-experimental',action='store_true',
                         help='Allow user-chosen passwords; offline guessing remains possible')
    args=p.parse_args(argv)
    try:
        if args.action=='benchmark':
            print(json.dumps(benchmark(args.kib,args.repeat),indent=2)); return 0
        if args.action=='keygen':
            if args.dpapi and args.raw:raise ValueError("Choose DPAPI or raw")
            if args.dpapi or (os.name=="nt" and not args.raw):
                from win_dpapi import generate_dpapi_key
                generate_dpapi_key(args.output)
            else:
                _keygen(args.output)
            print('Generated 256-bit master key, store separate backup securely:',args.output)
            return 0
        if args.action=='encrypt':
            mode=MODES[args.mode]
        else:
            with open(args.input,'rb') as f:
                mode=_parse_header(_read_exact(f, HEADER.size))['mode']
        ap=tp=None
        if bool(args.witness_url)!=bool(args.witness_secret_keyfile):
            raise ValueError('Provide --witness-url and --witness-secret-keyfile together')
        if args.ledger and args.witness_url:
            raise ValueError('Choose one witness backend')
        if bool(args.ledger)!=bool(args.ledger_keyfile):
            raise ValueError('Provide --ledger and --ledger-keyfile together')
        if not args.ledger and not args.witness_url and not args.allow_no_replay_protection:
            raise ValueError('Anti-rollback ledger required, or explicit --allow-no-replay-protection')
        if args.aes_keyfile and args.aes_dpapi or args.tf_keyfile and args.tf_dpapi:
            raise ValueError('Choose raw OR DPAPI key file for each layer')
        if args.aes_dpapi or args.tf_dpapi:
            from win_dpapi import read_dpapi_key
        ak=(_keyfile_read(args.aes_keyfile) if args.aes_keyfile else
            read_dpapi_key(args.aes_dpapi) if args.aes_dpapi else None)
        tk=(_keyfile_read(args.tf_keyfile) if args.tf_keyfile else
            read_dpapi_key(args.tf_dpapi) if args.tf_dpapi else None)
        if args.action=='decrypt':
            with open(args.input,'rb') as f:
                flags=_parse_header(_read_exact(f, HEADER.size))['flags']
            if flags != ((AES_RAW if ak is not None else 0)|(TF_RAW if tk is not None else 0)):
                raise ValueError('Required credential types are specified in the file header')
        if (mode in (1,3) and ak is None or mode in (2,3) and tk is None) and not args.allow_password_experimental:
            raise ValueError('Password credentials disabled by default. Use generated keyfiles or explicitly opt into experimental passwords')
        if mode in (1,3) and ak is None:
            ap=getpass.getpass('AES layer passphrase: ')
            if args.action=='encrypt' and ap!=getpass.getpass('Confirm AES passphrase: '):
                raise ValueError('AES passphrases differ')
        if mode in (2,3) and tk is None:
            tp=getpass.getpass('Threefish layer passphrase: ')
            if args.action=='encrypt' and tp!=getpass.getpass('Confirm Threefish passphrase: '):
                raise ValueError('Threefish passphrases differ')
        if args.action=='encrypt':
            docid=(bytes.fromhex(args.document_id) if args.document_id else None)
            generation=args.generation
            if args.supersede:
                if args.document_id or args.generation!=1:
                    raise ValueError('Do not combine --supersede with manual document ID or generation')
                with open(args.supersede,'rb') as previous:
                    old=_parse_header(_read_exact(previous,HEADER.size))
                docid=old['doc_id']
                generation=old['generation']+1
            result=encrypt_file(args.input,args.output,mode=args.mode,
                                aes_password=ap,tf_password=tp,aes_key=ak,tf_key=tk,chunk_kib=args.chunk_kib,workers=args.workers,
                                argon_mem_kib=args.argon_mem_kib,argon_time=args.argon_time,
                                document_id=docid,generation=generation)
        else:
            if args.ledger:
                from rollback_ledger import Ledger,digest_file
                with open(args.input,'rb') as cfile:
                    h=_parse_header(_read_exact(cfile,HEADER.size))
                with Ledger(args.ledger,_keyfile_read(args.ledger_keyfile)) as witness:
                    witness.verify(h['doc_id'],h['generation'],digest_file(args.input))
            if args.witness_url:
                from remote_witness import call_witness
                from rollback_ledger import digest_file
                with open(args.input,'rb') as cfile:
                    wh=_parse_header(_read_exact(cfile,HEADER.size))
                call_witness(args.witness_url,_keyfile_read(args.witness_secret_keyfile),
                             'verify',wh['doc_id'],wh['generation'],digest_file(args.input),args.witness_ca)
            def latest_version_check():
                # Recheck after full decrypt but BEFORE plain file publication.
                # Not a mathematical guarantee if the witness changes concurrently.
                if args.ledger:
                    from rollback_ledger import Ledger,digest_file
                    with Ledger(args.ledger,_keyfile_read(args.ledger_keyfile)) as witness:
                        witness.verify(h['doc_id'],h['generation'],digest_file(args.input))
                if args.witness_url:
                    from remote_witness import call_witness
                    from rollback_ledger import digest_file
                    call_witness(args.witness_url,_keyfile_read(args.witness_secret_keyfile),
                                 'verify',wh['doc_id'],wh['generation'],digest_file(args.input),args.witness_ca)
            result=decrypt_file(args.input,args.output,aes_password=ap,tf_password=tp,
                                aes_key=ak,tf_key=tk,
                                prepublish_check=latest_version_check if (args.ledger or args.witness_url) else None,workers=args.workers)
        if args.ledger:
            from rollback_ledger import Ledger,digest_file
            # Authenticated external latest-version state. Must be on a
            # separately trusted system for attacker-controlled host rollback.
            with open(args.input if args.action=='decrypt' else args.output,'rb') as cf:
                p4=_parse_header(_read_exact(cf,HEADER.size))
            path=args.input if args.action=='decrypt' else args.output
            with Ledger(args.ledger,_keyfile_read(args.ledger_keyfile)) as ledger:
                if args.action=='encrypt':
                    ledger.register(p4['doc_id'],p4['generation'],digest_file(path))
        if args.action=='encrypt' and args.witness_url:
            from remote_witness import call_witness
            from rollback_ledger import digest_file
            with open(args.output,'rb') as cfile:
                wh=_parse_header(_read_exact(cfile,HEADER.size))
            call_witness(args.witness_url,_keyfile_read(args.witness_secret_keyfile),
                         'register',wh['doc_id'],wh['generation'],digest_file(args.output),args.witness_ca)
        print(json.dumps(result,indent=2));return 0
    except (ValueError,OSError) as exc:
        print(f'ERROR: {exc}',file=sys.stderr);return 1

if __name__=='__main__':
    raise SystemExit(main())
