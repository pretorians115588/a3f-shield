"""Tests include authoritative vectors, file integrity, nonce misuse, malformed formats.
Passing these tests does not constitute a formal proof or an audit certificate.
"""
import hashlib
import hmac
import os
import struct
import pytest
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
from threefish_native import Threefish1024
from a3f_v4 import (Engine, HEADER, FRAME, TRAILER_LEN, FormatError, MODES,
                    _keys, _parse_header, _xor_threefish_ctr,
                    encrypt_file, decrypt_file, MAGIC, VERSION)

AES_PASS = 'test-aes-strong-ish'
TF_PASS = 'test-tf-different'
ARGON = dict(chunk_kib=1, argon_mem_kib=8192, argon_time=1)


def passwords(mode):
    return {'aes_password': AES_PASS if mode != 'threefish' else None,
            'tf_password': TF_PASS if mode != 'aes' else None}


def header_for(mode, size=1024, chunk_size=1024):
    return HEADER.pack(MAGIC, VERSION, MODES[mode], 0, chunk_size, 8192, 1, 1,
                       size, (size + chunk_size - 1)//chunk_size,
                       bytes(range(16)), bytes(range(16,32)), bytes(range(32,48)), bytes(range(12)),bytes(range(48,64)),1)


def engine_for(mode, size=1024):
    header = header_for(mode,size)
    x = _parse_header(header)
    keys = _keys(x['mode'], passwords(mode)['aes_password'],passwords(mode)['tf_password'],
                 x['file_id'],x['asalt'],x['tsalt'],x['mem'],x['passes'],x['lanes'])
    return Engine(header,keys)


def test_rfc8452_aes256gcmsiv_empty():
    key=bytes.fromhex('01'+'00'*31)
    nonce=bytes.fromhex('03'+'00'*11)
    assert AESGCMSIV(key).encrypt(nonce,b'',b'').hex() == '07f5f4169bbf55a8400cd47ea6fd400f'


def test_rfc8452_aes256gcmsiv_8_bytes():
    key=bytes.fromhex('01'+'00'*31)
    nonce=bytes.fromhex('03'+'00'*11)
    pt=bytes.fromhex('0100000000000000')
    want='c2ef328e5c71c83b843122130f7364b761e0b97427e3df28'
    assert AESGCMSIV(key).encrypt(nonce,pt,b'').hex() == want


def test_threefish1024_zero_vector():
    words=[0x04B3053D0A3D5CF0,0x0136E0D1C7DD85F7,0x067B212F6EA78A5C,
           0x0DA9C10B4C54E1C6,0x0F4EC27394CBACF0,0x32437F0568EA4FD5,
           0xCFF56D1D7654B49C,0xA2D5FB14369B2E7B,0x540306B460472E0B,
           0x71C18254BCEA820D,0xC36B4068BEAF32C8,0xFA4329597A360095,
           0xC4A36C28434A5B9A,0xD54331444B1046CF,0xDF11834830B2A460,
           0x1E39E8DFE1F7EE4F]
    tf=Threefish1024(bytes(128))
    want=struct.pack('<16Q', *words)
    assert tf.encrypt_block(bytes(128)) == want
    assert tf.decrypt_block(want) == bytes(128)


def test_threefish_nonzero_known_answer():
    key=struct.pack('<16Q',*[0x1716151413121110+i*0x0808080808080808 for i in range(16)])
    pt=struct.pack('<16Q',*[0xF8F9FAFBFCFDFEFF-i*0x0808080808080808 for i in range(16)])
    tw=struct.pack('<2Q',0x0706050403020100,0x0f0e0d0c0b0a0908)
    expected=struct.pack('<16Q',*[
        0x483AC62C27B09B59,0x4CB85AA9E48221AA,0x80BC1644069F7D0B,
        0xFCB26748FF92B235,0xE83D70243B5D294B,0x316A3CA3587A0E02,
        0x5461FD7C8EF6C1B9,0x7DD5C1A4C98CA574,0xFDA694875AA31A35,
        0x03D1319C26C2624C,0xA2066D0DF2BF7827,0x6831CCDAA5C8A370,
        0x2B8FCD9189698DAC,0xE47818BBFD604399,0xDF47E519CBCEA541,
        0x5EFD5FF4A5D4C259])
    tf=Threefish1024(key,tw)
    ct=tf.encrypt_block(pt)
    assert bytes(a^b for a,b in zip(ct,pt)) == expected
    assert tf.decrypt_block(ct) == pt


@pytest.mark.parametrize('mode',MODES)
@pytest.mark.parametrize('length',[0,1,15,16,127,128,129,1023,1024,1025,2345])
def test_file_roundtrip(tmp_path,mode,length):
    p=os.urandom(length)
    (tmp_path/'source').write_bytes(p)
    src=tmp_path/'source';dst=tmp_path/'cipher';end=tmp_path/'plain'
    encrypt_file(src,dst,mode=mode,**passwords(mode),**ARGON)
    assert dst.read_bytes().startswith(MAGIC)
    result=decrypt_file(dst,end,**passwords(mode))
    assert end.read_bytes()==p
    assert result['plaintext_bytes']==length


@pytest.mark.parametrize('mode',MODES)
def test_authentication_failure_wrong_password_and_output_preservation(tmp_path,mode):
    src=tmp_path/'src';dst=tmp_path/'ct';end=tmp_path/'decrypted'
    src.write_bytes(os.urandom(1500))
    encrypt_file(src,dst,mode=mode,**passwords(mode),**ARGON)
    wrong={**passwords(mode)}
    which='aes_password' if mode in ('aes','hybrid') else 'tf_password'
    wrong[which]='INCORRECT'
    with pytest.raises(FormatError):decrypt_file(dst,end,**wrong)
    assert not end.exists()
    end.write_bytes(b'KEEP')
    with pytest.raises(FileExistsError):decrypt_file(dst,end,**passwords(mode))
    assert end.read_bytes()==b'KEEP'


@pytest.mark.parametrize('mode',MODES)
def test_second_layer_password_wrong(tmp_path,mode):
    if mode!='hybrid':return
    src=tmp_path/'src';dst=tmp_path/'ct';end=tmp_path/'out'
    src.write_bytes(b'A'*2048)
    encrypt_file(src,dst,mode=mode,**passwords(mode),**ARGON)
    with pytest.raises(FormatError):
        decrypt_file(dst,end,aes_password=AES_PASS,tf_password='wrong')
    assert not end.exists()


@pytest.mark.parametrize('mode',MODES)
@pytest.mark.parametrize('tamper',['payload','header','frame_length','frame_index','tag','root','truncate','append','swap_frames'])
def test_file_tamper_rejected(tmp_path,mode,tamper):
    src=tmp_path/'src';dst=tmp_path/'ct';end=tmp_path/'out'
    src.write_bytes(os.urandom(2500))
    encrypt_file(src,dst,mode=mode,**passwords(mode),**ARGON)
    bs=bytearray(dst.read_bytes())
    if tamper=='payload':bs[HEADER.size+FRAME.size+10]^=1
    elif tamper=='header':bs[HEADER.size-3]^=1
    elif tamper=='frame_length':bs[HEADER.size+FRAME.size-1]^=1
    elif tamper=='frame_index':bs[HEADER.size]^=1
    elif tamper=='tag':bs[-1]^=1
    elif tamper=='root':bs[-33]^=1
    elif tamper=='truncate':bs=bs[:-1]
    elif tamper=='append':bs+=b'X'
    elif tamper=='swap_frames':
        ix=HEADER.size
        n1=FRAME.unpack(bs[ix:ix+FRAME.size])[1]
        ix2=ix+FRAME.size+n1
        n2=FRAME.unpack(bs[ix2:ix2+FRAME.size])[1]
        a=bs[ix:ix2];b=bs[ix2:ix2+FRAME.size+n2]
        bs[ix:ix2+FRAME.size+n2]=b+a
    dst.write_bytes(bs)
    with pytest.raises((FormatError,ValueError)):
        decrypt_file(dst,end,**passwords(mode))
    assert not end.exists()


@pytest.mark.parametrize('mode',MODES)
def test_repeat_nonce_different_plaintexts_does_not_leak_plaintext_xor(mode):
    engine=engine_for(mode)
    p1=b'A'*1024
    p2=b'B'*1024
    c1=engine.encrypt(0,p1)
    c2=engine.encrypt(0,p2)  # deliberately same key/header/index and therefore nonce
    assert c1!=c2
    assert engine.decrypt(0,c1,1024)==p1
    assert engine.decrypt(0,c2,1024)==p2
    # For the outer ciphertext portions, the stream differs for distinct inner text.
    if mode!='aes':
        assert c1[:32]!=c2[:32]  # synthetic IVs differ
        c1,c2=c1[32:-32],c2[32:-32]
    x=bytes(a^b for a,b in zip(c1,c2))
    px=bytes(a^b for a,b in zip(p1,p2))
    assert x[:1024] != px


@pytest.mark.parametrize('mode',MODES)
def test_repeat_nonce_equal_plaintext_leaks_equality(mode):
    e=engine_for(mode)
    p=b'X'*1024
    assert e.encrypt(0,p)==e.encrypt(0,p)  # unavoidable deterministic equality leakage


def test_same_password_two_independent_layers_forbidden(tmp_path):
    src=tmp_path/'src';src.write_bytes(b'demo')
    with pytest.raises(ValueError,match='different'):
        encrypt_file(src,tmp_path/'enc',mode='hybrid',aes_password='same',tf_password='same',**ARGON)
    assert not (tmp_path/'enc').exists()


@pytest.mark.parametrize('mode',MODES)
def test_salts_are_fresh_between_files(tmp_path,mode):
    src=tmp_path/'src';src.write_bytes(b'Z'*1000)
    encrypt_file(src,tmp_path/'one',mode=mode,**passwords(mode),**ARGON)
    encrypt_file(src,tmp_path/'two',mode=mode,**passwords(mode),**ARGON)
    assert (tmp_path/'one').read_bytes() != (tmp_path/'two').read_bytes()
    a=(tmp_path/'one').read_bytes()[:HEADER.size]
    b=(tmp_path/'two').read_bytes()[:HEADER.size]
    assert _parse_header(a)['file_id'] != _parse_header(b)['file_id']


def test_v1_rejected(tmp_path):
    src=tmp_path/'legacy';src.write_bytes(b'A3FLAB01'+bytes(300))
    with pytest.raises(FormatError):
        decrypt_file(src,tmp_path/'out',aes_password=AES_PASS,tf_password=TF_PASS)


def test_ctr_input_uses_distinct_blocks_and_siv():
    key=bytes(128);tf=Threefish1024(key)
    s1=bytes(32);s2=b'\x01'+bytes(31)
    z1=_xor_threefish_ctr(tf,bytes(384),s1)
    z2=_xor_threefish_ctr(tf,bytes(384),s2)
    assert z1[:128]!=z1[128:256]
    assert z1[128:256]!=z1[256:384]
    assert z1!=z2


def test_engine_rejects_wrong_chunk_structure():
    engine=engine_for('hybrid')
    with pytest.raises(FormatError):engine.encrypt(1,b'Z'*1024)
    with pytest.raises(FormatError):engine.encrypt(0,b'Z')
    with pytest.raises(FormatError):engine.decrypt(0,b'bad',1024)


def test_no_partial_plaintext_from_corrupted_later_chunk(tmp_path):
    src=tmp_path/'src';dst=tmp_path/'enc';out=tmp_path/'out'
    src.write_bytes(os.urandom(3800))
    encrypt_file(src,dst,mode='hybrid',**passwords('hybrid'),**ARGON)
    raw=bytearray(dst.read_bytes())
    raw[-TRAILER_LEN-10]^=1
    dst.write_bytes(raw)
    with pytest.raises(FormatError):decrypt_file(dst,out,**passwords('hybrid'))
    assert not out.exists()
    assert not list(tmp_path.glob('.a3f3-partial-*'))

@pytest.mark.parametrize('mode',MODES)
def test_independent_raw_master_keyfiles_roundtrip(tmp_path, mode):
    src=tmp_path/'src';src.write_bytes(os.urandom(2097))
    aes_key=os.urandom(32) if mode in ('aes','hybrid') else None
    tf_key=os.urandom(32) if mode in ('threefish','hybrid') else None
    creds={'aes_key':aes_key,'tf_key':tf_key}
    dst=tmp_path/'enc';out=tmp_path/'out'
    encrypt_file(src,dst,mode=mode,**creds,**ARGON)
    decrypt_file(dst,out,**creds)
    assert out.read_bytes()==src.read_bytes()
    with pytest.raises(FormatError):
        decrypt_file(dst,tmp_path/'out2',**passwords(mode))


def test_hybrid_identical_raw_keys_rejected(tmp_path):
    src=tmp_path/'src';src.write_bytes(b'ABCD')
    key=os.urandom(32)
    with pytest.raises(ValueError,match='distinct'):
        encrypt_file(src,tmp_path/'ct',mode='hybrid',aes_key=key,tf_key=key,**ARGON)


def test_repeated_ctr_keystream_old_design_did_leak_xor():
    # Intentionally re-implements v2's two CTR-style layers to confirm regression
    # (AES-GCM and Threefish CTR with same keys/nonce on two different messages).
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    k1=os.urandom(32); k2=os.urandom(128); nonce=os.urandom(16)
    aes=AESGCM(k1); tf=Threefish1024(k2)
    p1=b'A'*200;p2=b'B'*200
    def old_scheme(p):
        inner=aes.encrypt(nonce[:4]+bytes(8),p,b'same-aad')
        # v2 tf_ctr, same nonce/chunk index, used twice
        def legacy_ctr(data):
            out=bytearray(len(data))
            for block in range((len(data)+127)//128):
                counter=b'A3FCTR01'+nonce+struct.pack('>QQ',0,block)+bytes(88)
                stream=tf.encrypt_block(counter)
                for j, value in enumerate(data[128*block:128*(block+1)]):
                    out[128*block+j] = value ^ stream[j]
            return bytes(out)
        return legacy_ctr(inner)
    c1=old_scheme(p1);c2=old_scheme(p2)
    assert bytes(a^b for a,b in zip(c1,c2))[:len(p1)] == bytes(a^b for a,b in zip(p1,p2))


def test_keygen_creates_random_key_and_refuses_overwrite(tmp_path):
    from a3f_v4 import _keygen
    p=tmp_path/'keyfile'
    _keygen(str(p))
    first=p.read_bytes()
    assert len(first)==32
    with pytest.raises(FileExistsError):_keygen(str(p))
    assert p.read_bytes()==first


def test_wrong_raw_key_fails_before_output(tmp_path):
    src=tmp_path/'src';src.write_bytes(b'0123'*500)
    aes,tf=os.urandom(32),os.urandom(32)
    encrypted=tmp_path/'ct'
    encrypt_file(src,encrypted,mode='hybrid',aes_key=aes,tf_key=tf,**ARGON)
    with pytest.raises(FormatError):
        decrypt_file(encrypted,tmp_path/'out',aes_key=os.urandom(32),tf_key=tf)
    assert not (tmp_path/'out').exists()


def test_file_changed_between_authenticated_passes_rejected(tmp_path,monkeypatch):
    """Regression for ciphertext source TOCTOU at manifest boundary."""
    import a3f_v4
    src=tmp_path/'src';ct=tmp_path/'encrypted';out=tmp_path/'out'
    src.write_bytes(os.urandom(1600))
    encrypt_file(src,ct,mode='hybrid',**passwords('hybrid'),**ARGON)
    original=a3f_v4._verify_manifest
    def verify_then_modify(stream,header,params,key):
        original(stream,header,params,key)
        data=bytearray(ct.read_bytes())
        data[-1]^=1 # authenticated EOF tag changed after successful pass 1
        ct.write_bytes(data)
    monkeypatch.setattr(a3f_v4,'_verify_manifest',verify_then_modify)
    with pytest.raises(FormatError,match='changed'):
        decrypt_file(ct,out,**passwords('hybrid'))
    assert not out.exists()
    assert not list(tmp_path.glob('.a3f3-partial-*'))
