"""Native Threefish-1024 interface, explicit failure if native library is absent.

No silent fallback to the old Python encryptor. AES-GCM-SIV stays in cryptography.
"""
import ctypes
import os
from pathlib import Path

_base=Path(__file__).resolve().parent
_repo=_base.parent
_possible=[_repo/'native'/'threefish_native.dll', _repo/'native'/'libthreefish_native.so', _repo/'native'/'libthreefish_native.dylib']
_libpath=next((x for x in _possible if x.is_file()),None)
if _libpath is None:
    raise RuntimeError('Native Threefish library missing. Run install_windows.cmd or build_native.sh; no insecure fallback.')
_lib=ctypes.CDLL(str(_libpath))
_U8=ctypes.POINTER(ctypes.c_uint8)
_lib.a3f_tf_encrypt128.argtypes=[_U8,_U8,_U8]
_lib.a3f_tf_encrypt128.restype=ctypes.c_int
_lib.a3f_tf_ctr_xor.argtypes=[_U8,_U8,_U8,ctypes.c_size_t]
_lib.a3f_tf_ctr_xor.restype=ctypes.c_int
_lib.a3f_tf_crypt128_tweak.argtypes=[_U8,_U8,_U8,_U8,ctypes.c_int]
_lib.a3f_tf_crypt128_tweak.restype=ctypes.c_int

def _arr(data):
    return (ctypes.c_uint8*len(data)).from_buffer_copy(data)

class Threefish1024:
    def __init__(self,key:bytes,tweak:bytes=b'\x00'*16):
        if len(key)!=128 or len(tweak)!=16:
            raise ValueError('Native Threefish requires 128-byte key and 16-byte tweak')
        self.key=key
        self.tweak=tweak
    def encrypt_block(self,data:bytes)->bytes:
        if len(data)!=128: raise ValueError('Threefish block is 128 bytes')
        dst=(ctypes.c_uint8*128)()
        if _lib.a3f_tf_crypt128_tweak(_arr(self.key),_arr(self.tweak),_arr(data),dst,0)!=0: raise RuntimeError('native failure')
        return bytes(dst)
    def decrypt_block(self,data:bytes)->bytes:
        if len(data)!=128: raise ValueError('Threefish block is 128 bytes')
        dst=(ctypes.c_uint8*128)()
        if _lib.a3f_tf_crypt128_tweak(_arr(self.key),_arr(self.tweak),_arr(data),dst,1)!=0: raise RuntimeError('native failure')
        return bytes(dst)
    def xor_ctr(self,data:bytes,siv:bytes)->bytes:
        if self.tweak!=bytes(16): raise ValueError('CTR profile requires zero tweak')
        if len(siv)!=32: raise ValueError('SIV must have 32 bytes')
        if not data:return b''
        buf=(ctypes.c_uint8*len(data)).from_buffer_copy(data)
        rc=_lib.a3f_tf_ctr_xor(_arr(self.key),_arr(siv),buf,len(data))
        if rc: raise RuntimeError(f'native CTR failure {rc}')
        return bytes(buf)
