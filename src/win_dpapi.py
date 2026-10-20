"""Windows user-scoped DPAPI key wrapping, not a defense against malware running as user."""
import ctypes, os
from ctypes import wintypes
from pathlib import Path

if os.name=='nt':
    class DATA_BLOB(ctypes.Structure):
        _fields_=[('cbData',wintypes.DWORD),('pbData',ctypes.POINTER(ctypes.c_byte))]
    _crypt=ctypes.WinDLL('crypt32',use_last_error=True)
    _kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    _crypt.CryptProtectData.argtypes=[ctypes.POINTER(DATA_BLOB),wintypes.LPCWSTR,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,wintypes.DWORD,ctypes.POINTER(DATA_BLOB)]
    _crypt.CryptProtectData.restype=wintypes.BOOL
    _crypt.CryptUnprotectData.argtypes=[ctypes.POINTER(DATA_BLOB),ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,wintypes.DWORD,ctypes.POINTER(DATA_BLOB)]
    _crypt.CryptUnprotectData.restype=wintypes.BOOL
    _kernel.LocalFree.argtypes=[ctypes.c_void_p]
    _kernel.LocalFree.restype=ctypes.c_void_p

def _dpapi(data,protect):
    if os.name!='nt':raise OSError('Windows DPAPI only works on Windows')
    inmem=ctypes.create_string_buffer(data,len(data))
    input_blob=DATA_BLOB(len(data),ctypes.cast(inmem,ctypes.POINTER(ctypes.c_byte)))
    output_blob=DATA_BLOB()
    if protect:
        ok=_crypt.CryptProtectData(ctypes.byref(input_blob),'A3F v4 user key',None,None,None,1,ctypes.byref(output_blob))
    else:
        ok=_crypt.CryptUnprotectData(ctypes.byref(input_blob),None,None,None,None,1,ctypes.byref(output_blob))
    if not ok:raise ctypes.WinError(ctypes.get_last_error())
    try:return ctypes.string_at(output_blob.pbData,output_blob.cbData)
    finally:_kernel.LocalFree(ctypes.cast(output_blob.pbData,ctypes.c_void_p))

def generate_dpapi_key(path):
    from secrets import token_bytes
    key=token_bytes(32)
    wrapped=b'A3F4DPAPI\0'+_dpapi(key,True)
    fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    try:
        from file_hardening import restrict_owner
        restrict_owner(path)
        with os.fdopen(fd,'wb') as f:f.write(wrapped);f.flush();os.fsync(f.fileno())
    except BaseException:
        Path(path).unlink(missing_ok=True);raise

def read_dpapi_key(path):
    wrapped=Path(path).read_bytes()
    if not wrapped.startswith(b'A3F4DPAPI\0'):raise ValueError('not an A3F DPAPI key')
    k=_dpapi(wrapped[len(b'A3F4DPAPI\0'):],False)
    if len(k)!=32:raise ValueError('unwrapped key invalid length')
    return k
