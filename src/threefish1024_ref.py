"""Pedagogical Threefish-1024 v1.3 block cipher, NOT constant-time or audited.
Skein 1.3 section 3.3: https://www.schneier.com/wp-content/uploads/2015/01/skein.pdf
"""
import struct

MASK = (1 << 64) - 1
C240 = 0x1BD11BDAA9FC1A22
PERM = (0, 9, 2, 13, 6, 11, 4, 15, 10, 7, 12, 3, 14, 5, 8, 1)
ROT = (
    (24,13,8,47,8,17,22,37),
    (38,19,10,55,49,18,23,52),
    (33,4,51,13,34,41,59,17),
    (5,20,48,41,47,28,16,25),
    (41,9,37,31,12,47,44,30),
    (16,34,56,51,4,53,42,41),
    (31,44,47,46,19,42,44,25),
    (9,48,35,52,23,31,37,20),
)

def rol(x, n):
    return ((x << n) | (x >> (64-n))) & MASK

class Threefish1024:
    """Block encryptor. 128-byte key and 16-byte tweak."""
    def __init__(self, key: bytes, tweak: bytes=b'\0'*16):
        if len(key)!=128 or len(tweak)!=16:
            raise ValueError('Threefish-1024 needs 128-byte key and 16-byte tweak')
        kw = list(struct.unpack('<16Q', key))
        parity = C240
        for k in kw: parity ^= k
        kw.append(parity)
        t0,t1=struct.unpack('<2Q',tweak)
        tw=(t0,t1,t0 ^ t1)
        self.subkeys=[]
        for s in range(21):
            sub=[kw[(s+i)%17] for i in range(16)]
            sub[13]=(sub[13]+tw[s%3]) & MASK
            sub[14]=(sub[14]+tw[(s+1)%3]) & MASK
            sub[15]=(sub[15]+s) & MASK
            self.subkeys.append(sub)

    def encrypt_block(self, data: bytes)->bytes:
        if len(data)!=128: raise ValueError('Block must be 128 bytes')
        v=list(struct.unpack('<16Q',data))
        for d in range(80):
            if d%4==0:
                sub=self.subkeys[d//4]
                v=[(a+b)&MASK for a,b in zip(v,sub)]
            f=[0]*16
            for j in range(8):
                x,y=v[2*j],v[2*j+1]
                a=(x+y)&MASK
                f[2*j]=a
                f[2*j+1]=rol(y,ROT[d%8][j]) ^ a
            v=[f[PERM[i]] for i in range(16)]
        v=[(a+b)&MASK for a,b in zip(v,self.subkeys[20])]
        return struct.pack('<16Q',*v)

    def decrypt_block(self, data: bytes)->bytes:
        if len(data)!=128: raise ValueError('Block must be 128 bytes')
        v=list(struct.unpack('<16Q',data))
        v=[(a-b)&MASK for a,b in zip(v,self.subkeys[20])]
        for d in range(79,-1,-1):
            f=[0]*16
            for i in range(16): f[PERM[i]]=v[i]
            for j in range(8):
                a,b=f[2*j],f[2*j+1]
                y=rol(b^a,64-ROT[d%8][j])
                x=(a-y)&MASK
                v[2*j],v[2*j+1]=x,y
            if d%4==0:
                v=[(a-b)&MASK for a,b in zip(v,self.subkeys[d//4])]
        return struct.pack('<16Q',*v)

