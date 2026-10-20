/* A3F Shield v4: independent native Threefish-1024 encryption and CTR layer.
 * Author: pretorians115588/Andrw
 * No key-indexed lookup, no secret-dependent conditional or memory access.
 * Security claim limited to source structure; not a side-channel certification.
 * Based on Skein 1.3 Threefish-1024 specification; not an audited library.
 * Build Linux: cc -O3 -std=c11 -fPIC -shared -o libthreefish_native.so threefish1024.c
 * Build Windows/MSVC: cl /O2 /LD threefish1024.c /Fe:threefish_native.dll
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <limits.h>

#if defined(_WIN32)
#define A3F_API __declspec(dllexport)
#else
#define A3F_API __attribute__((visibility("default")))
#endif
#define A3F_MASK64 UINT64_MAX
static const uint8_t perm[16]={0,9,2,13,6,11,4,15,10,7,12,3,14,5,8,1};
static const uint8_t rotation[8][8]={
{24,13,8,47,8,17,22,37},
{38,19,10,55,49,18,23,52},
{33,4,51,13,34,41,59,17},
{5,20,48,41,47,28,16,25},
{41,9,37,31,12,47,44,30},
{16,34,56,51,4,53,42,41},
{31,44,47,46,19,42,44,25},
{9,48,35,52,23,31,37,20}
};
static uint64_t load64le(const uint8_t *p){
  uint64_t a=0; for(unsigned i=0;i<8;++i) a|=((uint64_t)p[i])<<(8*i); return a;
}
static void store64le(uint8_t *p,uint64_t a){
  for(unsigned i=0;i<8;++i) p[i]=(uint8_t)(a>>(8*i));
}
static uint64_t rotl64(uint64_t a,unsigned n){ return (a<<n)|(a>>(64-n)); }
static void secure_wipe(void *v, size_t n){
  volatile unsigned char *p=(volatile unsigned char*)v;
  while(n--) *p++=0;
}
typedef struct {uint64_t sk[21][16];} tf_ctx;
static void init(tf_ctx *ctx,const uint8_t *key,const uint8_t *tweak){
  uint64_t kw[17],tw[3];
  tw[0]=load64le(tweak);tw[1]=load64le(tweak+8);tw[2]=tw[0]^tw[1];
  uint64_t parity=UINT64_C(0x1BD11BDAA9FC1A22);
  for(unsigned i=0;i<16;i++){kw[i]=load64le(key+8*i);parity^=kw[i];}
  kw[16]=parity;
  for(unsigned s=0;s<21;s++){
    for(unsigned i=0;i<16;i++) ctx->sk[s][i]=kw[(s+i)%17];
    ctx->sk[s][13]+=tw[s%3];
    ctx->sk[s][14]+=tw[(s+1)%3];
    ctx->sk[s][15]+=s;
  }
  secure_wipe(kw,sizeof kw);secure_wipe(tw,sizeof tw);
}
static void encrypt_one(const tf_ctx *ctx,const uint8_t *src,uint8_t *dst){
  uint64_t v[16],f[16];
  for(unsigned i=0;i<16;i++)v[i]=load64le(src+8*i);
  /* Eight-round, compile-time-constant MIX and permutation schedule.
   * Compile-time rotations avoid variable shift instructions.
   * The outer loop index depends only on public fixed round count. */
  for(unsigned group=0;group<10;group++){
    for(unsigned j=0;j<16;j++)v[j]+=ctx->sk[2*group+0][j];
    f[0]=v[0]+v[1];f[1]=rotl64(v[1],24)^f[0];
    f[2]=v[2]+v[3];f[3]=rotl64(v[3],13)^f[2];
    f[4]=v[4]+v[5];f[5]=rotl64(v[5],8)^f[4];
    f[6]=v[6]+v[7];f[7]=rotl64(v[7],47)^f[6];
    f[8]=v[8]+v[9];f[9]=rotl64(v[9],8)^f[8];
    f[10]=v[10]+v[11];f[11]=rotl64(v[11],17)^f[10];
    f[12]=v[12]+v[13];f[13]=rotl64(v[13],22)^f[12];
    f[14]=v[14]+v[15];f[15]=rotl64(v[15],37)^f[14];
    v[0]=f[0];
    v[1]=f[9];
    v[2]=f[2];
    v[3]=f[13];
    v[4]=f[6];
    v[5]=f[11];
    v[6]=f[4];
    v[7]=f[15];
    v[8]=f[10];
    v[9]=f[7];
    v[10]=f[12];
    v[11]=f[3];
    v[12]=f[14];
    v[13]=f[5];
    v[14]=f[8];
    v[15]=f[1];
    f[0]=v[0]+v[1];f[1]=rotl64(v[1],38)^f[0];
    f[2]=v[2]+v[3];f[3]=rotl64(v[3],19)^f[2];
    f[4]=v[4]+v[5];f[5]=rotl64(v[5],10)^f[4];
    f[6]=v[6]+v[7];f[7]=rotl64(v[7],55)^f[6];
    f[8]=v[8]+v[9];f[9]=rotl64(v[9],49)^f[8];
    f[10]=v[10]+v[11];f[11]=rotl64(v[11],18)^f[10];
    f[12]=v[12]+v[13];f[13]=rotl64(v[13],23)^f[12];
    f[14]=v[14]+v[15];f[15]=rotl64(v[15],52)^f[14];
    v[0]=f[0];
    v[1]=f[9];
    v[2]=f[2];
    v[3]=f[13];
    v[4]=f[6];
    v[5]=f[11];
    v[6]=f[4];
    v[7]=f[15];
    v[8]=f[10];
    v[9]=f[7];
    v[10]=f[12];
    v[11]=f[3];
    v[12]=f[14];
    v[13]=f[5];
    v[14]=f[8];
    v[15]=f[1];
    f[0]=v[0]+v[1];f[1]=rotl64(v[1],33)^f[0];
    f[2]=v[2]+v[3];f[3]=rotl64(v[3],4)^f[2];
    f[4]=v[4]+v[5];f[5]=rotl64(v[5],51)^f[4];
    f[6]=v[6]+v[7];f[7]=rotl64(v[7],13)^f[6];
    f[8]=v[8]+v[9];f[9]=rotl64(v[9],34)^f[8];
    f[10]=v[10]+v[11];f[11]=rotl64(v[11],41)^f[10];
    f[12]=v[12]+v[13];f[13]=rotl64(v[13],59)^f[12];
    f[14]=v[14]+v[15];f[15]=rotl64(v[15],17)^f[14];
    v[0]=f[0];
    v[1]=f[9];
    v[2]=f[2];
    v[3]=f[13];
    v[4]=f[6];
    v[5]=f[11];
    v[6]=f[4];
    v[7]=f[15];
    v[8]=f[10];
    v[9]=f[7];
    v[10]=f[12];
    v[11]=f[3];
    v[12]=f[14];
    v[13]=f[5];
    v[14]=f[8];
    v[15]=f[1];
    f[0]=v[0]+v[1];f[1]=rotl64(v[1],5)^f[0];
    f[2]=v[2]+v[3];f[3]=rotl64(v[3],20)^f[2];
    f[4]=v[4]+v[5];f[5]=rotl64(v[5],48)^f[4];
    f[6]=v[6]+v[7];f[7]=rotl64(v[7],41)^f[6];
    f[8]=v[8]+v[9];f[9]=rotl64(v[9],47)^f[8];
    f[10]=v[10]+v[11];f[11]=rotl64(v[11],28)^f[10];
    f[12]=v[12]+v[13];f[13]=rotl64(v[13],16)^f[12];
    f[14]=v[14]+v[15];f[15]=rotl64(v[15],25)^f[14];
    v[0]=f[0];
    v[1]=f[9];
    v[2]=f[2];
    v[3]=f[13];
    v[4]=f[6];
    v[5]=f[11];
    v[6]=f[4];
    v[7]=f[15];
    v[8]=f[10];
    v[9]=f[7];
    v[10]=f[12];
    v[11]=f[3];
    v[12]=f[14];
    v[13]=f[5];
    v[14]=f[8];
    v[15]=f[1];
    for(unsigned j=0;j<16;j++)v[j]+=ctx->sk[2*group+1][j];
    f[0]=v[0]+v[1];f[1]=rotl64(v[1],41)^f[0];
    f[2]=v[2]+v[3];f[3]=rotl64(v[3],9)^f[2];
    f[4]=v[4]+v[5];f[5]=rotl64(v[5],37)^f[4];
    f[6]=v[6]+v[7];f[7]=rotl64(v[7],31)^f[6];
    f[8]=v[8]+v[9];f[9]=rotl64(v[9],12)^f[8];
    f[10]=v[10]+v[11];f[11]=rotl64(v[11],47)^f[10];
    f[12]=v[12]+v[13];f[13]=rotl64(v[13],44)^f[12];
    f[14]=v[14]+v[15];f[15]=rotl64(v[15],30)^f[14];
    v[0]=f[0];
    v[1]=f[9];
    v[2]=f[2];
    v[3]=f[13];
    v[4]=f[6];
    v[5]=f[11];
    v[6]=f[4];
    v[7]=f[15];
    v[8]=f[10];
    v[9]=f[7];
    v[10]=f[12];
    v[11]=f[3];
    v[12]=f[14];
    v[13]=f[5];
    v[14]=f[8];
    v[15]=f[1];
    f[0]=v[0]+v[1];f[1]=rotl64(v[1],16)^f[0];
    f[2]=v[2]+v[3];f[3]=rotl64(v[3],34)^f[2];
    f[4]=v[4]+v[5];f[5]=rotl64(v[5],56)^f[4];
    f[6]=v[6]+v[7];f[7]=rotl64(v[7],51)^f[6];
    f[8]=v[8]+v[9];f[9]=rotl64(v[9],4)^f[8];
    f[10]=v[10]+v[11];f[11]=rotl64(v[11],53)^f[10];
    f[12]=v[12]+v[13];f[13]=rotl64(v[13],42)^f[12];
    f[14]=v[14]+v[15];f[15]=rotl64(v[15],41)^f[14];
    v[0]=f[0];
    v[1]=f[9];
    v[2]=f[2];
    v[3]=f[13];
    v[4]=f[6];
    v[5]=f[11];
    v[6]=f[4];
    v[7]=f[15];
    v[8]=f[10];
    v[9]=f[7];
    v[10]=f[12];
    v[11]=f[3];
    v[12]=f[14];
    v[13]=f[5];
    v[14]=f[8];
    v[15]=f[1];
    f[0]=v[0]+v[1];f[1]=rotl64(v[1],31)^f[0];
    f[2]=v[2]+v[3];f[3]=rotl64(v[3],44)^f[2];
    f[4]=v[4]+v[5];f[5]=rotl64(v[5],47)^f[4];
    f[6]=v[6]+v[7];f[7]=rotl64(v[7],46)^f[6];
    f[8]=v[8]+v[9];f[9]=rotl64(v[9],19)^f[8];
    f[10]=v[10]+v[11];f[11]=rotl64(v[11],42)^f[10];
    f[12]=v[12]+v[13];f[13]=rotl64(v[13],44)^f[12];
    f[14]=v[14]+v[15];f[15]=rotl64(v[15],25)^f[14];
    v[0]=f[0];
    v[1]=f[9];
    v[2]=f[2];
    v[3]=f[13];
    v[4]=f[6];
    v[5]=f[11];
    v[6]=f[4];
    v[7]=f[15];
    v[8]=f[10];
    v[9]=f[7];
    v[10]=f[12];
    v[11]=f[3];
    v[12]=f[14];
    v[13]=f[5];
    v[14]=f[8];
    v[15]=f[1];
    f[0]=v[0]+v[1];f[1]=rotl64(v[1],9)^f[0];
    f[2]=v[2]+v[3];f[3]=rotl64(v[3],48)^f[2];
    f[4]=v[4]+v[5];f[5]=rotl64(v[5],35)^f[4];
    f[6]=v[6]+v[7];f[7]=rotl64(v[7],52)^f[6];
    f[8]=v[8]+v[9];f[9]=rotl64(v[9],23)^f[8];
    f[10]=v[10]+v[11];f[11]=rotl64(v[11],31)^f[10];
    f[12]=v[12]+v[13];f[13]=rotl64(v[13],37)^f[12];
    f[14]=v[14]+v[15];f[15]=rotl64(v[15],20)^f[14];
    v[0]=f[0];
    v[1]=f[9];
    v[2]=f[2];
    v[3]=f[13];
    v[4]=f[6];
    v[5]=f[11];
    v[6]=f[4];
    v[7]=f[15];
    v[8]=f[10];
    v[9]=f[7];
    v[10]=f[12];
    v[11]=f[3];
    v[12]=f[14];
    v[13]=f[5];
    v[14]=f[8];
    v[15]=f[1];
  }
  for(unsigned j=0;j<16;j++)store64le(dst+8*j,v[j]+ctx->sk[20][j]);
  secure_wipe(v,sizeof v);secure_wipe(f,sizeof f);
}
A3F_API int a3f_tf_encrypt128(const uint8_t *key,const uint8_t *in,uint8_t *out){
  if(!key||!in||!out)return -1;
  tf_ctx ctx;uint8_t zero[16]={0};init(&ctx,key,zero);encrypt_one(&ctx,in,out);secure_wipe(&ctx,sizeof ctx);return 0;
}
static void decrypt_one(const tf_ctx *ctx,const uint8_t *src,uint8_t *dst){
  uint64_t v[16],f[16];
  for(unsigned i=0;i<16;i++)v[i]=load64le(src+8*i)-ctx->sk[20][i];
  for(int d=79;d>=0;d--){
    for(unsigned i=0;i<16;i++)f[perm[i]]=v[i];
    for(unsigned j=0;j<8;j++){
      uint64_t a=f[2*j],b=f[2*j+1];
      uint64_t y=(b^a);
      unsigned n=rotation[d&7][j];
      y=(y>>n)|(y<<(64-n));
      v[2*j]=a-y;v[2*j+1]=y;
    }
    if((d&3)==0){for(unsigned j=0;j<16;j++)v[j]-=ctx->sk[d/4][j];}
  }
  for(unsigned j=0;j<16;j++)store64le(dst+8*j,v[j]);
  secure_wipe(v,sizeof v);secure_wipe(f,sizeof f);
}
A3F_API int a3f_tf_crypt128_tweak(const uint8_t *key,const uint8_t *tweak,
    const uint8_t *in,uint8_t *out,int decrypt){
  if(!key||!tweak||!in||!out)return -1;
  tf_ctx ctx;init(&ctx,key,tweak);
  if(decrypt)decrypt_one(&ctx,in,out);else encrypt_one(&ctx,in,out);
  secure_wipe(&ctx,sizeof ctx);return 0;
}
static const uint8_t domain[16]={'A','3','F','S','H','I','E','L','D','v','4','-','T','F','C','T'};
/* XOR data in-place: no allocations of secret-dependent size, no secret branches.
 * Counter starts at zero each call; caller must never use this CTR with a
 * different authenticated payload and the same SIV+key. */
A3F_API int a3f_tf_ctr_xor(const uint8_t *key,const uint8_t *siv,uint8_t *buffer,size_t n){
  if(!key||!siv||(n && !buffer))return -1;
  if(n>SIZE_MAX-127)return -2;
  size_t blocks=(n+127)/128;
  if(sizeof(size_t)>8 && blocks>UINT64_MAX)return -2;
  tf_ctx ctx;uint8_t zero[16]={0};init(&ctx,key,zero);
  uint8_t input[128]={0},stream[128];
  memcpy(input,domain,16);memcpy(input+16,siv,32);
  for(size_t k=0;k<blocks;k++){
    uint64_t ctr=(uint64_t)k;
    for(unsigned j=0;j<8;j++)input[48+j]=(uint8_t)(ctr>>(56-8*j));
    encrypt_one(&ctx,input,stream);
    size_t pos=k*128, len=(n-pos<128)?(n-pos):128;
    for(size_t j=0;j<len;j++)buffer[pos+j]^=stream[j];
  }
  secure_wipe(stream,sizeof stream);secure_wipe(input,sizeof input);secure_wipe(&ctx,sizeof ctx);
  return 0;
}
