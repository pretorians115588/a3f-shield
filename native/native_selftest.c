#include <stdint.h>
#include <stdio.h>
#include <string.h>
int a3f_tf_crypt128_tweak(const uint8_t*,const uint8_t*,const uint8_t*,uint8_t*,int);
int a3f_tf_ctr_xor(const uint8_t*,const uint8_t*,uint8_t*,size_t);
int main(void){
  uint8_t k[128]={0},tw[16]={0},p[128]={0},c[128]={0},q[128]={0},siv[32]={0};
  static const uint8_t expected_prefix[8]={0xf0,0x5c,0x3d,0x0a,0x3d,0x05,0xb3,0x04};
  if(a3f_tf_crypt128_tweak(k,tw,p,c,0)!=0)return 1;
  if(memcmp(c,expected_prefix,8)!=0)return 2;
  if(a3f_tf_crypt128_tweak(k,tw,c,q,1)!=0)return 3;
  if(memcmp(p,q,128)!=0)return 4;
  for(int i=0;i<128;i++)p[i]=(uint8_t)i;
  memcpy(q,p,128);
  if(a3f_tf_ctr_xor(k,siv,q,128)!=0)return 5;
  if(a3f_tf_ctr_xor(k,siv,q,128)!=0)return 6;
  if(memcmp(p,q,128)!=0)return 7;
  puts("native selftest OK");return 0;
}
