#include "globals.h"
#include "reader-common.h"

#include <termios.h>
#include <unistd.h>
#ifdef OS_LINUX
#include <linux/serial.h>
#endif

#define MAX_ATR_LEN 33         // max. ATR length
#define MAX_HIST    15         // max. number of historical characters

//////  ====================================================================================

int aes_active=0;
AES_KEY dkey, ekey;

static void cAES_SetKey(const unsigned char *key)
{
  AES_set_decrypt_key(key,128,&dkey);
  AES_set_encrypt_key(key,128,&ekey);
  aes_active=1;
}

static int cAES_Encrypt(const unsigned char *data, int len, unsigned char *crypt)
{
  if(aes_active) {
    len=(len+15)&(~15); // pad up to a multiple of 16
    int i;
    for(i=0; i<len; i+=16) AES_encrypt(data+i,crypt+i,(const AES_KEY *)&ekey);
    return len;
    }
  return -1;
}

//////  ====================================================================================
//////  special thanks to an "italian forum" !!!!

void postprocess_cw(ECM_REQUEST *er, int posECMbody)
{
#if __BYTE_ORDER == __BIG_ENDIAN
  static unsigned char Tb1[0xC]={0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,0xF8,0x61,0xCB,0x52};
  static unsigned char Tb2[0x40]= {
    0xC5,0x39,0xF5,0xB9,0x90,0x99,0x01,0x3A,0xD4,0xB9,0x6A,0xB5,0xEA,0x67,0x7E,0xB4,
    0x6C,0x30,0x4B,0xF0,0xB8,0x10,0xB0,0xB5,0xB7,0x6D,0xA7,0x51,0x1A,0xE7,0x14,0xCA,
    0x4F,0x4F,0x15,0x86,0x26,0x08,0x10,0xB1,0xE7,0xE1,0x48,0xBE,0x7D,0xDD,0x5E,0xCB,
    0xcF,0xBF,0x32,0x3B,0x8B,0x31,0xB1,0x31,0x0F,0x1A,0x66,0x4B,0x01,0x40,0x01,0x00
  };
#else
  static unsigned char Tb1[0xC]={0x23,0x01,0x67,0x45,0xAB,0x89,0xEF,0xCD,0x61,0xF8,0x52,0xCB};
  static unsigned char Tb2[0x40]= {
    0x39,0xC5,0xB9,0xF5,0x99,0x90,0x3A,0x01,0xB9,0xD4,0xB5,0x6A,0x67,0xEA,0xB4,0x7E,
    0x30,0x6C,0xF0,0x4B,0x10,0xB8,0xB5,0xB0,0x6D,0xB7,0x51,0xA7,0xE7,0x1A,0xCA,0x14,
    0x4F,0x4F,0x86,0x15,0x08,0x26,0xB1,0x10,0xE1,0xE7,0xBE,0x48,0xDD,0x7D,0xCB,0x5E,
    0xBF,0xCF,0x3B,0x32,0x31,0x8B,0x31,0xB1,0x1A,0x0F,0x4B,0x66,0x40,0x01,0x00,0x01
  };
#endif
  unsigned char tabletmp2[0x10] = {0x0B,0x04,0x07,0x08,0x05,0x09,0x0B,0x0A,0x07,0x02,0x0A,0x05,0x04,0x08,0x0D,0x0F};
  unsigned char table40[0x40];
  unsigned char Hash48[0x48];
  unsigned char Hash14[0x14];
  unsigned char counter=0,counter2=0;
  int tmp1;
  int a,b,h,j,k,l,m = 0;
  int i;
  int posB0 = -1;
  for (i = 6; i < posECMbody; i++)
  {
    if (er->ecm[i] == 0xB0)
    {
      posB0 = i;
      break;
    }
  }
  if (posB0 == -1) return;

  b= (er->ecm[0]&1) * 8;
  //for (b=0 ; b<=8; b+=8) {
    memset(Hash48,0,0x48);
    Hash48[0] = er->cw[b + 0];
    Hash48[1] = er->cw[b + 1];
    Hash48[2] = er->cw[b + 2];
    Hash48[3] = er->cw[b + 3];
    Hash48[4] = er->cw[b + 4];
    Hash48[5] = er->cw[b + 5];
    Hash48[6] = er->cw[b + 6];
    Hash48[7] = er->cw[b + 7];
    Hash48[8]=0x80;
    //for(a=9;a<0x48;a++)
    //  Hash48[a]=0;
    //table40=(unsigned char*)malloc(0x40);
    memcpy(table40,Tb2,0x40);
  
    for(i = 0; i < 12; i++) Hash14[i] = Tb1[i];
  
    int k1 = *((short*) &Hash14);  int k2 = *((short*) &Hash14+1);  int k3 = *((short*) &Hash14+2);
    int k4 = *((short*) &Hash14+3);  int k5 = *((short*) &Hash14+4);  int k6 = *((short*) &Hash14+5);
    for (m = 0; m < 2; m++) {
      int loop;
      for (loop = 0; loop < 0x24; loop++) {
        h=((Hash48[(loop<<1) +1]<<8)+Hash48[loop<<1])&0xFFFF;
        if(m)
          tmp1 = (((k2 & k4) | ((~k4) & k3)) & 0xFFFF);
        else
          tmp1 = (((k2 & k3) | ((~k2) & k4)) & 0xFFFF);
        if((counter & 1))
          k = *(((short *) table40)+(counter>>1))>>8;
        else
          k = *(((short *) table40)+(counter>>1));
        l = k1;  j = k2;
        k1 = k2;  k2 = k3;  k3 = k4;  k4 = k5;  k5 = k6;
        k6 = ((tmp1 + l + h + (k & 0xFF)) & 0xFFFF);
        tmp1 = tabletmp2[counter2];
        k6 = ((((k6 << tmp1) | (k6 >> (0x10 - tmp1))) + j) & 0xFFFF);
        counter2++;
        if(counter2 == 0x10) counter2 = 0;
        counter++;
        if(counter == 0x40) counter = 0;
      }
      //free(table40);
    }
  
//#if __BYTE_ORDER != __BIG_ENDIAN
    er->cw[b + 0] = (k1 + *((short *)&Hash14)) & 0xFF;
    er->cw[b + 1] = (k1 + *((short *)&Hash14))>>8;
    er->cw[b + 2] = (k2 + *((short *)&Hash14+1)) & 0xFF;
    er->cw[b + 3] = (er->cw[b + 0] + er->cw[b + 1] + er->cw[b + 2]) & 0xFF;
    er->cw[b + 4] = (k3 + *((short *)&Hash14+2)) & 0xFF;
    er->cw[b + 5] = (k3 + *((short *)&Hash14+2))>>8;
    er->cw[b + 6] = (k4 + *((short *)&Hash14+3)) & 0xFF;
    er->cw[b + 7] = (er->cw[b + 4] + er->cw[b + 5] + er->cw[b + 6]) & 0xFF;
/*#else
    er->cw[b + 0] = (k1 + *((short *)&Hash14))>>8;
    er->cw[b + 1] = (k1 + *((short *)&Hash14)) & 0xFF;
    er->cw[b + 2] = (k2 + *((short *)&Hash14+1))>>8;
    er->cw[b + 3] = (er->cw[b + 0] + er->cw[b + 1] + er->cw[b + 2]) & 0xFF;
    er->cw[b + 4] = (k3 + *((short *)&Hash14+2))>>8;
    er->cw[b + 5] = (k3 + *((short *)&Hash14+2)) & 0xFF;
    er->cw[b + 6] = (k4 + *((short *)&Hash14+3))>>8;
    er->cw[b + 7] = (er->cw[b + 4] + er->cw[b + 5] + er->cw[b + 6]) & 0xFF;
#endif*/
  
    cs_dump (er->cw+b, 8, "Postprocessed DW:");
//  }//end for b
}



//////  ====================================================================================

static void swap_lb (unsigned char *buff, int len)
{

#if __BYTE_ORDER != __BIG_ENDIAN
  return;

#endif /*  */
  int i;
  unsigned short *tmp;
  for (i = 0; i < len / 2; i++) {
    tmp = (unsigned short *) buff + i;
    *tmp = ((*tmp << 8) & 0xff00) | ((*tmp >> 8) & 0x00ff);
  }
} 

static inline void __xxor(unsigned char *data, int len, const unsigned char *v1, const unsigned char *v2)
{
  switch(len) { // looks ugly, but the compiler can optimize it very well ;)
    case 16:
      *((unsigned int *)data+3) = *((unsigned int *)v1+3) ^ *((unsigned int *)v2+3);
      *((unsigned int *)data+2) = *((unsigned int *)v1+2) ^ *((unsigned int *)v2+2);
    case 8:
      *((unsigned int *)data+1) = *((unsigned int *)v1+1) ^ *((unsigned int *)v2+1);
    case 4:
      *((unsigned int *)data+0) = *((unsigned int *)v1+0) ^ *((unsigned int *)v2+0);
      break;
    default:
      while(len--) *data++ = *v1++ ^ *v2++;
      break;
    }
}
#define xor16(v1,v2,d) __xxor((d),16,(v1),(v2))
#define val_by2on3(x)  ((0xaaab*(x))>>16) //fixed point *2/3

unsigned short cardkeys[3][32];
unsigned char stateD3A[16];

static void cCamCryptVG2_LongMult(unsigned short *pData, unsigned short *pLen, unsigned int mult, unsigned int carry);
static void cCamCryptVG2_PartialMod(unsigned short val, unsigned int count, unsigned short *outkey, const unsigned short *inkey);
static void cCamCryptVG2_RotateRightAndHash(unsigned char *p);
static void cCamCryptVG2_Reorder16A(unsigned char *dest, const unsigned char *src);
static void cCamCryptVG2_ReorderAndEncrypt(unsigned char *p);
static void cCamCryptVG2_Process_D0(const unsigned char *ins, unsigned char *data, const unsigned char *status);
static void cCamCryptVG2_Process_D1(const unsigned char *ins, unsigned char *data, const unsigned char *status);
static void cCamCryptVG2_Decrypt_D3(unsigned char *ins, unsigned char *data, const unsigned char *status);
static void cCamCryptVG2_PostProcess_Decrypt(unsigned char *buff, int len, unsigned char *cw1, unsigned char *cw2);
static void cCamCryptVG2_SetSeed(unsigned char *Key1, unsigned char *Key2);
static void cCamCryptVG2_GetCamKey(unsigned char *buff);

static void cCamCryptVG2_SetSeed(unsigned char *Key1, unsigned char *Key2)
{
  swap_lb (Key1, 64);
  swap_lb (Key2, 64);
  memcpy(cardkeys[1],Key1,sizeof(cardkeys[1]));
  memcpy(cardkeys[2],Key2,sizeof(cardkeys[2]));
  swap_lb (Key1, 64);
  swap_lb (Key2, 64);
}

static void cCamCryptVG2_GetCamKey(unsigned char *buff)
{
  unsigned short *tb2=(unsigned short *)buff, c=1;
  memset(tb2,0,64);
  tb2[0]=1;
  int i;
  for(i=0; i<32; i++) cCamCryptVG2_LongMult(tb2,&c,cardkeys[1][i],0);
  swap_lb (buff, 64);
}

static void cCamCryptVG2_PostProcess_Decrypt(unsigned char *buff, int len, unsigned char *cw1, unsigned char *cw2)
{
  switch(buff[0]) {
    case 0xD0:
      cCamCryptVG2_Process_D0(buff,buff+5,buff+buff[4]+5);
      break;
    case 0xD1:
      cCamCryptVG2_Process_D1(buff,buff+5,buff+buff[4]+5);
      break;
    case 0xD3:
      cCamCryptVG2_Decrypt_D3(buff,buff+5,buff+buff[4]+5);
      if(buff[1]==0x54) {
        memcpy(cw1,buff+5,8);
        int ind;
        for(ind=13; ind<len; ind++) {
          if(buff[ind]==0x25) {
            //memcpy(cw2,buff+5+ind+2,8);
            memcpy(cw2,buff+ind+3,8); //tested on viasat 093E, sky uk 0963
            break;
            }
/*          if(buff[ind+1]==0) break;
          ind+=buff[ind+1];*/
          }
        }
      break;
    }
}

static void cCamCryptVG2_Process_D0(const unsigned char *ins, unsigned char *data, const unsigned char *status)
{
  switch(ins[1]) {
    case 0xb4:
      swap_lb (data, 64);
      memcpy(cardkeys[0],data,sizeof(cardkeys[0]));
      break;
    case 0xbc: 
      {
      swap_lb (data, 64);
      unsigned short *idata=(unsigned short *)data;
      const unsigned short *key1=(const unsigned short *)cardkeys[1];
      unsigned short key2[32];
      memcpy(key2,cardkeys[2],sizeof(key2));
      int count2;
      for(count2=0; count2<32; count2++) {
        unsigned int rem=0, div=key1[count2];
        int i;
        for(i=31; i>=0; i--) {
          unsigned int x=idata[i] | (rem<<16);
          rem=(x%div)&0xffff;
          }
        unsigned int carry=1, t=val_by2on3(div) | 1;
        while(t) {
          if(t&1) carry=((carry*rem)%div)&0xffff;
          rem=((rem*rem)%div)&0xffff;
          t>>=1;
          }
        cCamCryptVG2_PartialMod(carry,count2,key2,key1);
        }
      unsigned short idatacount=0;
      int i;
      for(i=31; i>=0; i--) cCamCryptVG2_LongMult(idata,&idatacount,key1[i],key2[i]);
      swap_lb (data, 64);
      unsigned char stateD1[16];
      cCamCryptVG2_Reorder16A(stateD1,data);
      cAES_SetKey(stateD1);
      break;
      }
  }
}

static void cCamCryptVG2_Process_D1(const unsigned char *ins, unsigned char *data, const unsigned char *status)
{
  unsigned char iter[16], tmp[16];
  memset(iter,0,sizeof(iter));
  memcpy(iter,ins,5);
  xor16(iter,stateD3A,iter);
  memcpy(stateD3A,iter,sizeof(iter));

  int datalen=status-data;
  int datalen1=datalen;
  if(datalen<0) datalen1+=15;
  int blocklen=datalen1>>4;
  int i;
  int iblock;
  for(i=0,iblock=0; i<blocklen+2; i++,iblock+=16) {
    unsigned char in[16];
    int docalc=1;
    if(blocklen==i && (docalc=datalen&0xf)) {
      memset(in,0,sizeof(in));
      memcpy(in,&data[iblock],datalen-(datalen1&~0xf));
      }
    else if(blocklen+1==i) {
      memset(in,0,sizeof(in));
      memcpy(&in[5],status,2);
      }
    else
      memcpy(in,&data[iblock],sizeof(in));

    if(docalc) {
      xor16(iter,in,tmp);
      cCamCryptVG2_ReorderAndEncrypt(tmp);
      xor16(tmp,stateD3A,iter);
      }
    }
  memcpy(stateD3A,tmp,16);
}

static void cCamCryptVG2_Decrypt_D3(unsigned char *ins, unsigned char *data, const unsigned char *status)
{
  if(ins[4]>16) ins[4]-=16;
  if(ins[1]==0xbe) memset(stateD3A,0,sizeof(stateD3A));

  unsigned char tmp[16];
  memset(tmp,0,sizeof(tmp));
  memcpy(tmp,ins,5);
  xor16(tmp,stateD3A,stateD3A);

  int len1=ins[4];
  int blocklen=len1>>4;
  if(ins[1]!=0xbe) blocklen++;

  unsigned char iter[16], states[16][16];
  memset(iter,0,sizeof(iter));
  int blockindex;
  for(blockindex=0; blockindex<blocklen; blockindex++) {
    iter[0]+=blockindex;
    xor16(iter,stateD3A,iter);
    cCamCryptVG2_ReorderAndEncrypt(iter);
    xor16(iter,&data[blockindex*16],states[blockindex]);
    if(blockindex==(len1>>4)) {
      int c=len1-(blockindex*16);
      if(c<16) memset(&states[blockindex][c],0,16-c);
      }
    xor16(states[blockindex],stateD3A,stateD3A);
    cCamCryptVG2_RotateRightAndHash(stateD3A);
    }
  memset(tmp,0,sizeof(tmp));
  memcpy(tmp+5,status,2);
  xor16(tmp,stateD3A,stateD3A);
  cCamCryptVG2_ReorderAndEncrypt(stateD3A);

  memcpy(stateD3A,status-16,sizeof(stateD3A));
  cCamCryptVG2_ReorderAndEncrypt(stateD3A);

  memcpy(data,states[0],len1);
  if(ins[1]==0xbe) {
    cCamCryptVG2_Reorder16A(tmp,states[0]);
    cAES_SetKey(tmp);
    }
}

static void cCamCryptVG2_ReorderAndEncrypt(unsigned char *p)
{
  unsigned char tmp[16];
  cCamCryptVG2_Reorder16A(tmp,p);
  cAES_Encrypt(tmp,16,tmp);
  cCamCryptVG2_Reorder16A(p,tmp);
}

// reorder AAAABBBBCCCCDDDD to ABCDABCDABCDABCD

static void cCamCryptVG2_Reorder16A(unsigned char *dest, const unsigned char *src)
{
  int i;
  int j;
  int k;
  for(i=0,k=0; i<4; i++)
    for(j=i; j<16; j+=4,k++)
      dest[k]=src[j];
}

static void cCamCryptVG2_LongMult(unsigned short *pData, unsigned short *pLen, unsigned int mult, unsigned int carry)
{
  int i;
  for(i=0; i<*pLen; i++) {
    carry+=pData[i]*mult;
    pData[i]=(unsigned short)carry;
    carry>>=16;
    }
  if(carry) pData[(*pLen)++]=carry;
}

static void cCamCryptVG2_PartialMod(unsigned short val, unsigned int count, unsigned short *outkey, const unsigned short *inkey)
{
  if(count) {
    unsigned int mod=inkey[count];
    unsigned short mult=(inkey[count]-outkey[count-1])&0xffff;
    unsigned int i;
    unsigned int ib1;
    for(i=0,ib1=count-2; i<count-1; i++,ib1--) {
      unsigned int t=(inkey[ib1]*mult)%mod;
      mult=t-outkey[ib1];
      if(mult>t) mult+=mod;
      }
    mult+=val;
    if((val>mult) || (mod<mult)) mult-=mod;
    outkey[count]=(outkey[count]*mult)%mod;
    }
  else 
    outkey[0]=val;
}

static const unsigned char table1[256] = {
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5, 0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0, 0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc, 0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a, 0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0, 0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b, 0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85, 0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5, 0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17, 0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88, 0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c, 0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9, 0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6, 0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e, 0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94, 0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68, 0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
  };

static void cCamCryptVG2_RotateRightAndHash(unsigned char *p)
{
  unsigned char t1=p[15];
  int i;
  for(i=0; i<16; i++) {
    unsigned char t2=t1;
    t1=p[i]; p[i]=table1[(t1>>1)|((t2&1)<<7)];
    }
}

//////  ====================================================================================

static unsigned char CW1[8], CW2[8];

extern uchar cta_cmd[], cta_res[];
extern ushort cta_lr;

extern int io_serial_need_dummy_char;

struct CmdTabEntry {
  unsigned char cla;
  unsigned char cmd;
  unsigned char len;
  unsigned char mode;
};

struct CmdTab {
  unsigned char index;
  unsigned char size;
  unsigned char Nentries;
  unsigned char dummy;
  struct CmdTabEntry e[1];
};

struct CmdTab *cmd_table=NULL;
void memorize_cmd_table (const unsigned char *mem, int size){
  cmd_table=(struct CmdTab *)malloc(sizeof(unsigned char) * size);
  memcpy(cmd_table,mem,size);
}

int cmd_table_get_info(const unsigned char *cmd, unsigned char *rlen, unsigned char *rmode)
{
  struct CmdTabEntry *pcte=cmd_table->e;
  int i;
  for(i=0; i<cmd_table->Nentries; i++,pcte++)
    if(cmd[1]==pcte->cmd) {
      *rlen=pcte->len;
      *rmode=pcte->mode;
      return 1;
      }
  return 0;
}

static int status_ok(const unsigned char *status){
    //cs_log("check status %02x%02x", status[0],status[1]);
    return (status[0] == 0x90 || status[0] == 0x91)
           && (status[1] == 0x00 || status[1] == 0x01
               || status[1] == 0x20 || status[1] == 0x21
               || status[1] == 0x80 || status[1] == 0x81
               || status[1] == 0xa0 || status[1] == 0xa1);
}

#define write_cmd(cmd, data) (card_write(cmd, data) == 0)
#define read_cmd(cmd, data) (card_write(cmd, NULL) == 0)

static int read_cmd_len(const unsigned char *cmd) 
{ 
  unsigned char cmd2[5]; 
  memcpy(cmd2,cmd,5); 
  cmd2[3]=0x80; 
  cmd2[4]=1; 
  if(!read_cmd(cmd2,NULL) || cta_res[1] != 0x90 || cta_res[2] != 0x00) { 
    cs_debug("failed to read %02x%02x cmd length (%02x %02x)",cmd[1],cmd[2],cta_res[1],cta_res[2]); 
    return -1;
    } 
  return cta_res[0];   
}

static int do_cmd(const unsigned char *ins, const unsigned char *txbuff, unsigned char *rxbuff)
{
  unsigned char ins2[5];
  memcpy(ins2,ins,5);
  unsigned char len=0, mode=0;
  if(cmd_table_get_info(ins2,&len,&mode)) {
    if(len==0xFF && mode==2) {
      if(ins2[4]==0) ins2[4]=len=read_cmd_len(ins2);
      }
    else if(mode!=0) ins2[4]=len;
    }
  if(ins2[0]==0xd3) ins2[4]=len+16;
  len=ins2[4];

  unsigned char tmp[264];
  if(!rxbuff) rxbuff=tmp;
  if(mode>1) {
    if(!read_cmd(ins2,NULL) || !status_ok(cta_res+len)) return -1;
    memcpy(rxbuff,ins2,5);
    memcpy(rxbuff+5,cta_res,len);
    memcpy(rxbuff+5+len,cta_res+len,2);
    }
  else {
    if(!write_cmd(ins2,txbuff) || !status_ok(cta_res)) return -2;
    memcpy(rxbuff,ins2,5);
    memcpy(rxbuff+5,txbuff,len);
    memcpy(rxbuff+5+len,cta_res,2);
    }

  cCamCryptVG2_PostProcess_Decrypt(rxbuff,len,CW1,CW2);

  // Log decrypted INS54
  if (rxbuff[1] == 0x54) {
    cs_dump (rxbuff, 5, "Decrypted INS54:");
    cs_dump (rxbuff + 5, rxbuff[4], "");
  }

  return len;
}

#define BASEYEAR 1997
static void rev_date_calc(const unsigned char *Date, int *year, int *mon, int *day, int *hh, int *mm, int *ss)
{
  *year=(Date[0]/12)+BASEYEAR;
  *mon=(Date[0]%12)+1;
  *day=Date[1];
  *hh=Date[2]/8;
  *mm=(0x100*(Date[2]-*hh*8)+Date[3])/32;
  *ss=(Date[3]-*mm*32)*2;
}

static void read_tiers(void)
{
  static const unsigned char ins2a[5] = { 0xd0,0x2a,0x00,0x00,0x00 };
  int l;
  l=do_cmd(ins2a,NULL,NULL);
  if(l<0 || !status_ok(cta_res+l)) return;
  static unsigned char ins76[5] = { 0xd0,0x76,0x00,0x00,0x00 };
  ins76[3]=0x7f; ins76[4]=2;
  if(!read_cmd(ins76,NULL) || !status_ok(cta_res+2)) return;
  ins76[3]=0; ins76[4]=0;
  int num=cta_res[1];
  int i;
  for(i=0; i<num; i++) {
    ins76[2]=i;
    l=do_cmd(ins76,NULL,NULL);
    if(l<0 || !status_ok(cta_res+l)) return;
    if(cta_res[2]==0 && cta_res[3]==0) break;
    int y,m,d,H,M,S;
    rev_date_calc(&cta_res[4],&y,&m,&d,&H,&M,&S);
    cs_log("Tier: %02x%02x, expiry date: %04d/%02d/%02d-%02d:%02d:%02d",cta_res[2],cta_res[3],y,m,d,H,M,S);
    }
}

int videoguard_card_init(uchar *atr, int atrsize)
{
  /* known atrs */
  unsigned char atr_bskyb[] = { 0x3F, 0x7F, 0x13, 0x25, 0x03, 0x33, 0xB0, 0x06, 0x69, 0xFF, 0x4A, 0x50, 0xD0, 0x00, 0x00, 0x53, 0x59, 0x00, 0x00, 0x00 };
  unsigned char atr_bskyb_new[] = { 0x3F, 0xFD, 0x13, 0x25, 0x02, 0x50, 0x00, 0x0F, 0x33, 0xB0, 0x0F, 0x69, 0xFF, 0x4A, 0x50, 0xD0, 0x00, 0x00, 0x53, 0x59, 0x02 };
  unsigned char atr_skyitalia[] = { 0x3F, 0xFF, 0x13, 0x25, 0x03, 0x10, 0x80, 0x33, 0xB0, 0x0E, 0x69, 0xFF, 0x4A, 0x50, 0x70, 0x00, 0x00, 0x49, 0x54, 0x02, 0x00, 0x00 };
  unsigned char atr_skyitalia93b[] = { 0x3F, 0xFD, 0x13, 0x25, 0x02, 0x50, 0x80, 0x0F, 0x33, 0xB0, 0x13, 0x69, 0xFF, 0x4A, 0x50, 0xD0, 0x80, 0x00, 0x49, 0x54, 0x03 };
  unsigned char atr_directv[] = { 0x3F, 0x78, 0x13, 0x25, 0x03, 0x40, 0xB0, 0x20, 0xFF, 0xFF, 0x4A, 0x50, 0x00 };
  unsigned char atr_yes[] = { 0x3F, 0xFF, 0x13, 0x25, 0x03, 0x10, 0x80, 0x33, 0xB0, 0x11, 0x69, 0xFF, 0x4A, 0x50, 0x50, 0x00, 0x00, 0x47, 0x54, 0x01, 0x00, 0x00 };
  unsigned char atr_viasat_new[] = { 0x3F, 0x7D, 0x11, 0x25, 0x02, 0x41, 0xB0, 0x03, 0x69, 0xFF, 0x4A, 0x50, 0xF0, 0x80, 0x00, 0x56, 0x54, 0x03};
  unsigned char atr_premiere[] = { 0x3F, 0xFF, 0x11, 0x25, 0x03, 0x10, 0x80, 0x41, 0xB0, 0x07, 0x69, 0xFF, 0x4A, 0x50, 0x70, 0x00, 0x00, 0x50, 0x31, 0x01, 0x00, 0x11 };

    if ((atrsize == sizeof (atr_bskyb)) && (memcmp (atr, atr_bskyb, atrsize) == 0))
    {
        cs_log("Type: Videoguard BSkyB");
        /* BSkyB seems to need one additionnal byte in the serial communication... */
        io_serial_need_dummy_char = 1;
    }
    else if ((atrsize == sizeof (atr_bskyb_new)) && (memcmp (atr, atr_bskyb_new, atrsize) == 0))
    {
        cs_log("Type: Videoguard BSkyB - New");
    }
    else if ((atrsize == sizeof (atr_skyitalia)) && (memcmp (atr, atr_skyitalia, atrsize) == 0))
    {
        cs_log("Type: Videoguard Sky Italia");
	if (reader[ridx].custom_speed) {
	  cs_log("Notice: for Sky Italia 'customspeed = 1' will not work; resetting to 'customspeed = 0'");
	  reader[ridx].custom_speed = 0;
	}
	if (reader[ridx].mhz != 357)
	  cs_log("Warning: for Sky Italia currently only 'mhz = 357' is known to work! Device %s has mhz = %i",reader[ridx].device,reader[ridx].mhz);
    }
    else if ((atrsize == sizeof (atr_directv)) && (memcmp (atr, atr_directv, atrsize) == 0))
    {
        cs_log("Type: Videoguard DirecTV");
    }
    else if ((atrsize == sizeof (atr_yes)) && (memcmp (atr, atr_yes, atrsize) == 0))
    {
        cs_log("Type: Videoguard YES DBS Israel");
    }
    else if ((atrsize == sizeof (atr_viasat_new)) && (memcmp (atr, atr_viasat_new, atrsize) == 0))
    {
        cs_log("Type: Videoguard Viasat new (093E)");
    }
    else if ((atrsize == sizeof (atr_skyitalia93b)) && (memcmp (atr, atr_skyitalia93b, atrsize) == 0))
    {
        cs_log("Type: Videoguard Sky Italia new (093B)");
	if (reader[ridx].custom_speed) {
	  cs_log("Notice: for Sky Italia 'customspeed = 1' will not work; resetting to 'customspeed = 0'");
	  reader[ridx].custom_speed = 0;
	}
	if (reader[ridx].mhz != 357)
	  cs_log("Warning: for Sky Italia currently only 'mhz = 357' is known to work! Device %s has mhz = %i",reader[ridx].device,reader[ridx].mhz);
    }
    else if ((atrsize == sizeof (atr_premiere)) && (memcmp (atr, atr_premiere, atrsize) == 0))
    {
        cs_log("Type: Videoguard Sky Germany");
    }
/*    else
    {
        // not a known videoguard 
        return (0);
    }*/ 
    //a non videoguard2/NDS card will fail on read_cmd_len(ins7401)
    //this way also unknown videoguard2/NDS cards will work


#ifdef OS_LINUX
if (reader[ridx].typ != R_INTERN) {
  int bconst=B38400;
  int baud=64516;
  int fd=open(reader[ridx].device,O_RDWR|O_NONBLOCK|O_NOCTTY);

  struct termios tio;
  memset(&tio,0,sizeof(tio));
  tio.c_cflag = (CS8 | CREAD | HUPCL | CLOCAL);
  tio.c_cflag |= CSTOPB;
  tio.c_iflag = (INPCK | BRKINT);
  tio.c_cc[VMIN] = 1;
  cfsetispeed(&tio,bconst);
  cfsetospeed(&tio,bconst);
  tio.c_cflag |= (PARENB | PARODD);

  struct serial_struct s;
  if(ioctl(fd,TIOCGSERIAL,&s)<0) {
    cs_log("%s: get serial failed: %s",reader[ridx].device,strerror(errno));
    return 0;
    }
  if(!tcsetattr(fd,TCSANOW,&tio)) {
      if (reader[ridx].custom_speed) {
        s.custom_divisor=(s.baud_base+(baud/2))/baud;
        s.flags=(s.flags&~ASYNC_SPD_MASK) | ASYNC_SPD_CUST;
        cs_log ("%s: custom: baud_base=%d baud=%d divisor=%d -> effective baudrate %d (%+.2f%% off)",
                reader[ridx].device,s.baud_base,baud,s.custom_divisor,s.baud_base/s.custom_divisor,
                (float)(s.baud_base/s.custom_divisor-baud)/(float)baud);
      } else {
        s.flags &= ~ASYNC_SPD_CUST;
        cs_log ("%s: baud=%d", reader[ridx].device, 38400);
        }
      if(ioctl(fd,TIOCSSERIAL,&s)<0) {
        cs_log ("%s: set serial failed: %s",reader[ridx].device,strerror(errno));
        return 0;
        }
      }
  else {
    cs_log ("%s: tcsetattr failed: %s",reader[ridx].device,strerror(errno));
    return 0;
    }
}
#endif

  unsigned char ins7401[5] = { 0xD0,0x74,0x01,0x00,0x00 };
  int l;
  if((l=read_cmd_len(ins7401))<0) return 0; //not a videoguard2/NDS card or communication error
  ins7401[4]=l;
  if(!read_cmd(ins7401,NULL) || !status_ok(cta_res+l)) {
    cs_log ("failed to read cmd list");
    return 0;
    }
  memorize_cmd_table (cta_res,l);

  unsigned char buff[256];

  unsigned char ins7416[5] = { 0xD0,0x74,0x16,0x00,0x00 };
  if(do_cmd(ins7416, NULL, NULL)<0) {
    cs_log ("cmd 7416 failed");
    return 0;
    }

  unsigned char ins36[5] = { 0xD0,0x36,0x00,0x00,0x00 };
  unsigned char boxID [4];

  if (reader[ridx].boxid > 0) {
    /* the boxid is specified in the config */
    int i;
    for (i=0; i < 4; i++) {
        boxID[i] = (reader[ridx].boxid >> (8 * (3 - i))) % 0x100;
    }
  } else {
    /* we can try to get the boxid from the card */
    int boxidOK=0;
    l=do_cmd(ins36, NULL, buff);
    if(l>=0) {
      int i;
      for(i=0; i<l ;i++) {
        if(buff[i+1]==0xF3 && (buff[i]==0x00 || buff[i]==0x0A)) {
          memcpy(&boxID,&buff[i+2],sizeof(boxID));
          boxidOK=1;
          break;
          }
        }
      }

    if(!boxidOK) {
      cs_log ("no boxID available");
      return 0;
      }
  }

  unsigned char ins4C[5] = { 0xD0,0x4C,0x00,0x00,0x09 };
  unsigned char payload4C[9] = { 0,0,0,0, 3,0,0,0,4 };
  memcpy(payload4C,boxID,4);
  if(!write_cmd(ins4C,payload4C) || !status_ok(cta_res+l)) {
    cs_log("sending boxid failed");
    return 0;
    }

  short int SWIRDstatus = cta_res[1];
  unsigned char ins58[5] = { 0xD0,0x58,0x00,0x00,0x00 };
  l=do_cmd(ins58, NULL, buff);
  if(l<0) {
    cs_log("cmd ins58 failed");
    return 0;
    }
  memset(reader[ridx].hexserial, 0, 4);
  memcpy(reader[ridx].hexserial+4, cta_res+3, 4);
  reader[ridx].caid[0] = cta_res[24]*0x100+cta_res[25];

  /* we have one provider, 0x0000 */
  reader[ridx].nprov = 1;
  memset(reader[ridx].prid, 0x00, sizeof(reader[ridx].prid));

  /*
  cs_log ("INS58 : Fuse byte=0x%02X, IRDStatus=0x%02X", cta_res[2],SWIRDstatus);
  if (SWIRDstatus==4)  {
  // If swMarriage=4, not married then exchange for BC Key
  cs_log ("Card not married, exchange for BC Keys");
   */

  unsigned char seed1[] = {
    0xb9, 0xd5, 0xef, 0xd5, 0xf5, 0xd5, 0xfb, 0xd5, 0x31, 0xd6, 0x43, 0xd6, 0x55, 0xd6, 0x61, 0xd6,
    0x85, 0xd6, 0x9d, 0xd6, 0xaf, 0xd6, 0xc7, 0xd6, 0xd9, 0xd6, 0x09, 0xd7, 0x15, 0xd7, 0x21, 0xd7,
    0x27, 0xd7, 0x3f, 0xd7, 0x45, 0xd7, 0xb1, 0xd7, 0xbd, 0xd7, 0xdb, 0xd7, 0x11, 0xd8, 0x23, 0xd8,
    0x29, 0xd8, 0x2f, 0xd8, 0x4d, 0xd8, 0x8f, 0xd8, 0xa1, 0xd8, 0xad, 0xd8, 0xbf, 0xd8, 0xd7, 0xd8
    };
  unsigned char seed2[] = {
    0x01, 0x00, 0xcf, 0x13, 0xe0, 0x60, 0x54, 0xac, 0xab, 0x99, 0xe6, 0x0c, 0x9f, 0x5b, 0x91, 0xb9,
    0x72, 0x72, 0x4d, 0x5b, 0x5f, 0xd3, 0xb7, 0x5b, 0x01, 0x4d, 0xef, 0x9e, 0x6b, 0x8a, 0xb9, 0xd1,
    0xc9, 0x9f, 0xa1, 0x2a, 0x8d, 0x86, 0xb6, 0xd6, 0x39, 0xb4, 0x64, 0x65, 0x13, 0x77, 0xa1, 0x0a,
    0x0c, 0xcf, 0xb4, 0x2b, 0x3a, 0x2f, 0xd2, 0x09, 0x92, 0x15, 0x40, 0x47, 0x66, 0x5c, 0xda, 0xc9
    };
  cCamCryptVG2_SetSeed(seed1,seed2);

  unsigned char insB4[5] = { 0xD0,0xB4,0x00,0x00,0x40 };
  unsigned char tbuff[64];
  cCamCryptVG2_GetCamKey(tbuff);
  l=do_cmd(insB4, tbuff, NULL);
  if(l<0 || !status_ok(cta_res)) {
    cs_log ("cmd D0B4 failed (%02X%02X)", cta_res[0], cta_res[1]);
    return 0;
    }

  unsigned char insBC[5] = { 0xD0,0xBC,0x00,0x00,0x00 };
  l=do_cmd(insBC, NULL, NULL);
  if(l<0) {
    cs_log("cmd D0BC failed");
    return 0;
    }

  unsigned char insBE[5] = { 0xD3,0xBE,0x00,0x00,0x00 };
  l=do_cmd(insBE, NULL, NULL);
  if(l<0) {
    cs_log("cmd D3BE failed");
    return 0;
    }

  unsigned char ins58a[5] = { 0xD1,0x58,0x00,0x00,0x00 };
  l=do_cmd(ins58a, NULL, NULL);
  if(l<0) {
    cs_log("cmd D158 failed");
    return 0;
    }

  unsigned char ins4Ca[5] = { 0xD1,0x4C,0x00,0x00,0x00 };
  l=do_cmd(ins4Ca,payload4C, NULL);
  if(l<0 || !status_ok(cta_res)) {
    cs_log("cmd D14Ca failed");
    return 0;
    }

  cs_log("type: Videoguard, caid: %04X, serial: %02X%02X%02X%02X, BoxID: %02X%02X%02X%02X",
         reader[ridx].caid[0],
         reader[ridx].hexserial[4],reader[ridx].hexserial[5],reader[ridx].hexserial[6],reader[ridx].hexserial[7],
         boxID[0],boxID[1],boxID[2],boxID[3]);

  ///read_tiers();

  cs_log("ready for requests");

  return(1);
}

int videoguard_do_ecm(ECM_REQUEST *er)
{
  static unsigned char ins40[5] = { 0xD1,0x40,0x00,0x80,0xFF };
  static const unsigned char ins54[5] = { 0xD3,0x54,0x00,0x00,0x00};
  int posECMpart2=er->ecm[6]+7;
  int lenECMpart2=er->ecm[posECMpart2]+1;
  unsigned char tbuff[264];
  tbuff[0]=0;
  memcpy(&tbuff[1],&(er->ecm[posECMpart2+1]),lenECMpart2-1);
  ins40[4]=lenECMpart2;
  int l;
  l = do_cmd(ins40,tbuff,NULL);
  if(l>0 && status_ok(cta_res)) {
    l = do_cmd(ins54,NULL,NULL);
    if(l>0 && status_ok(cta_res+l)) {
      if(er->ecm[0]&1) {
        memcpy(er->cw+8,CW1,8);
        //memcpy(er->cw+0,CW2,8);
      } else {
        memcpy(er->cw+0,CW1,8);
        //memcpy(er->cw+8,CW2,8);
        }
      postprocess_cw(er, posECMpart2);
      return 1;
      }
    }
  return 0;
}

static unsigned int num_addr(const unsigned char *data)
{
  return ((data[3]&0x30)>>4)+1;
}

static int addr_mode(const unsigned char *data)
{
  switch(data[3]&0xC0) {
    case 0x40: return 3;
    case 0x80: return 2;
    default:   return 0;
    }
}

static const unsigned char * payload_addr(const unsigned char *data, const unsigned char *a)
{
  int s;
  int l;
  const unsigned char *ptr = NULL;

  switch(addr_mode(data)) {
    case 2: s=3; break;
    case 3: s=4; break;
    default: return NULL;
    }

  int position=-1;
  for(l=0;l<num_addr(data);l++) {
    if(!memcmp(&data[l*4+4],a+4,s)) {
      position=l;
      break;
      }
    }

  /* skip header, the list of address, and the separator (the two 00 00) */
  ptr = data+4+4*num_addr(data)+2;

  /* skip optional 00 */
  if (*ptr == 0x00) ptr++;

  /* skip the 1st bitmap len */
  ptr++;

  /* check */
  if (*ptr != 0x02) return NULL;

  /* skip the 1st timestamp 02 00 or 02 06 xx aabbccdd yy */
  ptr += 2 + ptr[1];

  for(l=0;l<position;l++) {

    /* skip the payload of the previous SA */
    ptr += 1 + ptr [0];

    /* skip optional 00 */
    if (*ptr == 0x00) ptr++;

    /* skip the bitmap len */
    ptr++;

    /* check */
    if (*ptr != 0x02) return NULL;

    /* skip the timestamp 02 00 or 02 06 xx aabbccdd yy */
    ptr += 2 + ptr[1];
    }

  return ptr;
}

int videoguard_do_emm(EMM_PACKET *ep)
{
  unsigned char ins42[5] = { 0xD1,0x42,0x00,0x00,0xFF };
  int rc=0;

  const unsigned char *payload = payload_addr(ep->emm, reader[ridx].hexserial);
  if (payload) {
    ins42[4]=*payload;
    int l = do_cmd(ins42,payload+1,NULL);
    if(l>0 && status_ok(cta_res)) {
      rc=1;
      }

    cs_log("EMM request return code : %02X%02X", cta_res[0], cta_res[1]);
//cs_dump(ep->emm, 64, "EMM:");
    if (status_ok (cta_res)) {
      read_tiers();
      }

    }
 
  return(rc);
}

int videoguard_card_info(void)
{
  /* info is displayed in init, or when processing info */
  cs_log("card detected");
  cs_log("type: Videoguard" );
  read_tiers ();
  return(1);
}
