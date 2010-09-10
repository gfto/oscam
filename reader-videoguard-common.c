//
// Common videoguard functions.
//
#include "globals.h"
#include "reader-common.h"
#include "reader-videoguard-common.h"

int aes_active=0;
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

struct CmdTab *cmd_table=NULL;


int cw_is_valid(unsigned char *cw)	//returns 1 if cw_is_valid, returns 0 if cw is all zeros
{
  int i;
  for (i = 0; i < 8; i++)
    if (cw[i] != 0) {		//test if cw = 00
      return OK;
    }
  return ERROR;
}

void cAES_SetKey(const unsigned char *key)
{
  AES_set_decrypt_key(key,128,&dkey);
  AES_set_encrypt_key(key,128,&ekey);
  aes_active=1;
}

int cAES_Encrypt(const unsigned char *data, int len, unsigned char *crypt)
{
  if(aes_active) {
    len=(len+15)&(~15); // pad up to a multiple of 16
    int i;
    for(i=0; i<len; i+=16) AES_encrypt(data+i,crypt+i,(const AES_KEY *)&ekey);
    return len;
    }
  return -1;
}


void swap_lb (unsigned char *buff, int len)
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

inline void __xxor(unsigned char *data, int len, const unsigned char *v1, const unsigned char *v2)
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


void cCamCryptVG_SetSeed(unsigned char *Key1, unsigned char *Key2)
{
  swap_lb (Key1, 64);
  swap_lb (Key2, 64);
  memcpy(cardkeys[1],Key1,sizeof(cardkeys[1]));
  memcpy(cardkeys[2],Key2,sizeof(cardkeys[2]));
  swap_lb (Key1, 64);
  swap_lb (Key2, 64);
}


void cCamCryptVG_GetCamKey(unsigned char *buff)
{
  unsigned short *tb2=(unsigned short *)buff, c=1;
  memset(tb2,0,64);
  tb2[0]=1;
  int i;
  for(i=0; i<32; i++) cCamCryptVG_LongMult(tb2,&c,cardkeys[1][i],0);
  swap_lb (buff, 64);
}

void cCamCryptVG_PostProcess_Decrypt(unsigned char *buff, int len, unsigned char *cw1, unsigned char *cw2)
{
  switch(buff[0]) {
    case 0xD0:
      cCamCryptVG_Process_D0(buff,buff+5);
      break;
    case 0xD1:
      cCamCryptVG_Process_D1(buff,buff+5,buff+buff[4]+5);
      break;
    case 0xD3:
      cCamCryptVG_Decrypt_D3(buff,buff+5,buff+buff[4]+5);
      if(buff[1]==0x54) {
        memcpy(cw1,buff+5,8);
    	memset(cw2,0,8); //set to 0 so client will know it is not valid if not overwritten with valid cw
        int ind;
        for(ind=13; ind<len+13-8; ind++) {
          if(buff[ind]==0x25) {
            //memcpy(cw2,buff+5+ind+2,8);
            memcpy(cw2,buff+ind+3,8); //tested on viasat 093E, sky uk 0963, sky it 919  //don't care whether cw is 0 or not
            break;
          }
/*          if(buff[ind+1]==0) break;
          ind+=buff[ind+1];*/
        }
      }
      break;
  }
}

void cCamCryptVG_Process_D0(const unsigned char *ins, unsigned char *data)
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
        cCamCryptVG_PartialMod(carry,count2,key2,key1);
        }
      unsigned short idatacount=0;
      int i;
      for(i=31; i>=0; i--) cCamCryptVG_LongMult(idata,&idatacount,key1[i],key2[i]);
      swap_lb (data, 64);
      unsigned char stateD1[16];
      cCamCryptVG_Reorder16A(stateD1,data);
      cAES_SetKey(stateD1);
      break;
      }
  }
}

void cCamCryptVG_Process_D1(const unsigned char *ins, unsigned char *data, const unsigned char *status)
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
      cCamCryptVG_ReorderAndEncrypt(tmp);
      xor16(tmp,stateD3A,iter);
      }
    }
  memcpy(stateD3A,tmp,16);
}

void cCamCryptVG_Decrypt_D3(unsigned char *ins, unsigned char *data, const unsigned char *status)
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
    cCamCryptVG_ReorderAndEncrypt(iter);
    xor16(iter,&data[blockindex*16],states[blockindex]);
    if(blockindex==(len1>>4)) {
      int c=len1-(blockindex*16);
      if(c<16) memset(&states[blockindex][c],0,16-c);
      }
    xor16(states[blockindex],stateD3A,stateD3A);
    cCamCryptVG_RotateRightAndHash(stateD3A);
    }
  memset(tmp,0,sizeof(tmp));
  memcpy(tmp+5,status,2);
  xor16(tmp,stateD3A,stateD3A);
  cCamCryptVG_ReorderAndEncrypt(stateD3A);

  memcpy(stateD3A,status-16,sizeof(stateD3A));
  cCamCryptVG_ReorderAndEncrypt(stateD3A);

  memcpy(data,states[0],len1);
  if(ins[1]==0xbe) {
    cCamCryptVG_Reorder16A(tmp,states[0]);
    cAES_SetKey(tmp);
    }
}

void cCamCryptVG_ReorderAndEncrypt(unsigned char *p)
{
  unsigned char tmp[16];
  cCamCryptVG_Reorder16A(tmp,p);
  cAES_Encrypt(tmp,16,tmp);
  cCamCryptVG_Reorder16A(p,tmp);
}

// reorder AAAABBBBCCCCDDDD to ABCDABCDABCDABCD

void cCamCryptVG_Reorder16A(unsigned char *dest, const unsigned char *src)
{
  int i;
  int j;
  int k;
  for(i=0,k=0; i<4; i++)
    for(j=i; j<16; j+=4,k++)
      dest[k]=src[j];
}

void cCamCryptVG_LongMult(unsigned short *pData, unsigned short *pLen, unsigned int mult, unsigned int carry)
{
  int i;
  for(i=0; i<*pLen; i++) {
    carry+=pData[i]*mult;
    pData[i]=(unsigned short)carry;
    carry>>=16;
    }
  if(carry) pData[(*pLen)++]=carry;
}

void cCamCryptVG_PartialMod(unsigned short val, unsigned int count, unsigned short *outkey, const unsigned short *inkey)
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


void cCamCryptVG_RotateRightAndHash(unsigned char *p)
{
  unsigned char t1=p[15];
  int i;
  for(i=0; i<16; i++) {
    unsigned char t2=t1;
    t1=p[i]; p[i]=table1[(t1>>1)|((t2&1)<<7)];
    }
}


void memorize_cmd_table (const unsigned char *mem, int size){
  cmd_table=(struct CmdTab *)malloc(sizeof(unsigned char) * size);
  memcpy(cmd_table,mem,size);
}

void Manage_Tag(unsigned char *Answer)
{
	unsigned char Tag,Len,Len2;
	bool Valid_0x55=0;
	unsigned char *Body;
	unsigned char Buffer[0x10];
	int a=0x13;
	Len2=Answer[4];
	while(a<Len2)
	{
		Tag=Answer[a];
		Len=Answer[a+1];
		Body=Answer+a+2;
		switch(Tag)
		{
			case 0x55:{
				if(Body[0]==0x84)		//Tag 0x56 has valid data...
					Valid_0x55=1;
			}break;	
			case 0x56:{
				memcpy(Buffer+8,Body,8);
			}break;
		}
		a+=Len+2;	
	
	}			
	if(Valid_0x55)
	{
		memcpy(Buffer,Answer+5,8);									//Copy original DW 
		AES_decrypt(Buffer,Buffer,&Astro_Key);			//Astro_Key declared and filled before...
		memcpy(CW1,Buffer,8);												//Now copy calculated DW in right place
	}
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

int status_ok(const unsigned char *status)
{
    //cs_log("[videoguard2-reader] check status %02x%02x", status[0],status[1]);
    return (status[0] == 0x90 || status[0] == 0x91)
           && (status[1] == 0x00 || status[1] == 0x01
               || status[1] == 0x20 || status[1] == 0x21
               || status[1] == 0x80 || status[1] == 0x81
               || status[1] == 0xa0 || status[1] == 0xa1);
}



int read_cmd_len(struct s_reader * reader, const unsigned char *cmd) 
{ 
  def_resp;
  unsigned char cmd2[5];
  memcpy(cmd2,cmd,5);
  cmd2[3]=0x80;
  cmd2[4]=1;
  // some card reply with L 91 00 (L being the command length).
  
  if(!write_cmd_vg(cmd2,NULL) || !status_ok(cta_res+1)) {
    cs_debug("[videoguard2-reader] failed to read %02x%02x cmd length (%02x %02x)",cmd[1],cmd[2],cta_res[1],cta_res[2]);
    return -1;
    }
  return cta_res[0];
}

int do_cmd(struct s_reader * reader, const unsigned char *ins, const unsigned char *txbuff, unsigned char *rxbuff, unsigned char * cta_res)
{
  ushort cta_lr;
  unsigned char ins2[5];
  memcpy(ins2,ins,5);
  unsigned char len=0, mode=0;
  if(cmd_table_get_info(ins2,&len,&mode)) {
    if(len==0xFF && mode==2) {
      if(ins2[4]==0) ins2[4]=len=read_cmd_len(reader, ins2);
      }
    else if(mode!=0) ins2[4]=len;
    }
  if(ins2[0]==0xd3) ins2[4]=len+16;
  len=ins2[4];

  unsigned char tmp[264];
  if(!rxbuff) rxbuff=tmp;
  if(mode>1) {
    if(!write_cmd_vg(ins2,NULL) || !status_ok(cta_res+len)) return -1;
    memcpy(rxbuff,ins2,5);
    memcpy(rxbuff+5,cta_res,len);
    memcpy(rxbuff+5+len,cta_res+len,2);
    }
  else {
    if(!write_cmd_vg(ins2,(uchar *)txbuff) || !status_ok(cta_res)) return -2;
    memcpy(rxbuff,ins2,5);
    memcpy(rxbuff+5,txbuff,len);
    memcpy(rxbuff+5+len,cta_res,2);
    }

  cCamCryptVG_PostProcess_Decrypt(rxbuff,len,CW1,CW2);

// Start of suggested fix for 09ac cards
  // Log decrypted INS54
  ///if (rxbuff[1] == 0x54) {
  ///  cs_dump (rxbuff, 5, "Decrypted INS54:");
  ///  cs_dump (rxbuff + 5, rxbuff[4], "");
  ///}

  Manage_Tag(rxbuff);
//	End of suggested fix
  return len;
}

void rev_date_calc(const unsigned char *Date, int *year, int *mon, int *day, int *hh, int *mm, int *ss, int base_year)
{
  *year=(Date[0]/12)+base_year;
  *mon=(Date[0]%12)+1;
  *day=Date[1] & 0x1f;
  *hh=Date[2]/8;
  *mm=(0x100*(Date[2]-*hh*8)+Date[3])/32;
  *ss=(Date[3]-*mm*32)*2;
}

