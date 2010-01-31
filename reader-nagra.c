#include "globals.h"
#include "reader-common.h"
#include "cscrypt/idea.h"
#include <termios.h>
#include <unistd.h>

extern uchar cta_res[];
extern ushort cta_lr;

IDEA_KEY_SCHEDULE ksSession;
// Card Status checks
#define HAS_CW      ((reader[ridx].cam_state[2]&6)==6)
#define RENEW_SESSIONKEY ((reader[ridx].cam_state[0]&128)==128 || (reader[ridx].cam_state[0]&64)==64 ||  (reader[ridx].cam_state[0]&32)==32)
#define SENDDATETIME ((reader[ridx].cam_state[0]&16)==16)
// Datatypes
#define DT01        0x01
#define IRDINFO     0x00
#define TIERS       0x05
#define DT06        0x06
#define CAMDATA     0x08

#define MAX_REC     20
#define SYSTEM_NAGRA 0x1800
#define SYSTEM_MASK 0xFF00


static time_t tier_date(ulong date, char *buf, int l)
{
  time_t ut=870393600L+date*(24*3600);
  if (buf)
  {
    struct tm *t;
    t=gmtime(&ut);
    snprintf(buf, l, "%04d/%02d/%02d", t->tm_year+1900, t->tm_mon+1, t->tm_mday);
  }
  return(ut);
}

static int do_cmd(unsigned char cmd, int ilen, unsigned char res, int rlen, unsigned char *data)
{
	/*
	here we build the command related to the protocol T1 for ROM142 or T14 for ROM181
	the only different that i know is the command length byte msg[4], this msg[4]+=1 by a ROM181 smartcard (_nighti_)
	one example for the cmd$C0
	T14 protocol:       01 A0 CA 00 00 03 C0 00 06 91
	T1  protocol: 21 00 08 A0 CA 00 00 02 C0 00 06 87
	*/
	int msglen=ilen+6;
	unsigned char msg[msglen];
	static char nagra_head[] = {0xA0, 0xCA, 0x00, 0x00};

	memset(msg, 0, msglen);
	memcpy(msg,nagra_head,4);
	msg[4] = ilen;
	msg[5] = cmd;
	int dlen=ilen-2;
	msg[6] = dlen;
	if(data && dlen>0) memcpy(msg+7,data,dlen);
	msg[dlen+7] = rlen;
	if (dlen<0)
	{
		cs_debug("[nagra-reader] invalid data length encountered");
    		return ERROR;
    	}
    	if (reader[ridx].is_pure_nagra==1)
    	{
    		msg[4]+=1;
    	}
    	if(!reader_cmd2icc(msg,msglen))
  	{
  		cs_sleepms(5);
		if(cta_res[0]!=res) 
	      	{
	      		cs_debug("[nagra-reader] result not expected (%02x != %02x)",cta_res[0],res);
	      		return ERROR;
	      	}
	      	if((cta_lr-2)!=rlen) 
	      	{
	      		cs_debug("[nagra-reader] result length expected (%d != %d)",(cta_lr-2),rlen);
	      		return ERROR;
	      	}
      		return cta_lr;
      	}		
    	return ERROR;
}

static void ReverseMem(unsigned char *vIn, int len)
{
	unsigned char temp;
	int i;
	for(i=0; i < (len/2); i++)
	{
		temp = vIn[i];
		vIn[i] = vIn[len-i-1];
		vIn[len-i-1] = temp;
	}
}

static void Signature(unsigned char *sig, const unsigned char *vkey,const unsigned char *msg, int len) 
{
	IDEA_KEY_SCHEDULE ks;
	unsigned char v[8];
	unsigned char b200[16];
	unsigned char b0f0[8];
	memcpy(b200,vkey,sizeof(b200));
	int i;
	int j;
	for(i=0; i<len; i+=8)
	{
		idea_set_encrypt_key(b200,&ks);
		memset(v,0,sizeof(v));
		idea_cbc_encrypt(msg+i,b0f0,8,&ks,v,IDEA_DECRYPT);
		for(j=7; j>=0; j--) b0f0[j]^=msg[i+j];
		memcpy(b200+0,b0f0,8);
		memcpy(b200+8,b0f0,8);
	}
	memcpy(sig,b0f0,8);
	return;
}

static int CamStateRequest(void)
{
	if(do_cmd(0xC0,0x02,0xB0,0x06,NULL))
	{
		memcpy(reader[ridx].cam_state,cta_res+3,3);
		cs_debug("[nagra-reader] Camstate: %s",cs_hexdump (1, reader[ridx].cam_state, 3));
	}
	else
	{
		cs_debug("[nagra-reader] CamStateRequest failed");
		return ERROR;
	}
	return OK;
}

static void DateTimeCMD(void)
{
	do_cmd(0xC8,0x02,0xB8,0x06,NULL);
}

static int NegotiateSessionKey_Tiger(void)
{

	unsigned char vFixed[] = {0,1,2,3,0x11};
	unsigned char parte_fija[120];
	unsigned char parte_variable[88];
	unsigned char d1_rsa_modulo[88];
	unsigned char d2_data[88];
	unsigned char sign1[8];
	unsigned char sk[16];
	unsigned char tmp[104];
	unsigned char idea_sig[16];
	unsigned char random[88];
					 
	if(!do_cmd(0xd1,0x02,0x51,0xd2,NULL))
	{
		cs_debug("[nagra-reader] CMD$D1 failed");
		return ERROR;
	}
	
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *bnN = BN_CTX_get(ctx);
	BIGNUM *bnE = BN_CTX_get(ctx);
	BIGNUM *bnCT = BN_CTX_get(ctx);
	BIGNUM *bnPT = BN_CTX_get(ctx);
	BN_bin2bn(reader[ridx].rsa_mod, 120, bnN);
	BN_bin2bn(vFixed+4, 1, bnE);
	BN_bin2bn(&cta_res[90], 120, bnCT);
	BN_mod_exp(bnPT, bnCT, bnE, bnN, ctx);
	memset(parte_fija, 0, 120);
	BN_bn2bin(bnPT, parte_fija + (120-BN_num_bytes(bnPT)));
	BN_CTX_end(ctx);
	BN_CTX_free (ctx);
	
	cs_debug("[nagra-reader] ---------- SIG CHECK ---------------------");
	memset(tmp,0, 104);
	memcpy(tmp+4, parte_fija+11, 100);
	memset(idea_sig, 0x37, 16);
	Signature(sign1, idea_sig, tmp, 104);
	cs_debug("[nagra-reader] sign1: %s", cs_hexdump (0, sign1, 8));
	cs_debug("[nagra-reader] sign2: %s", cs_hexdump (0, parte_fija+111, 8));
	if (!memcmp (parte_fija+111, sign1, 8)==0)
	{
		cs_debug("[nagra-reader] signature check nok");
		cs_debug("[nagra-reader] ------------------------------------------");
		return ERROR;
	}
	cs_debug("[nagra-reader] signature check ok");
	cs_debug("[nagra-reader] ------------------------------------------");
	
	memcpy(reader[ridx].hexserial+2, parte_fija+15, 4);
	memcpy(reader[ridx].irdId, parte_fija+19, 4);
	memcpy(d1_rsa_modulo,parte_fija+23,88);
	
	ReverseMem(cta_res+2, 88);
	BN_CTX *ctx1 = BN_CTX_new();
	BIGNUM *bnN1 = BN_CTX_get(ctx1);
	BIGNUM *bnE1 = BN_CTX_get(ctx1);
	BIGNUM *bnCT1 = BN_CTX_get(ctx1);
	BIGNUM *bnPT1 = BN_CTX_get(ctx1);
	BN_bin2bn(d1_rsa_modulo, 88, bnN1);
	BN_bin2bn(vFixed+4, 1, bnE1);
	BN_bin2bn(cta_res+2, 88, bnCT1);
	BN_mod_exp(bnPT1, bnCT1, bnE1, bnN1, ctx1);
	memset(parte_variable, 0, 88);
	BN_bn2bin(bnPT1, parte_variable + (88-BN_num_bytes(bnPT1)));
	BN_CTX_end(ctx1);
	BN_CTX_free (ctx1);
	
	reader[ridx].prid[0][0]=0x00;
	reader[ridx].prid[0][1]=0x00;
	reader[ridx].prid[0][2]=parte_variable[73];
	reader[ridx].prid[0][3]=parte_variable[74];
	reader[ridx].caid[0] =(SYSTEM_NAGRA|parte_variable[76]);
	memcpy(sk,&parte_variable[79],8);                                                                           
	memcpy(sk+8,&parte_variable[79],8); 
     	cs_ri_log("[nagra-reader] CAID: %04X, IRD ID: %s",reader[ridx].caid[0], cs_hexdump (1,reader[ridx].irdId,4));
     	cs_ri_log("[nagra-reader] ProviderID: %s",cs_hexdump (1,reader[ridx].prid[0],4));

	memset(random, 0, 88);
	memcpy(random, sk,16);
	ReverseMem(random, 88);
	
	
	BN_CTX *ctx3 = BN_CTX_new();
	BIGNUM *bnN3 = BN_CTX_get(ctx3);
	BIGNUM *bnE3 = BN_CTX_get(ctx3);
	BIGNUM *bnCT3 = BN_CTX_get(ctx3);
	BIGNUM *bnPT3 = BN_CTX_get(ctx3);
	BN_bin2bn(d1_rsa_modulo, 88, bnN3);
	BN_bin2bn(vFixed+4, 1, bnE3);
	BN_bin2bn(random, 88, bnCT3);
	BN_mod_exp(bnPT3, bnCT3, bnE3, bnN3, ctx3);
	memset(d2_data, 0, 88);
	BN_bn2bin(bnPT3, d2_data + (88-BN_num_bytes(bnPT3)));
	BN_CTX_end(ctx3);
	BN_CTX_free (ctx3);
	ReverseMem(d2_data, 88);

	if(!do_cmd(0xd2,0x5a,0x52,0x03, d2_data)) 
	{
		cs_debug("[nagra-reader] CMD$D2 failed");
		return ERROR;
	}
	if (cta_res[2] == 0x00)
	{
		memcpy(reader[ridx].sessi,sk,16);
		IDEA_KEY_SCHEDULE ks;
		idea_set_encrypt_key(reader[ridx].sessi,&ks);
		idea_set_decrypt_key(&ks,&ksSession);
		cs_ri_log("[nagra-reader] session key: %s", cs_hexdump(1, reader[ridx].sessi, 16));
		return OK;
	}
	cs_ri_log("Negotiate sessionkey was not successfull! Please check tivusat rsa key");
	return ERROR;
		
}

static int NegotiateSessionKey(void)
{
	unsigned char cmd2b[] = {0x21, 0x40, 0x48, 0xA0, 0xCA, 0x00, 0x00, 0x43, 0x2B, 0x40, 0x1C, 0x54, 0xd1, 0x26, 0xe7, 0xe2, 0x40, 0x20, 0xd1, 0x66, 0xf4, 0x18, 0x97, 0x9d, 0x5f, 0x16, 0x8f, 0x7f, 0x7a, 0x55, 0x15, 0x82, 0x31, 0x14, 0x06, 0x57, 0x1a, 0x3f, 0xf0, 0x75, 0x62, 0x41, 0xc2, 0x84, 0xda, 0x4c, 0x2e, 0x84, 0xe9, 0x29, 0x13, 0x81, 0xee, 0xd6, 0xa9, 0xf5, 0xe9, 0xdb, 0xaf, 0x22, 0x51, 0x3d, 0x44, 0xb3, 0x20, 0x83, 0xde, 0xcb, 0x5f, 0x35, 0x2b, 0xb0, 0xce, 0x70, 0x02, 0x00};
	unsigned char negot[64];
	unsigned char tmp[64];
	unsigned char idea1[16];
	unsigned char idea2[16];
	unsigned char sign1[8];
	unsigned char sign2[8];
	
	if (reader[ridx].is_tiger)
	{
		if (!NegotiateSessionKey_Tiger())
		{
			cs_debug("[nagra-reader] NegotiateSessionKey_Tiger failed");
			return ERROR;
		}
		return OK;
	}
	if (!reader[ridx].has_dt08) // if we have no valid dt08 calc then we use rsa from config and hexserial for calc of sessionkey
	{
		memcpy(reader[ridx].plainDT08RSA, reader[ridx].rsa_mod, 64); 
		memcpy(reader[ridx].signature,reader[ridx].nagra_boxkey, 8);
	}
	if(!do_cmd(0x2a,0x02,0xaa,0x42,NULL))
	{
		cs_debug("[nagra-reader] CMD$2A failed");
		return ERROR;
	}

	// RSA decrypt of cmd$2a data, result is stored in "negot"
	ReverseMem(cta_res+2, 64);
	//cs_debug("[nagra-reader] reader[ridx].plainDT08RSA: %s", cs_hexdump (1, reader[ridx].plainDT08RSA, 32));
	//cs_debug("[nagra-reader] reader[ridx].plainDT08RSA: %s", cs_hexdump (1, &reader[ridx].plainDT08RSA[32], 32));
	unsigned char vFixed[] = {0,1,2,3};
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *bnN = BN_CTX_get(ctx);
	BIGNUM *bnE = BN_CTX_get(ctx);
	BIGNUM *bnCT = BN_CTX_get(ctx);
	BIGNUM *bnPT = BN_CTX_get(ctx);
	BN_bin2bn(reader[ridx].plainDT08RSA, 64, bnN);
	BN_bin2bn(vFixed+3, 1, bnE);
	BN_bin2bn(cta_res+2, 64, bnCT);
	BN_mod_exp(bnPT, bnCT, bnE, bnN, ctx);
	memset(negot, 0, 64);
	BN_bn2bin(bnPT, negot + (64-BN_num_bytes(bnPT)));
	//cs_debug("[nagra-reader] DT08 decrypted $2a data: %s", cs_hexdump (1, negot, 32));
 		//cs_debug("[nagra-reader] DT08 decrypted $2a data: %s", cs_hexdump (1, &negot[32], 32));
 		
	memcpy(tmp, negot, 64);
	ReverseMem(tmp, 64);
	
	// build sessionkey
	// first halve is IDEA Hashed in chuncs of 8 bytes using the Signature1 from dt08 calc, CamID-Inv.CamID(16 bytes key) the results are the First 8 bytes of the Session key
	memcpy(idea1, reader[ridx].signature, 8); 
	memcpy(idea1+8, reader[ridx].hexserial+2, 4);
	idea1[12] = ~reader[ridx].hexserial[2]; idea1[13] = ~reader[ridx].hexserial[3]; idea1[14] = ~reader[ridx].hexserial[4]; idea1[15] = ~reader[ridx].hexserial[5];
		
	Signature(sign1, idea1, tmp, 32);
	memcpy(idea2,sign1,8); memcpy(idea2+8,sign1,8); 
	Signature(sign2, idea2, tmp, 32);
	memcpy(reader[ridx].sessi,sign1,8); memcpy(reader[ridx].sessi+8,sign2,8);
		
	// prepare cmd$2b data
	BN_bin2bn(negot, 64, bnCT);
	BN_mod_exp(bnPT, bnCT, bnE, bnN, ctx);
	memset(cmd2b+10, 0, 64);
	BN_bn2bin(bnPT, cmd2b+10 + (64-BN_num_bytes(bnPT)));
	BN_CTX_end(ctx);
	BN_CTX_free (ctx);
	ReverseMem(cmd2b+10, 64);
		
	IDEA_KEY_SCHEDULE ks;
	idea_set_encrypt_key(reader[ridx].sessi,&ks);
	idea_set_decrypt_key(&ks,&ksSession);
	
	if(!do_cmd(0x2b,0x42,0xab,0x02, cmd2b+10))
	{
		cs_debug("[nagra-reader] CMD$2B failed");
		return ERROR;
	}

	cs_debug("[nagra-reader] session key: %s", cs_hexdump(1, reader[ridx].sessi, 16));
	
	if (!CamStateRequest())
	{
		cs_debug("[nagra-reader] CamStateRequest failed");
		return ERROR;
	}
	if SENDDATETIME 
	{
		DateTimeCMD();
	}
	if RENEW_SESSIONKEY
	{
		cs_ri_log("Negotiate sessionkey was not successfull! Please check rsa key and boxkey");
		return ERROR;
	}

	return OK;
}

static void decryptDT08(void)
{

	unsigned char vFixed[] = {0,1,2,3};
	unsigned char v[72];
	unsigned char buf[72];
	unsigned char sign2[8];
	unsigned char static_dt08[73];
	unsigned char camid[4];
	int i, n;
	BN_CTX *ctx;
	BIGNUM *bn_mod, *bn_exp, *bn_data, *bn_res;
	
	memcpy(static_dt08, &cta_res[12], 73);
	// decrypt RSA Part of dt08
	bn_mod = BN_new ();
  	bn_exp = BN_new ();
  	bn_data = BN_new ();
  	bn_res = BN_new ();
  	ctx= BN_CTX_new();
	if (ctx == NULL) cs_debug("[nagra-reader] RSA Error in dt08 decrypt");
  	ReverseMem(static_dt08+1, 64);
  	BN_bin2bn (reader[ridx].rsa_mod, 64, bn_mod); // rsa modulus
  	BN_bin2bn (vFixed+3, 1, bn_exp); // exponent
  	BN_bin2bn (static_dt08+1, 64, bn_data);
  	BN_mod_exp (bn_res, bn_data, bn_exp, bn_mod, ctx);
  	memset (static_dt08+1, 0, 64);
  	n = BN_bn2bin (bn_res, static_dt08+1);
  	BN_CTX_free (ctx);
  	ReverseMem(static_dt08+1, n);
  	
  	// RSA data can never be bigger than the modulo
  	static_dt08[64] |= static_dt08[0] & 0x80;
  	
  	// IdeaCamKey
  	memcpy (&reader[ridx].IdeaCamKey[0], reader[ridx].nagra_boxkey, 8);
  	memcpy (&reader[ridx].IdeaCamKey[8], reader[ridx].irdId, 4);
  	for (i = 0; i < 4; i++)
        	reader[ridx].IdeaCamKey[12 + i] = ~reader[ridx].irdId[i];
        
  	// now IDEA decrypt
  	IDEA_KEY_SCHEDULE ks;
  	idea_set_encrypt_key(reader[ridx].IdeaCamKey,&ks);
  	idea_set_decrypt_key(&ks,&ksSession);
  	memcpy (&buf[0], static_dt08+1, 64);
  	memcpy (&buf[64], static_dt08+65, 8);
  	memset(v,0,sizeof(v));
  	memset(static_dt08,0,sizeof(static_dt08));
  	idea_cbc_encrypt(buf,static_dt08,72,&ksSession,v,IDEA_DECRYPT);
  	
  	if (reader[ridx].swapCW==1)
  	{
  		memset(camid,0xff,4);
  	}
  	else
  	{
  		memcpy(camid, reader[ridx].hexserial+2,4);
  	}
  	cs_debug("[nagra-reader] using camid %s for dt08 calc",cs_hexdump (1,camid,4));
  	
	// Calculate signature
  	memcpy (reader[ridx].signature, static_dt08, 8);
  	memset (static_dt08 + 0, 0, 4);
  	memcpy (static_dt08 + 4, camid, 4);
  	Signature(sign2,reader[ridx].IdeaCamKey,static_dt08,72);
	
	if (memcmp (reader[ridx].signature, sign2, 8)==0)
	{
		reader[ridx].has_dt08=1;
		memcpy (reader[ridx].plainDT08RSA, static_dt08+8, 64);
		cs_debug("[nagra-reader] DT08 signature check ok");
	}
	else
	{
		reader[ridx].has_dt08=0;
		cs_debug("[nagra-reader] DT08 signature check nok");
	}  	
}

static void addProvider()
{
	int i;
	int toadd=1;
	for (i=0; i<reader[ridx].nprov; i++)
	{
		if ((cta_res[7]==reader[ridx].prid[i][2]) && (cta_res[8]==reader[ridx].prid[i][3]))
		{
			toadd = 0;
		}
	}
	if (toadd)
	{
		reader[ridx].prid[reader[ridx].nprov][0]=0;
  		reader[ridx].prid[reader[ridx].nprov][1]=0;
  		reader[ridx].prid[reader[ridx].nprov][2]=cta_res[7];
  		reader[ridx].prid[reader[ridx].nprov][3]=cta_res[8];
  		memcpy(reader[ridx].sa[reader[ridx].nprov], reader[ridx].sa[0], 4);
 		reader[ridx].nprov+=1;
	}
}			

static int ParseDataType(unsigned char dt)
{
	char ds[16], de[16];
      	ushort chid;
	switch(dt) 
	{
		case IRDINFO:
		{
			reader[ridx].prid[0][0]=0;
  			reader[ridx].prid[0][1]=0;
  			reader[ridx].prid[0][2]=cta_res[7];
  			reader[ridx].prid[0][3]=cta_res[8];
  			if ( ((cta_res[7] == 0x34) && (cta_res[8] == 0x11)) || ((cta_res[7] == 0x04) && (cta_res[8] == 0x01))) //provider 3411, 0401 needs cw swap
  			{
  				cs_debug("[nagra-reader] detect provider with swap cw!");
  				reader[ridx].swapCW=1;
  			}
  			
			reader[ridx].prid[1][0]=0x00;
			reader[ridx].prid[1][1]=0x00;
			reader[ridx].prid[1][2]=0x00;
			reader[ridx].prid[1][3]=0x00;
			memcpy(reader[ridx].sa[1], reader[ridx].sa[0], 4);
 			reader[ridx].nprov+=1;
 					
			reader[ridx].caid[0] =(SYSTEM_NAGRA|cta_res[11]);
			//reader[ridx].caid[0] =0x1801;
     			memcpy(reader[ridx].irdId,cta_res+14,4);
     			cs_debug("[nagra-reader] CAID: %04X, IRD ID: %s",reader[ridx].caid[0], cs_hexdump (1,reader[ridx].irdId,4));
     			cs_debug("[nagra-reader] ProviderID: %s",cs_hexdump (1,reader[ridx].prid[0],4));
     			return OK;
     		}
   		case TIERS:
   			if ((cta_lr>33) && (chid=b2i(2, cta_res+11)))
      			{
      				int id=(cta_res[7]*256)|cta_res[8];
        			tier_date(b2i(2, cta_res+20)-0x7f7, ds, 15);
        			tier_date(b2i(2, cta_res+13)-0x7f7, de, 15);
        			cs_ri_log("|%04X|%04X    |%s  |%s  |", id,chid, ds, de);
        			addProvider(); 
        		}
       		case 0x08:
     		case 0x88: if (cta_res[11] == 0x49) decryptDT08();  			
       		default:
       			return OK;
   	}
  	return ERROR;
}

static int GetDataType(unsigned char dt, int len, int shots)
{
	int i;
  	for(i=0; i<shots; i++)
  	{
  		if(!do_cmd(0x22,0x03,0xA2,len,&dt))
  		{
  			cs_debug("[nagra-reader] failed to get datatype %02X",dt);
  			return ERROR;
  		}
    		if((cta_res[2]==0) && (dt != 0x08 || dt != 0x88)) return OK;
    		if(!ParseDataType(dt&0x0F)) return ERROR;
    		if ((dt != 0x08 || dt != 0x88) && (cta_res[11] == 0x49)) return OK; //got dt08 data	
    		dt|=0x80; // get next item
    	}
  	return OK;
}

int nagra2_card_init(ATR newatr)
{
	get_atr;
	memset(reader[ridx].rom, 0, 15);
	reader[ridx].nprov = 1;
	memset(reader[ridx].hexserial, 0, 8); 
	reader[ridx].caid[0]=SYSTEM_NAGRA;
	reader[ridx].is_pure_nagra = 0;
	reader[ridx].is_tiger=0;
	reader[ridx].has_dt08=0;
	memset(reader[ridx].plainDT08RSA, 0, 64);
	memset(reader[ridx].irdId, 0xff, 4);
	
	if (memcmp(atr+11, "DNASP", 5)==0)
	{
		cs_ri_log("[nagra-reader] detect native nagra card T1 protocol");
		memcpy(reader[ridx].rom,atr+11,15);
	}
	else if (memcmp(atr+11, "TIGER", 5)==0 || (memcmp(atr+11, "NCMED", 5)==0))
	{
		cs_ri_log("[nagra-reader] detect nagra tiger card");
		memcpy(reader[ridx].rom,atr+11,15);
		reader[ridx].is_tiger=1;
	}
	else if ((!memcmp(atr+4, "IRDETO", 6)) && ((atr[14]==0x03) && (atr[15]==0x84) && (atr[16]==0x55)))
	{
		cs_ri_log("[nagra-reader] detect Irdeto tunneled nagra card");
		if(!reader[ridx].has_rsa)
		{
			cs_ri_log("[nagra-reader] switching back to Irdeto mode");
			return ERROR;
		}
		cs_ri_log("[nagra-reader] using nagra mode");
		reader[ridx].is_pure_nagra=1;
		if(!do_cmd(0x10,0x02,0x90,0x11,0))
		{
			cs_debug("[nagra-reader] get rom version failed");
			return ERROR;
		}
		memcpy(reader[ridx].rom,cta_res+2,15);
	}
	else return ERROR;

	if (!reader[ridx].is_tiger)
	{
		CamStateRequest();
		if(!do_cmd(0x12,0x02,0x92,0x06,0)) 
		{
			cs_debug("[nagra-reader] get Serial failed");
			return ERROR;
		}
		memcpy(reader[ridx].hexserial+2, cta_res+2, 4);
		cs_debug("[nagra-reader] SER:  %s", cs_hexdump (1, reader[ridx].hexserial+2, 4));
		//memset(reader[ridx].sa[0], 0xff, 4);
		memcpy(reader[ridx].sa[0], cta_res+2, 2);
		
		if(!GetDataType(DT01,0x0E,MAX_REC)) return ERROR;
		cs_debug("[nagra-reader] DT01 DONE");
		CamStateRequest();
		if(!GetDataType(IRDINFO,0x39,MAX_REC)) return ERROR;
		cs_debug("[nagra-reader] IRDINFO DONE");
		CamStateRequest();
		if(!GetDataType(CAMDATA,0x55,10)) return ERROR;
		cs_debug("[nagra-reader] CAMDATA Done");
		if(!GetDataType(0x04,0x44,MAX_REC)) return ERROR;
		cs_debug("[nagra-reader] DT04 DONE");
		CamStateRequest();
		
		if (!memcmp(reader[ridx].rom+5, "181", 3)==0) //dt05 is not supported by rom181
		{
			cs_ri_log("-----------------------------------------");
			cs_ri_log("|id  |tier    |valid from  |valid to    |");
		  	cs_ri_log("+----+--------+------------+------------+");
			if(!GetDataType(TIERS,0x57,MAX_REC)) return ERROR;
			cs_ri_log("-----------------------------------------");
			CamStateRequest();
		}
		
		if(!GetDataType(DT06,0x16,MAX_REC)) return ERROR;
		cs_debug("[nagra-reader] DT06 DONE");
		CamStateRequest();
	}
	if (!NegotiateSessionKey())
	{
		cs_debug("[nagra-reader] NegotiateSessionKey failed");
		return ERROR;
	}
	if ((reader[ridx].cardmhz != 368) && (reader[ridx].is_pure_nagra == 0))
		cs_log("WARNING: For Nagra2 cards you will have to set 'cardmhz = 368' in oscam.server");
	
	return OK;
}

int nagra2_card_info(void)
{
	int i;
	cs_ri_log("ROM:    %c %c %c %c %c %c %c %c", reader[ridx].rom[0], reader[ridx].rom[1], reader[ridx].rom[2], 
												reader[ridx].rom[3], reader[ridx].rom[4], reader[ridx].rom[5], 
												reader[ridx].rom[6], reader[ridx].rom[7]);
	cs_ri_log("REV:    %c %c %c %c %c %c", reader[ridx].rom[9], reader[ridx].rom[10], reader[ridx].rom[11],
											reader[ridx].rom[12], reader[ridx].rom[13], reader[ridx].rom[14]);
	cs_ri_log("SER:    %s", cs_hexdump (1, reader[ridx].hexserial+2, 4));
	cs_ri_log("CAID:   %04X",reader[ridx].caid[0]);
	cs_ri_log("Prv.ID: %s(sysid)",cs_hexdump (1,reader[ridx].prid[0],4));
	for (i=1; i<reader[ridx].nprov; i++)
	{
		cs_ri_log("Prv.ID: %s",cs_hexdump (1,reader[ridx].prid[i],4));
	}
	cs_log("[nagra-reader] ready for requests"); 
	return OK;
}

void nagra2_post_process(void)
{
	if (!reader[ridx].is_tiger)
	{
		CamStateRequest();
		cs_sleepms(10);
		if RENEW_SESSIONKEY NegotiateSessionKey();
		if SENDDATETIME DateTimeCMD();
	}
}

int nagra2_do_ecm(ECM_REQUEST *er)
{
	if (!reader[ridx].is_tiger)
	{
		int retry=0;
		if(!do_cmd(er->ecm[3],er->ecm[4]+2,0x87,0x02, er->ecm+3+2)) 
		{
			cs_debug("[nagra-reader] nagra2_do_ecm failed, retry");
			cs_sleepms(10);
			if(!do_cmd(er->ecm[3],er->ecm[4]+2,0x87,0x02, er->ecm+3+2))
			{
				cs_debug("[nagra-reader] nagra2_do_ecm failed, retry failed!");
				return ERROR;
			}
	
		}
		cs_sleepms(10);
		while(!CamStateRequest() && retry < 3)
		{
			cs_debug("[nagra-reader] CamStateRequest failed, try: %d", retry);
			retry++;
	                cs_sleepms(10);
		}
		//cs_sleepms(10);
		if (HAS_CW && (do_cmd(0x1C,0x02,0x9C,0x36,NULL)))
		{
			unsigned char v[8];
			memset(v,0,sizeof(v));
			idea_cbc_encrypt(&cta_res[30],er->cw,8,&ksSession,v,IDEA_DECRYPT);
			memset(v,0,sizeof(v));
			idea_cbc_encrypt(&cta_res[4],er->cw+8,8,&ksSession,v,IDEA_DECRYPT);
			if (reader[ridx].swapCW==1)
		  	{
		  		cs_debug("[nagra-reader] swap cws");
		    		unsigned char tt[8];
		    		memcpy(&tt[0],&er->cw[0],8);
		    		memcpy(&er->cw[0],&er->cw[8],8);
		   		memcpy(&er->cw[8],&tt[0],8);
		    	}
			return OK;
		}
	}
	else
	{
		//check ECM prov id
		if (memcmp(&reader[ridx].prid[0][2], er->ecm+5, 2))
			return ERROR;
	
		//                  ecm_data: 80 30 89 D3 87 54 11 10 DA A6 0F 4B 92 05 34 00 ...
		//serial_data: A0 CA 00 00 8C D3 8A 00 00 00 00 00 10 DA A6 0F .
		unsigned char ecm_trim[150];
		memset(ecm_trim, 0, 150);
		memcpy(&ecm_trim[5], er->ecm+3+2+2, er->ecm[4]+2);
		if(do_cmd(er->ecm[3],er->ecm[4]+5,0x53,0x16, ecm_trim)) 
		{
			if(cta_res[2] == 0x01)
			{

				unsigned char v[8];
				memset(v,0,sizeof(v));
				idea_cbc_encrypt(&cta_res[14],er->cw,8,&ksSession,v,IDEA_DECRYPT);
				memset(v,0,sizeof(v));
				idea_cbc_encrypt(&cta_res[6],er->cw+8,8,&ksSession,v,IDEA_DECRYPT);
				return OK;
			}
			cs_debug("[nagra-reader] can't decode ecm");
			return ERROR;
		}
	}
	return ERROR;
}

int nagra2_do_emm(EMM_PACKET *ep)
{
	if (!reader[ridx].is_tiger)
	{
		if(!do_cmd(ep->emm[8],ep->emm[9]+2,0x84,0x02,ep->emm+8+2))
		{
			cs_debug("[nagra-reader] nagra2_do_emm failed");
			return ERROR;
		}
		// for slow t14 nagra cards, we must do additional timeout
		if (reader[ridx].is_pure_nagra==1) 
		{
			cs_sleepms(300);
		}
		cs_sleepms(250);
		nagra2_post_process();
	}
	else
	{
		//check EMM prov id
		if (memcmp(&reader[ridx].prid[0][2], ep->emm+10, 2))
			return ERROR;
	
		//   emm_data: 82 70 8E 00 00 00 00 00 D3 87 8D 11 C0 F4 B1 27 2C 3D 25 94 ...
		//serial_data: A0 CA 00 00 8C D3 8A 01 00 00 00 00 C0 F4 B1 27 2C 3D 25 94 ...
		unsigned char emm_trim[150];
		memset(emm_trim, 0, 150);
		memcpy(&emm_trim[5], ep->emm+3+5+2+2, ep->emm[9]+2);
		if(!do_cmd(ep->emm[8],ep->emm[9]+5,0x53,0x16, emm_trim))
		{
			cs_debug("[nagra-reader] nagra2_do_emm failed");
			return ERROR;
		}
		cs_sleepms(300); 
	}
	return OK;
}
