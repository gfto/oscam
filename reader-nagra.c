#include "globals.h"
#include "reader-common.h"
#include "cscrypt/i_cbc.c"
#include "cscrypt/i_skey.c"
#include <termios.h>
#include <unistd.h>
#ifdef OS_LINUX
#include <linux/serial.h>
#endif

IDEA_KEY_SCHEDULE ksSession;
extern uchar cta_res[];
extern ushort cta_lr;
int is_pure_nagra=0;
int hasMod=0;
unsigned char rom[15];
unsigned char plainDT08RSA[64];
unsigned char IdeaCamKey[16];
unsigned char irdId[] = {0xff,0xff,0xff,0xff};
unsigned char camid[] = {0xff,0xff,0xff,0xff};
unsigned char sessi[16];
unsigned char signature[8];
unsigned char cam_state[4];
unsigned char static_dt08[73];

#define SYSTEM_NAGRA 0x1800
// Card Status checks
//#define HAS_CW      ((cam_state[1]==0x10)&&((cam_state[3]&6)==6))
#define HAS_CW      ((cam_state[3]&6)==6)
// Datatypes
#define DT01        0x01
#define IRDINFO     0x00
#define TIERS       0x05
#define DT06        0x06
#define CAMDATA     0x08

#define MAX_REC     20

unsigned char XorSum(const unsigned char *mem, int len)
{
  unsigned char cs;
  cs=0x00;
  while(len>0) 
  {
  	cs ^= *mem++; 
  	len--;
  }
  return cs;
}

void Date(const unsigned char *data, char *dt, char *ti)
{
	int date=(data[0]<<8)|data[1];
	int time=(data[2]<<8)|data[3];
	struct tm t;
	memset(&t,0,sizeof(struct tm));
	t.tm_min =0;//-300;
	t.tm_year=92;
	t.tm_mday=date + 1;
	t.tm_sec =(time - 1) * 2;
  	mktime(&t);
  	snprintf(dt,11,"%.2d.%.2d.%.4d",t.tm_mon+1,t.tm_mday,t.tm_year+1900);
  	snprintf(ti,9,"%.2d:%.2d:%.2d",t.tm_hour,t.tm_min,t.tm_sec);
}

int do_cmd(unsigned char cmd, int ilen, unsigned char res, int rlen, unsigned char *data)
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
    		return 0;
    	}
    	if (is_pure_nagra==0) msg[4]+=1;
    	cs_sleepms(50);
    	if(!reader_cmd2icc(msg,msglen))
  	{
		if(cta_res[0]!=res) 
	      	{
	      		cs_debug("[nagra-reader] result not expected (%02x != %02x)",cta_res[0],res);
	      		return 0;
	      	}
	      	if((cta_lr-2)!=rlen) 
	      	{
	      		cs_debug("[nagra-reader] result length expected (%d != %d)",(cta_lr-2),rlen);
	      		return 0;
	      	}
      		return cta_lr;
      	}		
    	return 0;
}

int SetIFS(unsigned char size)
{
	unsigned char buf[5];
	int ret;
  	// NAD, PCB, LEN
  	buf[0] = 0x21;
  	buf[1] = 0xC1; // IFS Request cmd
  	buf[2] = 0x01; // cmd length
  	buf[3] = size; // Information Field size
  	buf[4] = XorSum(buf,4); //lrc byte

	cs_debug("[nagra-reader] IFS cmd: %s", cs_hexdump (1, buf, 5));
	ret = reader_cmd2api(buf, 5);
	cs_debug("[nagra-reader] IFS response: %s", cs_hexdump (1, cta_res, cta_lr));
  	if ((cta_lr!=5) || (ret!=OK)) 
  	{
    		cs_debug("[nagra-reader] setting IFS to %02x failed", size);
    		return 0;
    	}
    	cs_debug("[nagra-reader] IFS is now %02x", size);
  	return 1;
}

void ReverseMem(unsigned char *vIn, int len)
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

void Signature(unsigned char *sig, const unsigned char *vkey,const unsigned char *msg, int len)
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

int CamStateRequest(void)
{
	if(do_cmd(0xC0,0x02,0xB0,0x06,NULL))
	{
		memcpy(cam_state,cta_res+2,4);
		switch(cam_state[1])
		{
			case 0xb0: cs_debug("[nagra-reader] CamStateRequest: request [%X]", cam_state[1]); break;
			case 0x30: cs_debug("[nagra-reader] CamStateRequest: request [%X]", cam_state[1]); break;
			case 0x90: cs_debug("[nagra-reader] CamStateRequest: request [%X]", cam_state[1]); break;
			//case 0x10: cs_debug("[nagra-reader] CamStateRequest: has_cw"); break;
			case 0xc3: cs_debug("[nagra-reader] CamStateRequest: cam has been reseted"); break;
			case 0xc1: 
			case 0xd1: cs_debug("[nagra-reader] CamStateRequest: dump DT"); break; //DumpDatatypes(); break;
			case 0xd0: cs_debug("[nagra-reader] CamStateRequest: NegotiateSessionKey"); NegotiateSessionKey(); break;
			case 0x00:
			case 0x11:
			case 0xc0: cs_debug("[nagra-reader] CamStateRequest: ready for requests"); break;
			default:   cs_debug("[nagra-reader] CamStateRequest: unknown request [%X]", cam_state[1]); break;
		}
	}
	else
	{
		cs_debug("[nagra-reader] CamStateRequest failed");
		return 0;
	}
	return (1);
}

int NegotiateSessionKey(void)
{
	unsigned char cmd2b[] = {0x21, 0x40, 0x48, 0xA0, 0xCA, 0x00, 0x00, 0x43, 0x2B, 0x40, 0x1C, 0x54, 0xd1, 0x26, 0xe7, 0xe2, 0x40, 0x20, 0xd1, 0x66, 0xf4, 0x18, 0x97, 0x9d, 0x5f, 0x16, 0x8f, 0x7f, 0x7a, 0x55, 0x15, 0x82, 0x31, 0x14, 0x06, 0x57, 0x1a, 0x3f, 0xf0, 0x75, 0x62, 0x41, 0xc2, 0x84, 0xda, 0x4c, 0x2e, 0x84, 0xe9, 0x29, 0x13, 0x81, 0xee, 0xd6, 0xa9, 0xf5, 0xe9, 0xdb, 0xaf, 0x22, 0x51, 0x3d, 0x44, 0xb3, 0x20, 0x83, 0xde, 0xcb, 0x5f, 0x35, 0x2b, 0xb0, 0xce, 0x70, 0x02, 0x00};
	unsigned char negot[64];
	unsigned char tmp[64];
	unsigned char idea1[16];
	unsigned char idea2[16];
	unsigned char sign1[8];
	unsigned char sign2[8];

	if(!do_cmd(0x2a,0x02,0xaa,0x42,NULL))
	{
		cs_debug("[nagra-reader] CMD$2A failed");
		return 0;
	}

	{
		// RSA decrypt of cmd$2a data, result is stored in "negot"
		ReverseMem(cta_res+2, 64);
		//cs_debug("[nagra-reader] plainDT08RSA: %s", cs_hexdump (1, plainDT08RSA, 32));
  		//cs_debug("[nagra-reader] plainDT08RSA: %s", cs_hexdump (1, &plainDT08RSA[32], 32));
		unsigned char vFixed[] = {0,1,2,3};
		BN_CTX *ctx = BN_CTX_new();
		BIGNUM *bnN = BN_CTX_get(ctx);
		BIGNUM *bnE = BN_CTX_get(ctx);
		BIGNUM *bnCT = BN_CTX_get(ctx);
		BIGNUM *bnPT = BN_CTX_get(ctx);
		BN_bin2bn(plainDT08RSA, 64, bnN);
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
		memcpy(idea1, signature, 8); memcpy(idea1+8, reader[ridx].hexserial, 4); idea1[12] = ~reader[ridx].hexserial[0]; idea1[13] = ~reader[ridx].hexserial[1]; idea1[14] = ~reader[ridx].hexserial[2]; idea1[15] = ~reader[ridx].hexserial[3];
		Signature(sign1, idea1, tmp, 32);
		memcpy(idea2,sign1,8); memcpy(idea2+8,sign1,8); 
		Signature(sign2, idea2, tmp, 32);
		memcpy(sessi,sign1,8); memcpy(sessi+8,sign2,8);
		
		// prepare cmd$2b data
		BN_bin2bn(negot, 64, bnCT);
		BN_mod_exp(bnPT, bnCT, bnE, bnN, ctx);
		memset(cmd2b+10, 0, 64);
		BN_bn2bin(bnPT, cmd2b+10 + (64-BN_num_bytes(bnPT)));
		BN_CTX_end(ctx);
		BN_CTX_free (ctx);
		ReverseMem(cmd2b+10, 64);
		
		IDEA_KEY_SCHEDULE ks;
		idea_set_encrypt_key(sessi,&ks);
		idea_set_decrypt_key(&ks,&ksSession);

	}

	if(!do_cmd(0x2b,0x42,0xab,0x02, cmd2b+10)) 
	{
		cs_debug("[nagra-reader] CMD$2B failed");
		return 0;
	}
	cs_ri_log("[nagra-reader] Session Key: %s", cs_hexdump(1, sessi, 16));
	return 1;
}

void decryptDT08(void)
{

	unsigned char vFixed[] = {0,1,2,3};
	unsigned char v[72];
	unsigned char buf[72];
	unsigned char sign2[8];
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
  	//cs_debug("[nagra-reader]   DT08 RSA modulus: %s", cs_hexdump (1, reader[ridx].rsa_mod, 32));
  	//cs_debug("[nagra-reader]   DT08 RSA modulus: %s", cs_hexdump (1, &reader[ridx].rsa_mod[32], 32));
  	ReverseMem(static_dt08+1, 64);
  	BN_bin2bn (reader[ridx].rsa_mod, 64, bn_mod); // rsa modulus
  	BN_bin2bn (vFixed+3, 1, bn_exp); // exponent
  	BN_bin2bn (static_dt08+1, 64, bn_data);
  	//cs_debug("[nagra-reader]   DT08 crypted rsa: %s", cs_hexdump (1, static_dt08+1, 32));
  	//cs_debug("[nagra-reader]   DT08 crypted rsa: %s", cs_hexdump (1, static_dt08+33, 32));
  	BN_mod_exp (bn_res, bn_data, bn_exp, bn_mod, ctx);
  	memset (static_dt08+1, 0, 64);
  	n = BN_bn2bin (bn_res, static_dt08+1);
  	ReverseMem(static_dt08+1, n);
  	//cs_debug("[nagra-reader] DT08 decrypted rsa: %s", cs_hexdump (1, static_dt08+1, 32));
  	//cs_debug("[nagra-reader] DT08 decrypted rsa: %s", cs_hexdump (1, static_dt08+33, 32));
  	
  	// RSA data can never be bigger than the modulo
  	//decryptedRsaDT08[63] |= static_dt08[0] & 0x80;
  	
  	// IdeaCamKey
  	memcpy (&IdeaCamKey[0], reader[ridx].nagra_boxkey, 8);
  	memcpy (&IdeaCamKey[8], irdId, 4);
  	for (i = 0; i < 4; i++)
        	IdeaCamKey[12 + i] = ~irdId[i];
        //cs_debug("[nagra-reader] DT08 Plainkey: %s", cs_hexdump (1, IdeaCamKey, 16));
        
  	// now IDEA decrypt
  	IDEA_KEY_SCHEDULE ks;
  	idea_set_encrypt_key(IdeaCamKey,&ks);
  	idea_set_decrypt_key(&ks,&ksSession);
	//cs_debug("[nagra-reader] dt08 idea part: %s", cs_hexdump (1, static_dt08+65, 8));
  	memcpy (&buf[0], static_dt08+1, 64);
  	memcpy (&buf[64], static_dt08+65, 8);
  	//cs_debug("[nagra-reader] dt08 64byte rsa decrypted + 8last byte: %s", cs_hexdump (1, buf, 64));
  	//cs_debug("[nagra-reader] dt08 64byte rsa decrypted + 8last byte: %s", cs_hexdump (1, &buf[64], 8));
  	memset(v,0,sizeof(v));
  	memset(static_dt08,0,sizeof(static_dt08));
  	idea_cbc_encrypt(buf,static_dt08,72,&ksSession,v,IDEA_DECRYPT);
  	//cs_debug("[nagra-reader] dt08 72byte idea decrypted: %s", cs_hexdump (1, &static_dt08[0], 36));
  	//cs_debug("[nagra-reader] dt08 72byte idea decrypted: %s", cs_hexdump (1, &static_dt08[35], 37));
  	
	// Calculate signature
  	memcpy (signature, static_dt08, 8);
  	memset (static_dt08 + 0, 0, 4);
  	memcpy (static_dt08 + 4, camid, 4);
  	Signature(sign2,IdeaCamKey,static_dt08,72);
  	
  	memcpy (plainDT08RSA, static_dt08+8, 64);

	BN_CTX_free (ctx);
	//cs_debug("[nagra-reader] dt08 sign1: %s", cs_hexdump (0, signature, 8));
	//cs_debug("[nagra-reader] dt08 sign2: %s", cs_hexdump (0, sign2, 8));
	
	if (memcmp (signature, sign2, 8)==0)
	{
		cs_debug("[nagra-reader] DT08 signature check ok");
		hasMod=1;
	}
	else
	{
		cs_debug("[nagra-reader] DT08 signature check nok");
		hasMod=0;
	}  	
}
/*
int DumpDatatype(unsigned char dtbyte)
{
	static unsigned char cmd22[] = {0x21, 0x00, 0x09, 0xA0, 0xCA, 0x00, 0x00, 0x04, 0x22, 0x01, 0x01, 0x0E};
	int r;
	unsigned char dtactualsize;
	ushort chid;
      	char ds[16], de[16];
      	cmd22[0x0A] = dtbyte;

	while(1)
	{
		cmd22[0x0B] = 7;
        	 if( (do_cmd(0x22,0x03,0xa2,cmd22[0x0B],&cmd22[0x0A]))<=0 )
        	{
			cs_debug("[nagra-reader] DT read failed");
                	return 0;
		}
		dtactualsize = cta_res[2];
		if(!dtactualsize) break;

		cmd22[0x0A] = dtbyte | 0xC0;
		cmd22[0x0B] = dtactualsize + 3;
		if( (do_cmd(0x22,0x03,0xa2,cmd22[0x0B],&cmd22[0x0A]))<=0 )
        	{
			cs_debug("[nagra-reader] DT read failed");
			return 0;
		}
		cmd22[0x0A] = dtbyte | 0x80;
	}
	return 1;
}

int DumpDatatypes(void)
{
	int r;
	unsigned char dtbyte = 0;
	unsigned short dtflags;
	while(1)
	{
	        if( (do_cmd(0xc7,0x02,0xb7,0x04,NULL))<=0)
        	{
                	cs_debug("[nagra-reader] Determine updated DTs failed");
                	return 0;
        	}
		memcpy(&dtflags,cta_res+2,2);
		if(!dtflags)
			break;
		for(dtbyte; dtbyte < 16; dtbyte++)
			if(dtflags & (0x01 << dtbyte))
				if (!DumpDatatype(dtbyte)) break;
	}
	return 1;
}
*/
int ParseDataType(unsigned char dt)
{
	unsigned short irdProvId;
	switch(dt) 
	{
		case IRDINFO:
		{
     			irdProvId=(cta_res[10]*256)|cta_res[11];
     			reader[ridx].caid[0] =(SYSTEM_NAGRA|cta_res[11]);
     			memcpy(irdId,cta_res+14,4);
     			cs_debug("[nagra-reader] CAID: %04X, IRD ID: %s",reader[ridx].caid[0], cs_hexdump (1,irdId,4));
     			return 1;
     		}
   		case TIERS:
     			if(cta_res[7]==0x88 || cta_res[7]==0x08  || cta_res[7]==0x0C)
     			{
       				int id=(cta_res[10]*256)|cta_res[11];
       				int tLowId=(cta_res[20]*256)|cta_res[21];
       				int tHiId=(cta_res[31]*256)|cta_res[32];
       				char date1[15], time1[15], date2[15], time2[15];
       				Date(cta_res+23,date1,time1);
       				Date(cta_res+27,date2,time2);
       				cs_log("|%04X|%04X|%04X|%s|%s|",id,tLowId,tHiId,date1,time1);
       				cs_log("|    |    |    |%s|%s|",date2,time2);
       			}
       		case 0x08:
     		case 0x88: if (cta_res[11] == 0x49) decryptDT08();    			
       		default:
       			return 1;
   	}
  	return 0;
}

int GetDataType(unsigned char dt, int len, int shots)
{
	int i;
  	for(i=0; i<shots; i++)
  	{
  		if(!do_cmd(0x22,0x03,0xA2,len,&dt))
  		{
  			cs_debug("[nagra-reader] failed to get datatype %02X",dt);
  			return 0;
  		}
    		if(cta_res[2]==0) return 1;
    		if(!ParseDataType(dt&0x0F)) return 0;
    		if ((dt == CAMDATA) && (cta_res[11] == 0x49)) return 1; //got dt08 data	
    		dt|=0x80; // get next item
    	}
  	return 1;
}

int chk_caid(ushort caid, CAIDTAB *ctab)
{
	int n;
	for (n=0; (n<CS_MAXCAIDTAB); n++)
	if (caid == ctab->caid[n])
	{
		cs_debug("[nagra-reader] switching back to Betacrypt mode");
    		return 1;
    	}
    	return 0;
}
int setBaudrate(void)
{
#ifdef OS_LINUX
	if (reader[ridx].typ != R_INTERN) 
	{
	  	int bconst=B38400;
	  	int baud=115200;
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
	  	if(ioctl(fd,TIOCGSERIAL,&s)<0)
	  	{
	    		cs_log("%s: get serial failed: %s",reader[ridx].device,strerror(errno));
	    		return 0;
	    	}
	  	if(!tcsetattr(fd,TCSANOW,&tio))
	  	{
	      		if (reader[ridx].custom_speed) 
	      		{
	        	s.custom_divisor=(s.baud_base+(baud/2))/baud;
	        	s.flags=(s.flags&~ASYNC_SPD_MASK) | ASYNC_SPD_CUST;
	        	cs_log ("%s: custom: baud_base=%d baud=%d divisor=%d -> effective baudrate %d (%+.2f%% off)",
	                			reader[ridx].device,s.baud_base,baud,s.custom_divisor,s.baud_base/s.custom_divisor,
	                			(float)(s.baud_base/s.custom_divisor-baud)/(float)baud);
	      		}
	      		else
	      		{
	        		s.flags &= ~ASYNC_SPD_CUST;
	        		cs_log ("%s: baud=%d", reader[ridx].device, 38400);
	        	}
	      		if(ioctl(fd,TIOCSSERIAL,&s)<0)
	      		{
	        		cs_log ("%s: set serial failed: %s",reader[ridx].device,strerror(errno));
	        		return 0;
	        	}
	      	}
	  	else
	  	{
	    		cs_log ("%s: tcsetattr failed: %s",reader[ridx].device,strerror(errno));
	    		return 0;
	    	}
	}
#endif
	return 1;
}

int nagra2_card_init(uchar *atr, int atrlen)
{
	memset(rom, 0, 15);
	// hardcoded for testing only
	reader[ridx].nprov = 1;
	memset (reader[ridx].prid, 0, sizeof (reader[ridx].prid));
	memset (reader[ridx].sa, 0xFF, sizeof (reader[ridx].sa));
	reader[ridx].sa[0][3] = 0;
	reader[ridx].caid[0]=SYSTEM_NAGRA;
	
	if (memcmp(atr+11, "DNASP", 5)==0)
	{
		//if(SetIFS(0xFE) != 1) return 0;
		//if (!setBaudrate()) return 0;
		cs_debug("[nagra-reader] detect pure nagra card T1 protocol");
		is_pure_nagra=1;
		memcpy(rom,atr+11,15);
	}
	else if (!memcmp(atr+4, "IRDETO", 6))
	{
		cs_debug("[nagra-reader] support for non native nagra cards not finished Switching back to irdeto mode");
		return 0;
		/*
		cs_debug("[nagra-reader] detect tunneled nagra card T14 protocol");
		is_pure_nagra=0;
		if(!do_cmd(0x10,0x02,0x90,0x11,0))
		{
			cs_debug("[nagra-reader] get rom version failed");
			return 0;
		}
		memcpy(rom,cta_res+2,15);
		*/
	}
	else return 0;
	CamStateRequest();
	if(!do_cmd(0x12,0x02,0x92,0x06,0)) 
	{
		cs_debug("[nagra-reader] get Serial failed");
		return 0;
	}
	memcpy(reader[ridx].hexserial, cta_res+2, 4);
	cs_debug("[nagra-reader] SER:  %s", cs_hexdump (1, reader[ridx].hexserial, 4));
	
	if(!GetDataType(DT01,0x0E,MAX_REC)) return 0;
	cs_debug("[nagra-reader] DT01 DONE");
	if(!GetDataType(CAMDATA,0x55,10)) return 0;
	cs_debug("[nagra-reader] CAMDATA Done");

	if(!GetDataType(IRDINFO,0x39,MAX_REC)) return 0;
	cs_debug("[nagra-reader] IRDINFO DONE");
	/*
	if(!GetDataType(0x04,0x44,MAX_REC)) return 0;
	cs_debug("[nagra-reader] DT04 DONE");
	if(!GetDataType(TIERS,0x57,MAX_REC)) return 0;
	cs_debug("[nagra-reader] TIERS DONE");
	if(!GetDataType(DT06,0x16,MAX_REC)) return 0;
	cs_debug("[nagra-reader] DT06 DONE");
	*/
	if (!NegotiateSessionKey())
	{
		cs_debug("[nagra-reader] NegotiateSessionKey failed");
		return 0;
	}
	if (!CamStateRequest())
	{
		cs_debug("[nagra-reader] CamStateRequest failed");
		return 0;
	}
	return(1);
}

int nagra2_card_info(void)
{
	cs_log("ROM:  %c %c %c %c %c %c %c %c", rom[0], rom[1], rom[2],rom[3], rom[4], rom[5], rom[6], rom[7]);
	cs_log("REV:  %c %c %c %c %c %c %c", rom[8], rom[9], rom[10], rom[11], rom[12], rom[13], rom[14]);
	cs_log("SER:  %s", cs_hexdump (1, reader[ridx].hexserial, 4));
	cs_log("CAID: %04X",reader[ridx].caid[0]);
	cs_log("ready for requests"); 
	return(1);
}

int nagra2_do_ecm(ECM_REQUEST *er)
{
	if(!do_cmd(er->ecm[3],er->ecm[4]+2,0x87,0x02, er->ecm+3+2))
	{
		cs_debug("[nagra-reader] nagra2_do_ecm failed");
		return (0);
	}
	if (CamStateRequest() && HAS_CW && do_cmd(0x1C,0x02,0x9C,0x36,NULL))
	{
		unsigned char v[8];
		memset(v,0,sizeof(v));
		idea_cbc_encrypt(&cta_res[4],er->cw,8,&ksSession,v,IDEA_DECRYPT);
		memset(v,0,sizeof(v));
		idea_cbc_encrypt(&cta_res[30],er->cw+8,8,&ksSession,v,IDEA_DECRYPT);
		return (1);
	}
	return(0);
}
