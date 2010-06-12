#include "globals.h"
#include "reader-common.h"

#define CMD_LEN 5

static void RotateBytes1(unsigned char *out, unsigned char *in, int n)
{
  // loop is executed atleast once, so it's not a good idea to
  // call with n=0 !!
  out+=n;
  do { *(--out)=*(in++); } while(--n);
}

static void RotateBytes2(unsigned char *in, int n)
{
  // loop is executed atleast once, so it's not a good idea to
  // call with n=0 !!
  unsigned char *e=in+n-1;
  do
  {
    unsigned char temp=*in;
    *in++=*e;
    *e-- =temp;
  } while(in<e);
}

static int Input(BIGNUM *d, unsigned char *in, int n, int LE)
{
  if (LE)
  {
    unsigned char tmp[n];
    RotateBytes1(tmp,in,n);
    return(BN_bin2bn(tmp,n,d)!=0);
  }
  else
    return(BN_bin2bn(in,n,d)!=0);
}

static int Output(unsigned char *out, int n, BIGNUM *r, int LE)
{
  int s=BN_num_bytes(r);
  if (s>n)
  {
    unsigned char buff[s];
    cs_debug("[cryptoworks-reader] rsa: RSA len %d > %d, truncating", s, n);
    BN_bn2bin(r,buff);
    memcpy(out,buff+s-n,n);
  }
  else if (s<n)
  {
    int l=n-s;
    cs_debug("[cryptoworks-reader] rsa: RSA len %d < %d, padding", s, n);
    memset(out,0,l);
    BN_bn2bin(r,out+l);
  }
  else
    BN_bn2bin(r,out);
  if (LE)
    RotateBytes2(out,n);
  return(s);
}

static int RSA(unsigned char *out, unsigned char *in, int n, BIGNUM *exp, BIGNUM *mod, int LE)
{
  int rc=0;
  BN_CTX *ctx;
  BIGNUM *r, *d;
  ctx=BN_CTX_new();
  r=BN_new();
  d=BN_new();
  if (Input(d,in,n,LE))
  {
    if(BN_mod_exp(r,d,exp,mod,ctx))
      rc=Output(out,n,r,LE);
    else
      cs_log("[cryptoworks-reader] rsa: mod-exp failed");
  }
  BN_CTX_free(ctx);
  BN_free(d);
  BN_free(r);
  return(rc);
}

int CheckSctLen(const uchar *data, int off)
{
  int l=SCT_LEN(data);
  if (l+off > MAX_LEN)
  {
    cs_debug("[cryptoworks-reader] smartcard: section too long %d > %d", l, MAX_LEN-off);
    l=-1;
  }
  return(l);
}

static char *chid_date(uchar *ptr, char *buf, int l)
{
  if (buf)
  {
    snprintf(buf, l, "%04d/%02d/%02d",
                     1990+(ptr[0]>>1), ((ptr[0]&1)<<3)|(ptr[1]>>5), ptr[1]&0x1f);
  }
  return(buf);
}

static int select_file(struct s_reader * reader, uchar f1, uchar f2, uchar * cta_res, ushort * p_cta_lr)
{
  ushort cta_lr;
  uchar insA4[] = {0xA4, 0xA4, 0x00, 0x00, 0x02, 0x00, 0x00};
  insA4[5]=f1;
  insA4[6]=f2;
  write_cmd(insA4, insA4+5);	// select file
  *p_cta_lr = cta_lr;
  return((cta_res[0]==0x9f)&&(cta_res[1]==0x11));
}

static int read_record(struct s_reader * reader, uchar rec, uchar * cta_res)
{
  ushort cta_lr;
  uchar insA2[] = {0xA4, 0xA2, 0x00, 0x00, 0x01, 0x00};
  uchar insB2[] = {0xA4, 0xB2, 0x00, 0x00, 0x00};

  insA2[5]=rec;
  write_cmd(insA2, insA2+5);	// select record
  if (cta_res[0]!=0x9f)
    return(-1);
  insB2[4]=cta_res[1];		// get len
  write_cmd(insB2, NULL);	// read record
  if ((cta_res[cta_lr-2]!=0x90) || (cta_res[cta_lr-1]))
    return(-1);
  return(cta_lr-2);
}

/*
int cryptoworks_send_pin(struct s_reader * reader)
{
  unsigned char insPIN[] = { 0xA4, 0x20, 0x00, 0x00, 0x04, 0x00,0x00,0x00,0x00 }; //Verify PIN  
  
  if(reader->pincode[0] && (reader->pincode[0]&0xF0)==0x30)
  {
	  memcpy(insPIN+5,reader->pincode,4);
	
	  write_cmd(insPIN, insPIN+5);
	  cs_ri_log (reader, "sending pincode to card");  
	  if((cta_res[0]==0x98)&&(cta_res[1]==0x04)) cs_ri_log (reader, "bad pincode");
	  	 
	  return OK;
  }
  
  return(0);
}
*/

static int cryptoworks_disable_pin(struct s_reader * reader)
{
  def_resp;
  unsigned char insPIN[] = { 0xA4, 0x26, 0x00, 0x00, 0x04, 0x00,0x00,0x00,0x00 }; //disable PIN  
  
  if(reader->pincode[0] && (reader->pincode[0]&0xF0)==0x30)
  {
	  memcpy(insPIN+5,reader->pincode,4);
	
	  write_cmd(insPIN, insPIN+5);
	  cs_ri_log (reader, "disable pincode to card");
	  if((cta_res[0]==0x98)&&(cta_res[1]==0x04)) cs_ri_log (reader, "bad pincode");
	  return ERROR;
  }
  return OK;
}

int cryptoworks_card_init(struct s_reader * reader, ATR newatr)
{
  get_atr;
  def_resp;
  int i;
  unsigned int mfid=0x3F20;
  static uchar cwexp[] = { 1, 0 , 1};
  uchar insA4C[]= {0xA4, 0xC0, 0x00, 0x00, 0x11};
  uchar insB8[] = {0xA4, 0xB8, 0x00, 0x00, 0x0c};
  uchar issuerid=0;
  char issuer[20]={0};
  char *unknown="unknown", *pin=unknown, ptxt[CS_MAXPROV<<2]={0};

  if ((atr[6]!=0xC4) || (atr[9]!=0x8F) || (atr[10]!=0xF1)) return ERROR;

  cs_log("[cryptoworks-reader] card detected");
  cs_log("[cryptoworks-reader] type: CryptoWorks");

  reader->caid[0]=0xD00;
  reader->nprov=0;
  reader->ucpk_valid = 0;
  memset(reader->prid, 0, sizeof(reader->prid));

  write_cmd(insA4C, NULL);		// read masterfile-ID
  if ((cta_res[0]==0xDF) && (cta_res[1]>=6))
    mfid=(cta_res[6]<<8)|cta_res[7];

  select_file(reader, 0x3f, 0x20, cta_res, &cta_lr);
  insB8[2]=insB8[3]=0;		// first
  for(cta_res[0]=0xdf; cta_res[0]==0xdf;)
  {
    write_cmd(insB8, NULL);		// read provider id's
    if (cta_res[0]!=0xdf) break;
    if (((cta_res[4]&0x1f)==0x1f) && (reader->nprov<CS_MAXPROV))
    {
      sprintf(ptxt+strlen(ptxt), ",%02X", cta_res[5]);
      reader->prid[reader->nprov++][3]=cta_res[5];
    }
    insB8[2]=insB8[3]=0xff;	// next
  }
  for (i=reader->nprov; i<CS_MAXPROV; i++)
    memset(&reader->prid[i][0], 0xff, 4);

  select_file(reader, 0x2f, 0x01, cta_res, &cta_lr);		// read caid
  if (read_record(reader, 0xD1, cta_res)>=4)
    reader->caid[0]=(cta_res[2]<<8)|cta_res[3];

  if (read_record(reader, 0x80, cta_res)>=7)		// read serial
    memcpy(reader->hexserial, cta_res+2, 5);
  cs_ri_log (reader, "type: CryptoWorks, caid: %04X, ascii serial: %llu, hex serial: %s",
            reader->caid[0], b2ll(5, reader->hexserial),cs_hexdump(0, reader->hexserial, 5));

  if (read_record(reader, 0x9E, cta_res)>=66)	// read ISK
  {
    uchar keybuf[256];
    BIGNUM *ipk;
    if (search_boxkey(reader->caid[0], (char *)keybuf))
    {
      ipk=BN_new();
      BN_bin2bn(cwexp, sizeof(cwexp), &reader->exp);
      BN_bin2bn(keybuf, 64, ipk);
      RSA(cta_res+2, cta_res+2, 0x40, &reader->exp, ipk, 0);
      BN_free(ipk);
      reader->ucpk_valid =(cta_res[2]==((mfid & 0xFF)>>1));
      if (reader->ucpk_valid)
      {
        cta_res[2]|=0x80;
        BN_bin2bn(cta_res+2, 0x40, &reader->ucpk);
        cs_ddump(cta_res+2, 0x40, "IPK available -> session-key:");
      }
      else
      {
        reader->ucpk_valid =(keybuf[0]==(((mfid & 0xFF)>>1)|0x80));
        if (reader->ucpk_valid)
        {
          BN_bin2bn(keybuf, 0x40, &reader->ucpk);
          cs_ddump(keybuf, 0x40, "session-key found:");
        }
        else
          cs_log("[cryptoworks-reader] invalid IPK or session-key for CAID %04X !", reader->caid[0]);
      }
    }
  }
  if (read_record(reader, 0x9F, cta_res)>=3)
    issuerid=cta_res[2];
  if (read_record(reader, 0xC0, cta_res)>=16)
  {
    cs_strncpy(issuer, (const char *)cta_res+2, sizeof(issuer));
    trim(issuer);
  }
  else
    strcpy(issuer, unknown);

  select_file(reader, 0x3f, 0x20, cta_res, &cta_lr);
  select_file(reader, 0x2f, 0x11, cta_res, &cta_lr);		// read pin
  if (read_record(reader, atr[8], cta_res)>=7)
  {
    cta_res[6]=0;
    pin=(char *)cta_res+2;
  }
  cs_ri_log (reader, "issuer: %s, id: %02X, bios: v%d, pin: %s, mfid: %04X", issuer, issuerid, atr[7], pin, mfid);
  cs_ri_log (reader, "providers: %d (%s)", reader->nprov, ptxt+1);
  
  cryptoworks_disable_pin(reader);
  	
  return OK;
}

/*
#ifdef LALL
bool cSmartCardCryptoworks::Decode(const cEcmInfo *ecm, const unsigned char *data, unsigned char *cw)
{
  static unsigned char ins4c[] = { 0xA4,0x4C,0x00,0x00,0x00 };

  unsigned char nanoD4[10];
  int l=CheckSctLen(data,-5+(ucpkValid ? sizeof(nanoD4):0));
  if(l>5) {
    unsigned char buff[MAX_LEN];
    if(ucpkValid) {
      memcpy(buff,data,l);
      nanoD4[0]=0xD4;
      nanoD4[1]=0x08;
      for(unsigned int i=2; i<sizeof(nanoD4); i++) nanoD4[i]=rand();
      memcpy(&buff[l],nanoD4,sizeof(nanoD4));
      data=buff; l+=sizeof(nanoD4);
      }
    ins4c[3]=ucpkValid ? 2 : 0;
    ins4c[4]=l-5;
    if(IsoWrite(ins4c,&data[5]) && Status() &&
       (l=GetLen())>0 && ReadData(buff,l)==l) {
      int r=0;
      for(int i=0; i<l && r<2; ) {
        int n=buff[i+1];
        switch(buff[i]) {
          case 0x80:
            de(printf("smartcardcryptoworks: nano 80 (serial)\n"))
            break;
          case 0xD4:
            de(printf("smartcardcryptoworks: nano D4 (rand)\n"))
            if(n<8 || memcmp(&buff[i],nanoD4,sizeof(nanoD4)))
              di(printf("smartcardcryptoworks: random data check failed after decrypt\n"))
            break;
          case 0xDB: // CW
            de(printf("smartcardcryptoworks: nano DB (cw)\n"))
            if(n==0x10) {
              memcpy(cw,&buff[i+2],16);
              r|=1;
              }
            break;
          case 0xDF: // signature
            de(printf("smartcardcryptoworks: nano DF %02x (sig)\n",n))
            if(n==0x08) {
              if((buff[i+2]&0x50)==0x50 && !(buff[i+3]&0x01) && (buff[i+5]&0x80))
                r|=2;
              }
            else if(n==0x40) { // camcrypt
              if(ucpkValid) {
                RSA(&buff[i+2],&buff[i+2],n,exp,ucpk,false);
                de(printf("smartcardcryptoworks: after camcrypt "))
                de(HexDump(&buff[i+2],n))
                r=0; l=n-4; n=4;
                }
              else {
                di(printf("smartcardcryptoworks: valid UCPK needed for camcrypt!\n"))
                return false;
                }
              }
            break;
          default:
            de(printf("smartcardcryptoworks: nano %02x (unhandled)\n",buff[i]))
            break;
          }
        i+=n+2;
        }
      return r==3;
      }
    }
  return false;
}
#endif
*/

int cryptoworks_do_ecm(struct s_reader * reader, ECM_REQUEST *er)
{
  def_resp;
	int r=0;
  static unsigned char ins4C[] = { 0xA4,0x4C,0x00,0x00,0x00 };
  static unsigned char insC0[] = { 0xA4,0xC0,0x00,0x00,0x1C };
  unsigned char nanoD4[10];
  int secLen=CheckSctLen(er->ecm,-5+(reader->ucpk_valid ? sizeof(nanoD4):0));

  if(secLen>5)
  {
    int i;
    uchar *ecm=er->ecm;
    uchar buff[MAX_LEN];

    if(reader->ucpk_valid)
    {
      memcpy(buff,er->ecm,secLen);
      nanoD4[0]=0xD4;
      nanoD4[1]=0x08;
      for (i=2; i<(int)sizeof(nanoD4); i++)
        nanoD4[i]=rand();
      memcpy(&buff[secLen], nanoD4, sizeof(nanoD4));
      ecm=buff;
      secLen+=sizeof(nanoD4);
    }

    ins4C[3]=reader->ucpk_valid ? 2 : 0;
    ins4C[4]=secLen-5;
    write_cmd(ins4C, ecm+5);
    if (cta_res[cta_lr-2]==0x9f)
    {
      insC0[4]=cta_res[cta_lr-1];
      write_cmd(insC0, NULL);
      for(i=0; i<secLen && r<2; )
      {
        int n=cta_res[i+1];
        switch(cta_res[i])
	{
          case 0x80:
            cs_debug("[cryptoworks-reader] nano 80 (serial)");
            break;
          case 0xD4:
            cs_debug("[cryptoworks-reader] nano D4 (rand)");
            if(n<8 || memcmp(&cta_res[i],nanoD4,sizeof(nanoD4)))
              cs_debug("[cryptoworks-reader] random data check failed after decrypt");
            break;
          case 0xDB: // CW
            cs_debug("[cryptoworks-reader] nano DB (cw)");
            if(n==0x10)
            {
              memcpy(er->cw, &cta_res[i+2], 16);
              r|=1;
            }
            break;
          case 0xDF: // signature
            cs_debug("[cryptoworks-reader] nano DF %02x (sig)", n);
            if (n==0x08)
            {
              if((cta_res[i+2]&0x50)==0x50 && !(cta_res[i+3]&0x01) && (cta_res[i+5]&0x80))
                r|=2;
            }
            else if (n==0x40) // camcrypt
            {
              if(reader->ucpk_valid)
              {
                RSA(&cta_res[i+2],&cta_res[i+2], n, &reader->exp, &reader->ucpk, 0);
                cs_debug("[cryptoworks-reader] after camcrypt ");
                r=0; secLen=n-4; n=4;
              }
              else
              {
                cs_log("[cryptoworks-reader] valid UCPK needed for camcrypt!");
                return ERROR;
              }
            }
            break;
          default:
            cs_debug("[cryptoworks-reader] nano %02x (unhandled)",cta_res[i]);
            break;
        }
        i+=n+2;
      }
    }

/*
#ifdef LALL
    if ((cta_res[cta_lr-2]==0x9f)&&(cta_res[cta_lr-1]==0x1c))
    {
      write_cmd(insC0, NULL);
      if ((cta_lr>26)&&(cta_res[cta_lr-2]==0x90)&&(cta_res[cta_lr-1]==0))
      {
        if (rc=(((cta_res[20]&0x50)==0x50) && 
                (!(cta_res[21]&0x01)) && 
                (cta_res[23]&0x80)))
          memcpy(er->cw, cta_res+2, 16);
      }
    }
#endif
*/
  }
  //return(rc ? 1 : 0);
  return((r==3) ? 1 : 0);
}

int cryptoworks_get_emm_type(EMM_PACKET *ep, struct s_reader * rdr)
{
  char dumprdrserial[18];

  cs_debug_mask(D_EMM, "Entered cryptoworks_get_emm_type ep->emm[0]=%02x",ep->emm[0]);
  switch (ep->emm[0]) {
		case 0x82:
  	 		if(ep->emm[3]==0xA9 && ep->emm[4]==0xFF && ep->emm[13]==0x80 && ep->emm[14]==0x05) {
				ep->type = UNIQUE;
				memset(ep->hexserial, 0, 8);
				memcpy(ep->hexserial, ep->emm + 5, 5);
				strcpy(dumprdrserial, cs_hexdump(1, rdr->hexserial, 5));
				cs_debug_mask(D_EMM, "CRYPTOWORKS EMM: UNIQUE, ep = %s rdr = %s", 
					      cs_hexdump(1, ep->hexserial, 5), dumprdrserial);
				return (!memcmp(ep->emm + 5, rdr->hexserial, 5)); // check for serial
			}

		case 0x84:
	  	 	if(ep->emm[3]==0xA9 && ep->emm[4]==0xFF && ep->emm[12]==0x80 && ep->emm[13]==0x04) {
				ep->type = SHARED;
				memset(ep->hexserial, 0, 8);
				memcpy(ep->hexserial, ep->emm + 5, 4);
				strcpy(dumprdrserial, cs_hexdump(1, rdr->hexserial, 4));
				cs_debug_mask(D_EMM, "CRYPTOWORKS EMM: SHARED, ep = %s rdr = %s", 
					      cs_hexdump(1, ep->hexserial, 4), dumprdrserial);
				return (!memcmp(ep->emm + 5, rdr->hexserial, 4)); // check for SA
			}

		case 0x86:
			if(ep->emm[3]==0xA9 && ep->emm[4]==0xFF && ep->emm[5]==0x83 
			   && ep->emm[6]==0x01 && ep->emm[8]==0x85) {
				cs_debug_mask(D_EMM, "CRYPTOWORKS EMM: GLOBAL");
				ep->type = GLOBAL;
				return TRUE;
			}

		case 0x88:
		case 0x89:
  	 		if(ep->emm[3]==0xA9 && ep->emm[4]==0xFF && ep->emm[8]==0x83 && ep->emm[9]==0x01) {
				cs_debug_mask(D_EMM, "CRYPTOWORKS EMM: GLOBAL");
				ep->type = GLOBAL;
				return TRUE;
			}

		/* FIXME: Dont know how to handle camd3 cryptoworks emms correct */
		case 0x8F:
			ep->type = UNKNOWN;
			cs_debug_mask(D_EMM, "CRYPTOWORKS EMM: UNKNOWN 0x8F via camd3");
			return TRUE;

		/* FIXME: Seems to be that all other EMM types are rejected by the card */
		default: 
			ep->type = UNKNOWN;
			cs_debug_mask(D_EMM, "CRYPTOWORKS EMM: UNKNOWN");
			return FALSE; // skip emm
	}
}

void cryptoworks_get_emm_filter(struct s_reader * rdr, uchar *filter)
{
	filter[0]=0xFF;
	filter[1]=3;

	filter[2]=GLOBAL;
	filter[3]=0;

	filter[4+0]    = 0x88;
	filter[4+0+16] = 0xFE; // 0x88 to 0x89
	filter[4+1]    = 0xA9;
	filter[4+1+16] = 0xFF;
	filter[4+2]    = 0xFF;
	filter[4+2+16] = 0xFF;
	filter[4+6]    = 0x83;
	filter[4+6+16] = 0xFF;
	filter[4+7]    = 0x01;
	filter[4+7+16] = 0xFF;

	filter[36]=SHARED;
	filter[37]=0;

	filter[38+0]    = 0x84;
	filter[38+0+16] = 0xFF;
	filter[38+1]    = 0xA9;
	filter[38+1+16] = 0xFF;
	filter[38+2]    = 0xFF;
	filter[38+2+16] = 0xFF;
	memcpy(filter+38+3, rdr->hexserial, 4);
	memset(filter+38+3+16, 0xFF, 4);
	filter[38+10]    = 0x80;
	filter[38+10+16] = 0xFF;
	filter[38+11]    = 0x04;
	filter[38+11+16] = 0xFF;

	filter[70]=UNIQUE;
	filter[71]=0;

	filter[72+0]    = 0x82;
	filter[72+0+16] = 0xFF;
	filter[72+1]    = 0xA9;
	filter[72+1+16] = 0xFF;
	filter[72+2]    = 0xFF;
	filter[72+2+16] = 0xFF;
	memcpy(filter+72+3, rdr->hexserial, 5);
	memset(filter+72+3+16, 0xFF, 5);
	filter[72+11]    = 0x80;
	filter[72+11+16] = 0xFF;
	filter[72+12]    = 0x05;
	filter[72+12+16] = 0xFF;

	return;
}

int cryptoworks_do_emm(struct s_reader * reader, EMM_PACKET *ep)
{
  def_resp;
  uchar insEMM_GA[] = {0xA4, 0x44, 0x00, 0x00, 0x00};
  uchar insEMM_SA[] = {0xA4, 0x48, 0x00, 0x00, 0x00};
  uchar insEMM_UA[] = {0xA4, 0x42, 0x00, 0x00, 0x00};
  int rc=0;
  uchar *emm=ep->emm;
  
  /* FIXME: this is the original code how to deal with camd3 EMM's
  if ((emm[0]==0x8f) && (emm[3]==0xa4))		// emm via camd3.5x
  {    
    ep->type=emm[4];
    write_cmd(emm+3, emm+3+CMD_LEN);
    if ((cta_lr==2) && (cta_res[0]==0x90) && (cta_res[1]==0))
      rc=1;
  }
  */
   
  switch(ep->type)
  {
  	 // emm via camd3.5x
  	 case UNKNOWN:  	 	  
		  if(emm[3]==0xA4)
		  {		    
		    write_cmd(emm+3, emm+3+CMD_LEN);
		    rc=((cta_res[0]==0x90)&&(cta_res[1]==0x00));	
		  }
  	 	break;

  	 //GA    	 
  	 case GLOBAL:
				insEMM_GA[4]=ep->emm[2]-2;
				if(emm[7]==insEMM_GA[4]-3)
				{
					write_cmd(insEMM_GA, emm+5);
					rc=((cta_res[0]==0x90)&&(cta_res[1]==0x00));					
				}
  	 	break;
  	 
  	 //SA
  	 case SHARED:
				insEMM_SA[4]=ep->emm[2]-6;
				//if(emm[11]==insEMM_SA[4]-3)
				//{
					write_cmd(insEMM_SA, emm+9);
					rc=((cta_res[0]==0x90)&&(cta_res[1]==0x00));					
				//}
  	 	break;
  	 
  	 //UA	  	 
  	 case UNIQUE:
			insEMM_UA[4]=ep->emm[2]-7;
			if(emm[12]==insEMM_UA[4]-3)
			{
				//cryptoworks_send_pin(); //?? may be 
				write_cmd(insEMM_UA, emm+10);
				rc=((cta_res[0]==0x90)&&(cta_res[1]==0x00));					
			}
  	 	break;  	
  }

  return(rc);
}

int cryptoworks_card_info(struct s_reader * reader)
{
  def_resp;
	int i;
  uchar insA21[]= {0xA4, 0xA2, 0x01, 0x00, 0x05, 0x8C, 0x00, 0x00, 0x00, 0x00};
  uchar insB2[] = {0xA4, 0xB2, 0x00, 0x00, 0x00};
  char l_name[20+8]=", name: ";

  for (i=0; i<reader->nprov; i++)
  {
    l_name[8]=0;
    select_file(reader, 0x1f, reader->prid[i][3], cta_res, &cta_lr);	// select provider
    select_file(reader, 0x0e, 0x11, cta_res, &cta_lr);		// read provider name
    if (read_record(reader, 0xD6, cta_res)>=16)
    {
      cs_strncpy(l_name+8, (const char *)cta_res+2, sizeof(l_name)-9);
      l_name[sizeof(l_name)-1]=0;
      trim(l_name+8);
    }
    l_name[0]=(l_name[8]) ? ',' : 0;
    cs_ri_log (reader, "provider: %d, id: %02X%s", i+1, reader->prid[i][3], l_name);
    select_file(reader, 0x0f, 0x20, cta_res, &cta_lr);		// select provider class
    write_cmd(insA21, insA21+5);
    if (cta_res[0]==0x9f)
    {
      insB2[4]=cta_res[1];
      for(insB2[3]=0; (cta_res[0]!=0x94)||(cta_res[1]!=0x2); insB2[3]=1)
      {
        write_cmd(insB2, NULL);		// read chid
        if (cta_res[0]!=0x94)
        {
          char ds[16], de[16];
          chid_date(cta_res+28, ds, sizeof(ds)-1);
          chid_date(cta_res+30, de, sizeof(de)-1);
          cs_ri_log (reader, "chid: %02X%02X, date: %s - %s, name: %s",
                    cta_res[6], cta_res[7], ds, de, trim((char *) cta_res+10));
        }
      }
    }

    select_file(reader, 0x0f, 0x00, cta_res, &cta_lr);		// select provider channel 
    write_cmd(insA21, insA21+5);
    if (cta_res[0]==0x9f)
    {
      insB2[4]=cta_res[1];
      for(insB2[3]=0; (cta_res[0]!=0x94)||(cta_res[1]!=0x2); insB2[3]=1)
      {
        write_cmd(insB2, NULL);		// read chid
        if (cta_res[0]!=0x94)
        {
          char ds[16], de[16];
          chid_date(cta_res+28, ds, sizeof(ds)-1);
          chid_date(cta_res+30, de, sizeof(de)-1);
          cta_res[27]=0;
          cs_ri_log (reader, "chid: %02X%02X, date: %s - %s, name: %s",
                    cta_res[6], cta_res[7], ds, de, trim((char *)cta_res+10));
        }
      }
    }
  }
  cs_log("[cryptoworks-reader] ready for requests");
  return OK;
}
