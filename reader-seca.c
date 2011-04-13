#include "globals.h"
#include "reader-common.h"
#include <stdlib.h>

static int32_t set_provider_info(struct s_reader * reader, int32_t i)
{
  def_resp;
  uchar ins12[] = { 0xc1, 0x12, 0x00, 0x00, 0x19 }; // get provider info
  int32_t year, month, day;
  struct tm lt;
  time_t t;
  int32_t valid=0;//0=false, 1=true
  char l_name[16+8+1]=", name: ";

  ins12[2]=i;//select provider
  write_cmd(ins12, NULL); // show provider properties
  
  if ((cta_res[25] != 0x90) || (cta_res[26] != 0x00)) return ERROR;
  reader->prid[i][0]=0;
  reader->prid[i][1]=0;//blanken high byte provider code
  memcpy(&reader->prid[i][2], cta_res, 2);
  
  year = (cta_res[22]>>1) + 1990;
  month = ((cta_res[22]&0x1)<< 3) | (cta_res[23] >>5);
  day = (cta_res[23]&0x1f);
  t=time(NULL);
  localtime_r(&t, &lt);
  if (lt.tm_year + 1900 != year)
     valid = (lt.tm_year + 1900 < year);
  else if (lt.tm_mon + 1 != month)
     valid = (lt.tm_mon + 1 < month);
  else if (lt.tm_mday != day)
     valid = (lt.tm_mday < day);

  memcpy(l_name+8, cta_res+2, 16);
  l_name[sizeof(l_name)-1]=0;
  trim(l_name+8);
  l_name[0]=(l_name[8]) ? ',' : 0;
  reader->availkeys[i][0]=valid; //misusing availkeys to register validity of provider
  cs_ri_log (reader, "[seca-reader] provider: %d, valid: %i%s, expiry date: %4d/%02d/%02d",
         i+1, valid,l_name, year, month, day);
  memcpy(&reader->sa[i][0], cta_res+18, 4);
  if (valid==1) //if not expired
    cs_ri_log (reader, "[seca-reader] SA: %s", cs_hexdump(0, cta_res+18, 4));
  return OK;
}

static int32_t unlock_parental(struct s_reader * reader)
{
    // Unlock parental control
    // c1 30 00 01 09
    // 00 00 00 00 00 00 00 00 ff
    static const uchar ins30[] = { 0xc1, 0x30, 0x00, 0x01, 0x09 };
    static uchar ins30data[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff };

    def_resp;

    if (strcmp(reader->pincode, "none")) {
        cs_log("[seca-reader] Using PIN %s",reader->pincode);
        // the pin need to be coded in bcd, so we need to convert from ascii to bcd, so '1234' -> 0x12 0x34
        ins30data[6]=((reader->pincode[0]-0x30)<<4) | ((reader->pincode[1]-0x30) & 0x0f);
        ins30data[7]=((reader->pincode[2]-0x30)<<4) | ((reader->pincode[3]-0x30) & 0x0f);
    }
    else {
        cs_log("[seca-reader] Using PIN 0000!");
    }

    write_cmd(ins30, ins30data); 
    if( !(cta_res[cta_lr-2]==0x90 && cta_res[cta_lr-1]==0) ) {
        if (strcmp(reader->pincode, "none")) {
            cs_log("[seca-reader] Can't disable parental lock. Wrong PIN? OSCam used %s!",reader->pincode);
        }
        else {
            cs_log("[seca-reader] Can't disable parental lock. Wrong PIN? OSCam used 0000!");
        }
    }
    else
        cs_log("[seca-reader] Parental lock disabled");
    
    cs_debug_mask(D_READER, "[seca-reader] ins30_answer: %02x%02x",cta_res[0], cta_res[1]);
    return 0;
}

static int32_t seca_card_init(struct s_reader * reader, ATR newatr)
{
	get_atr;
	def_resp;
	char *card;
	uint16_t pmap=0;	// provider-maptable
	uint64_t serial ;
  uchar buf[256];
  static const uchar ins0e[] = { 0xc1, 0x0e, 0x00, 0x00, 0x08 }; // get serial number (UA)
  static const uchar ins16[] = { 0xc1, 0x16, 0x00, 0x00, 0x07 }; // get nr. of prividers
  int32_t i;


  buf[0]=0x00;
  if ((atr[10]!=0x0e) || (atr[11]!=0x6c) || (atr[12]!=0xb6) || (atr[13]!=0xd6)) return ERROR;
  switch(atr[7]<<8|atr[8])
  {
    case 0x5084: card="Generic"; break;
    case 0x5384: card="Philips"; break;
    case 0x5130:
    case 0x5430:
    case 0x5760: card="Thompson"; break;
    case 0x5284:
    case 0x5842:
    case 0x6060: card="Siemens"; break;
    case 0x7070: card="Canal+ NL"; break;
    default:     card="Unknown"; break;
  }
  reader->caid=0x0100;
  memset(reader->prid, 0xff, sizeof(reader->prid));
  write_cmd(ins0e, NULL); // read unique id
  memcpy(reader->hexserial, cta_res+2, 6);
  serial = b2ll(5, cta_res+3) ;
  cs_ri_log (reader, "type: SECA, caid: %04X, serial: %llu, card: %s v%d.%d",
         reader->caid, serial, card, atr[9]&0x0F, atr[9]>>4);
  write_cmd(ins16, NULL); // read nr of providers
  pmap=cta_res[2]<<8|cta_res[3];
  for (reader->nprov=0, i=pmap; i; i>>=1)
    reader->nprov+=i&1;
 
  for (i=0; i<16; i++)
    if (pmap&(1<<i))
    {
      if (set_provider_info(reader, i) == ERROR)
        return ERROR;
      else
	snprintf((char *) buf+strlen((char *)buf), sizeof(buf)-strlen((char *)buf), ",%04X", b2i(2, &reader->prid[i][2])); 
    }

  cs_ri_log (reader, "providers: %d (%s)", reader->nprov, buf+1);
// Unlock parental control
  if( cfg.ulparent != 0 ){
    unlock_parental(reader);
  }else {
	  cs_ri_log (reader, "[seca-reader] parental locked");
  }	
  cs_log("[seca-reader] ready for requests");
  return OK;
}

static int32_t get_prov_index(struct s_reader * rdr, char *provid)	//returns provider id or -1 if not found
{
  int32_t prov;
  for (prov=0; prov<rdr->nprov; prov++) //search for provider index
    if (!memcmp(provid, &rdr->prid[prov][2], 2))
      return(prov);
  return(-1);
}
	

static int32_t seca_do_ecm(struct s_reader * reader, ECM_REQUEST *er)
{
  def_resp;
  unsigned char ins3c[] = { 0xc1,0x3c,0x00,0x00,0x00 }; // coding cw
  unsigned char ins3a[] = { 0xc1,0x3a,0x00,0x00,0x10 }; // decoding cw
  int32_t i;
  i=get_prov_index(reader, (char *) er->ecm+3);
  if ((i == -1) || (reader->availkeys[i][0] == 0)) //if provider not found or expired
  {
      if( i == -1 )
        snprintf( er->msglog, MSGLOGSIZE, "provider not found" );
      else
        snprintf( er->msglog, MSGLOGSIZE, "provider expired" );

  	return ERROR;
  }

  ins3c[2]=i;
  ins3c[3]=er->ecm[7]; //key nr
  ins3c[4]=(((er->ecm[1]&0x0f) << 8) | er->ecm[2])-0x05;
 	int32_t try = 1;
 	int32_t ret;
  do {
    if (try > 1)
      snprintf( er->msglog, MSGLOGSIZE, "ins3c try nr %i", try);
    write_cmd(ins3c, er->ecm+8); //ecm request
    unsigned char ins30[] = { 0xC1, 0x30, 0x00, 0x02, 0x09 };
    unsigned char ins30data[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF };
    /* We need to use a token */
    if (cta_res[0] == 0x90 && cta_res[1] == 0x1a) {
      write_cmd(ins30, ins30data);
      write_cmd(ins3c, er->ecm+8); //ecm request
    }
    ret = ((cta_res[0] != 0x90) || (cta_res[1] != 0x00));
    if ((cta_res[0] == 0x93) && (cta_res[1] == 0x02)) {
      snprintf( er->msglog, MSGLOGSIZE, "%s unsubscribed", reader->label);
      break;
    }
    if (ret)
      snprintf( er->msglog, MSGLOGSIZE, "%s ins3c card response: %02x %02x", reader->label, cta_res[0] , cta_res[1] );
    try++;
  } while ((try < 3) && (ret));
  if (ret)
    return ERROR;
  
  write_cmd(ins3a, NULL); //get cw's
  if ((cta_res[16] != 0x90) || (cta_res[17] != 0x00)) { snprintf( er->msglog, MSGLOGSIZE, "ins3a card response: %02x %02x", cta_res[16] , cta_res[17] ); return ERROR; };//exit if response is not 90 00 //TODO: if response is 9027 ppv mode is possible!
  memcpy(er->cw,cta_res,16);
  return OK;
}

static int32_t seca_get_emm_type(EMM_PACKET *ep, struct s_reader * rdr) //returns TRUE if shared emm matches SA, unique emm matches serial, or global or unknown
{
	cs_debug_mask(D_EMM, "Entered seca_get_emm_type ep->emm[0]=%i",ep->emm[0]);
	int32_t i;
	switch (ep->emm[0]) {
		case 0x82:
			ep->type = UNIQUE;
			memset(ep->hexserial,0,8);
 			memcpy(ep->hexserial, ep->emm + 3, 6);
			cs_debug_mask(D_EMM, "SECA EMM: UNIQUE, ep->hexserial = %s", cs_hexdump(1, ep->hexserial, 6)); 
			cs_debug_mask(D_EMM, "SECA EMM: UNIQUE, rdr->hexserial = %s", cs_hexdump(1, rdr->hexserial, 6)); 
 			return (!memcmp (rdr->hexserial, ep->hexserial, 6));

		case 0x84:
			ep->type = SHARED;
			memset(ep->hexserial,0,8);
			memcpy(ep->hexserial, ep->emm + 5, 3); //dont include custom byte; this way the network also knows SA
			i=get_prov_index(rdr, (char *) ep->emm+3);
			cs_debug_mask(D_EMM, "SECA EMM: SHARED, ep->hexserial = %s", cs_hexdump(1, ep->hexserial, 3)); 
			if (i== -1) //provider not found on this card
				return FALSE; //do not pass this EMM
			cs_debug_mask(D_EMM, "SECA EMM: SHARED, rdr->sa[%i] = %s", i, cs_hexdump(1, rdr->sa[i], 3)); 
			return (!memcmp (rdr->sa[i], ep->hexserial, 3));

		// Unknown EMM types, but allready subbmited to dev's
		// FIXME: Drop EMM's until there are implemented
		case 0x83:
		/* 	EMM-G ?
			83 00 74 00 00 00 00 00 C4 7B E7 54 8D 25 8D 27
			CD 9C 87 4F B2 24 85 68 13 81 5E F1 EA AB 73 6D
			78 A2 86 F3 C9 4E 78 55 48 21 E4 A0 0B A0 54 3B
			5C 54 4B 01 39 1F FE C6 29 33 B8 6C 48 A0 9F 60
			47 EB 6A FC D3 CD 4B 9A 50 F2 05 80 66 F3 82 48
			22 EF E3 04 28 86 1D AB 82 26 9B 4D 09 B1 A8 F1
			1D D4 50 69 44 E8 94 04 91 5F 21 A2 3C 43 BC CB
			DD C1 90 AD 71 A7 38
		*/	
		case 0x88:
		case 0x89:
		// 	EMM-G ?
			ep->type = UNKNOWN;
			return FALSE;

		default:
			ep->type = UNKNOWN;
			return TRUE;
	}
}

static void seca_get_emm_filter(struct s_reader * rdr, uchar *filter)
{
	int32_t idx = 2;

	filter[0]=0xFF;
	filter[1]=0;

	filter[idx++]=EMM_UNIQUE;
	filter[idx++]=0;
	filter[idx+0]    = 0x82;
	filter[idx+0+16] = 0xFF;
	memcpy(filter+idx+1, rdr->hexserial, 6);
	memset(filter+idx+1+16, 0xFF, 6);
	filter[1]++;
	idx += 32;

	int32_t prov;
	for (prov=0; prov<rdr->nprov; prov++) {
		filter[idx++]=EMM_SHARED;
		filter[idx++]=0;
		filter[idx+0]    = 0x84;
		filter[idx+0+16] = 0xFF;
		memcpy(filter+idx+1, &rdr->prid[prov][2], 2);
		memset(filter+idx+1+16, 0xFF, 2);
		memcpy(filter+idx+3, &rdr->sa[prov], 3);
		memset(filter+idx+3+16, 0xFF, 3);
		filter[1]++;
		idx += 32;
		if (filter[1]>=10) {
			cs_log("seca_get_emm_filter: could not start all emm filter");
			break;
		}
	}

	return;
}

	
static int32_t seca_do_emm(struct s_reader * reader, EMM_PACKET *ep)
{
  def_resp;
  unsigned char ins40[] = { 0xc1,0x40,0x00,0x00,0x00 };
  int32_t i,ins40data_offset;
  int32_t emm_length = ((ep->emm[1] & 0x0f) << 8) + ep->emm[2];
  char *prov_id_ptr;

  cs_ddump_mask (D_EMM, ep->emm, emm_length + 3, "EMM:");
  switch (ep->type) {
		case SHARED:
			ins40[3]=ep->emm[9];
			ins40[4]= emm_length - 0x07;
			ins40data_offset = 10;
			prov_id_ptr = (char *)ep->emm+3;
			break;

		case UNIQUE:	
			ins40[3]=ep->emm[12];
			ins40[4]= emm_length - 0x0A;
			ins40data_offset = 13;
			prov_id_ptr = (char *)ep->emm+9;
			break;

		default:
    			cs_log("[seca-reader] EMM: Congratulations, you have discovered a new EMM on SECA.");
			cs_log("This has not been decoded yet, so send this output to authors:");
			cs_dump (ep->emm, emm_length + 3, "EMM:");
			return ERROR;
  }

  i=get_prov_index(reader, prov_id_ptr);
  if (i==-1) 
  {
      cs_log("[seca-reader] EMM: provider id not found.");
    return ERROR;
  }

  ins40[2]=(ep->emm[ins40data_offset-2] & 0xF0) | (i & 0x0F);
  write_cmd(ins40, ep->emm + ins40data_offset); //emm request
  if (cta_res[0] == 0x97) {
	 if (!(cta_res[1] & 4)) // date updated
	 	set_provider_info(reader, i);
	 else
	 	cs_log("[seca-reader] EMM: Update not necessary.");
	 return OK; //Update not necessary
  }
  if ((cta_res[0] == 0x90) && ((cta_res[1] == 0x00) || (cta_res[1] == 0x19)))
  	if (set_provider_info(reader, i) == OK) //after successfull EMM, print32_t new provider info
	  return OK;
  return ERROR;
}

static int32_t seca_card_info (struct s_reader * reader)
{
//SECA Package BitMap records (PBM) can be used to determine whether the channel is part of the package that the SECA card can decrypt. This module reads the PBM
//from the SECA card. It cannot be used to check the channel, because this information seems to reside in the CA-descriptor, which seems not to be passed on through servers like camd, newcamd, radegast etc.
//
//This module is therefore optical only

  def_resp;
  static const unsigned char ins34[] = { 0xc1, 0x34, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00 };				//data following is provider Package Bitmap Records
  unsigned char ins32[] = { 0xc1, 0x32, 0x00, 0x00, 0x20 };				// get PBM
  int32_t prov;

  for (prov = 0; prov < reader->nprov; prov++) {
    ins32[2] = prov;
    write_cmd (ins34, ins34 + 5);	//prepare card for pbm request
    write_cmd (ins32, NULL);	//pbm request
    uchar pbm[8];		//TODO should be arrayed per prov
    switch (cta_res[0]) {
    case 0x04:
      cs_ri_log (reader, "[seca-reader] no PBM for provider %i", prov + 1);
      break;
    case 0x83:
      memcpy (pbm, cta_res + 1, 8);
      cs_ri_log (reader, "[seca-reader] PBM for provider %i: %s", prov + 1, cs_hexdump (0, pbm, 8));
      break;
    default:
      cs_log ("[seca-reader] ERROR: PBM returns unknown byte %02x", cta_res[0]);
    }
  }
  return OK;
}

void reader_seca(struct s_cardsystem *ph) 
{
	ph->do_emm=seca_do_emm;
	ph->do_ecm=seca_do_ecm;
	ph->card_info=seca_card_info;
	ph->card_init=seca_card_init;
	ph->get_emm_type=seca_get_emm_type;
	ph->get_emm_filter=seca_get_emm_filter;
	ph->caids[0]=0x01;
	ph->desc="seca";
}
