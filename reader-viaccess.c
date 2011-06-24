#include "globals.h"
#include "reader-common.h"

struct via_date {
	uint16_t day_s   : 5;
	uint16_t month_s : 4;
	uint16_t year_s  : 7;

	uint16_t day_e   : 5;
	uint16_t month_e : 4;
	uint16_t year_e  : 7;
};

static void parse_via_date(const uchar *buf, struct via_date *vd, int32_t fend)
{
	uint16_t date;

	date = (buf[0]<<8) | buf[1];
	vd->day_s   = date & 0x1f;
	vd->month_s = (date>>5) & 0x0f;
	vd->year_s  = (date>>9) & 0x7f;

	if( fend )
	{
		date = (buf[2]<<8) | buf[3];
		vd->day_e   = date & 0x1f;
		vd->month_e = (date>>5) & 0x0f;
		vd->year_e  = (date>>9) & 0x7f;
	}
}

static void show_class(struct s_reader * reader, const char *p, const uchar *b, int32_t l)
{
	int32_t i, j;

	// b -> via date (4 bytes)
	b+=4;
	l-=4;

	j=l-1;
	for (; j>=0; j--)
		for (i=0; i<8; i++)
			if (b[j] & (1 << (i&7)))
			{
				uchar cls;
				struct via_date vd;
				parse_via_date(b-4, &vd, 1);
				cls=(l-(j+1))*8+i;
				if (p)
					cs_log("%sclass: %02X, expiry date: %04d/%02d/%02d - %04d/%02d/%02d", p, cls, 
					vd.year_s+1980, vd.month_s, vd.day_s,
					vd.year_e+1980, vd.month_e, vd.day_e);
				else
					cs_ri_log(reader, "class: %02X, expiry date: %04d/%02d/%02d - %04d/%02d/%02d", cls, 
					vd.year_s+1980, vd.month_s, vd.day_s,
					vd.year_e+1980, vd.month_e, vd.day_e);
			}
}

static void show_subs(struct s_reader * reader, const uchar *emm)
{  
	// emm -> A9, A6, B6

	switch( emm[0] )
	{
	case 0xA9:
		show_class(reader, "nano A9: ", emm+2, emm[1]);
		break;
		/*
		{
		int32_t i, j, byts;
		const uchar *oemm;

		oemm = emm;
		byts = emm[1]-4;
		emm+=6;

		j=byts-1;
		for( ; j>=0; j-- )
		for( i=0; i<8; i++ )
		if( emm[j] & (1 << (i&7)) )
		{
		uchar cls;
		struct via_date vd;
		parse_via_date(emm-4, &vd, 1);
		cls=(byts-(j+1))*8+i;
		cs_log("%sclass %02X: expiry date: %02d/%02d/%04d - %02d/%02d/%04d",
		fnano?"nano A9: ":"", cls, 
		vd.day_s, vd.month_s, vd.year_s+1980, 
		vd.day_e, vd.month_e, vd.year_e+1980);
		}
		break;
		}
		*/
	case 0xA6:
		{
			char szGeo[256];

			memset(szGeo, 0, 256);
			strncpy(szGeo, (char *)emm+2, emm[1]);
			cs_log("[viaccess-reader] nano A6: geo %s", szGeo);
			break;
		}
	case 0xB6:
		{
			uchar m; // modexp
			struct via_date vd;

			m=emm[emm[1]+1];
			parse_via_date(emm+2, &vd, 0);
			cs_log("[viaccess-reader] nano B6: modexp %d%d%d%d%d%d: %02d/%02d/%04d", (m&0x20)?1:0, 
				(m&0x10)?1:0,(m&0x08)?1:0,(m&0x04)?1:0,(m&0x02)?1:0,(m&0x01)?1:0,
				vd.day_s, vd.month_s, vd.year_s+1980);
			break;
		}
	}
}

static int32_t chk_prov(struct s_reader * reader, uchar *id, uchar keynr)
{
	int32_t i, j, rc;
	for (rc=i=0; (!rc) && (i<reader->nprov); i++)
		if(!memcmp(&reader->prid[i][1], id, 3))
			for (j=0; (!rc) && (j<16); j++)
				if (reader->availkeys[i][j]==keynr)
					rc=1;
	return(rc);
}

static int32_t unlock_parental(struct s_reader * reader)
{
	/* disabling parental lock. assuming pin "0000" if no pin code is provided in the config */

	static const uchar inDPL[] = {0xca, 0x24, 0x02, 0x00, 0x09};
	uchar cmDPL[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0F};
	def_resp;

	if (strcmp(reader->pincode, "none")) {
		cs_log("[viaccess-reader] Using PIN %s",reader->pincode);
		// the pin need to be coded in bcd, so we need to convert from ascii to bcd, so '1234' -> 0x12 0x34
		cmDPL[6]=((reader->pincode[0]-0x30)<<4) | ((reader->pincode[1]-0x30) & 0x0f);
		cmDPL[7]=((reader->pincode[2]-0x30)<<4) | ((reader->pincode[3]-0x30) & 0x0f);
	}
	else {
		cs_log("[viaccess-reader] Using PIN 0000!");
	}
	write_cmd(inDPL,cmDPL);
	if( !(cta_res[cta_lr-2]==0x90 && cta_res[cta_lr-1]==0) ) {
		if (strcmp(reader->pincode, "none")) {
			cs_log("[viaccess-reader] Can't disable parental lock. Wrong PIN? OSCam used %s!",reader->pincode);
		}
		else {
			cs_log("[viaccess-reader] Can't disable parental lock. Wrong PIN? OSCam used 0000!");
		}
	}
	else
		cs_log("[viaccess-reader] Parental lock disabled");

	return 0;
}

static int32_t viaccess_card_init(struct s_reader * reader, ATR newatr)
{
	get_atr;
	def_resp;
	int32_t i;
	uchar buf[256];
	uchar insac[] = { 0xca, 0xac, 0x00, 0x00, 0x00 }; // select data
	uchar insb8[] = { 0xca, 0xb8, 0x00, 0x00, 0x00 }; // read selected data
	uchar insa4[] = { 0xca, 0xa4, 0x00, 0x00, 0x00 }; // select issuer
	uchar insc0[] = { 0xca, 0xc0, 0x00, 0x00, 0x00 }; // read data item
	static const uchar insFAC[] = { 0x87, 0x02, 0x00, 0x00, 0x03 }; // init FAC
	static const uchar FacDat[] = { 0x00, 0x00, 0x28 };
	static unsigned char ins8702_data[] = { 0x00, 0x00, 0x11};
	static unsigned char ins8704[] = { 0x87, 0x04, 0x00, 0x00, 0x07 };
	static unsigned char ins8706[] = { 0x87, 0x06, 0x00, 0x00, 0x04 };


	if ((atr[1]!=0x77) || ((atr[2]!=0x18) && (atr[2]!=0x11) && (atr[2]!=0x19)) || (atr[9]!=0x68)) 
		return ERROR;

	write_cmd(insFAC, FacDat);
	if( !(cta_res[cta_lr-2]==0x90 && cta_res[cta_lr-1]==0) )
		return ERROR;

	memset(&reader->last_geo, 0, sizeof(reader->last_geo));
	write_cmd(insFAC, ins8702_data);
	if ((cta_res[cta_lr-2]==0x90) && (cta_res[cta_lr-1]==0x00)) {
		write_cmd(ins8704, NULL);
		if ((cta_res[cta_lr-2]==0x90) && (cta_res[cta_lr-1]==0x00)) {
			write_cmd(ins8706, NULL);
			if ((cta_res[cta_lr-2]==0x90) && (cta_res[cta_lr-1]==0x00)) {
				reader->last_geo.number_ecm =(cta_res[2]<<8) | (cta_res[3]);
				cs_log("[viaccess-reader] using ecm #%x for long viaccess ecm",reader->last_geo.number_ecm);
			}
		}
	}


	//  switch((atr[atrsize-4]<<8)|atr[atrsize-3])
	//  {
	//    case 0x6268: ver="2.3"; break;
	//    case 0x6668: ver="2.4(?)"; break;
	//    case 0xa268:
	//    default: ver="unknown"; break;
	//  }

	reader->caid=0x500;
	memset(reader->prid, 0xff, sizeof(reader->prid));
	insac[2]=0xa4; write_cmd(insac, NULL); // request unique id
	insb8[4]=0x07; write_cmd(insb8, NULL); // read unique id
	memcpy(reader->hexserial, cta_res+2, 5);
	//  cs_log("[viaccess-reader] type: Viaccess, ver: %s serial: %llu", ver, b2ll(5, cta_res+2));
	cs_ri_log(reader, "type: Viaccess (%sstandard atr), caid: %04X, serial: %llu",
		atr[9]==0x68?"":"non-",reader->caid, b2ll(5, cta_res+2));

	i=0;
	insa4[2]=0x00; write_cmd(insa4, NULL); // select issuer 0
	buf[0]=0;
	while((cta_res[cta_lr-2]==0x90) && (cta_res[cta_lr-1]==0))
	{
		insc0[4]=0x1a; write_cmd(insc0, NULL); // show provider properties
		cta_res[2]&=0xF0;
		reader->prid[i][0]=0;
		memcpy(&reader->prid[i][1], cta_res, 3);
		memcpy(&reader->availkeys[i][0], cta_res+10, 16);
		snprintf((char *)buf+strlen((char *)buf), sizeof(buf)-strlen((char *)buf), ",%06X", b2i(3, &reader->prid[i][1]));
		//cs_log("[viaccess-reader] buf: %s", buf);

		insac[2]=0xa5; write_cmd(insac, NULL); // request sa
		insb8[4]=0x06; write_cmd(insb8, NULL); // read sa
		memcpy(&reader->sa[i][0], cta_res+2, 4);

		/*
		insac[2]=0xa7; write_cmd(insac, NULL); // request name
		insb8[4]=0x02; write_cmd(insb8, NULL); // read name nano + len
		l=cta_res[1];
		insb8[4]=l; write_cmd(insb8, NULL); // read name
		cta_res[l]=0;
		cs_log("[viaccess-reader] name: %s", cta_res);
		*/

		insa4[2]=0x02;
		write_cmd(insa4, NULL); // select next issuer
		i++;
	}
	reader->nprov=i;
	cs_ri_log(reader, "providers: %d (%s)", reader->nprov, buf+1);

	if (cfg.ulparent)
		unlock_parental(reader);

	cs_log("[viaccess-reader] ready for requests");
	return OK;
}

bool dcw_crc(uchar *dw){
	int i;
	for(i=0;i<16;i+=4) if(dw[i+3]!=dw[i]+dw[i+1]+dw[i+2])return 0;
	return 1;
}

static int32_t viaccess_do_ecm(struct s_reader * reader, ECM_REQUEST *er)
{
	def_resp;
	static const unsigned char insa4[] = { 0xca,0xa4,0x04,0x00,0x03 }; // set provider id
	unsigned char ins88[] = { 0xca,0x88,0x00,0x00,0x00 }; // set ecm
	unsigned char insf8[] = { 0xca,0xf8,0x00,0x00,0x00 }; // set geographic info 
	static const unsigned char insc0[] = { 0xca,0xc0,0x00,0x00,0x12 }; // read dcw

	uchar *ecm88Data=er->ecm+4; //XXX what is the 4th byte for ??
	int32_t ecm88Len=SCT_LEN(er->ecm)-4;
	uint32_t provid=0;
	int32_t rc=0;
	int32_t hasD2 = 0;
	int32_t curEcm88len=0;
	int32_t nanoLen=0;
	uchar *nextEcm;
	uchar DE04[256];
	int32_t D2KeyID=0;
	int32_t curnumber_ecm=0;
	//nanoD2 d2 02 0d 02 -> D2 nano, len 2
	// 0d -> post AES decrypt CW
	// 0b -> pre AES decrypt CW
	int32_t nanoD2 = 0; //   0x0b = 1  0x0d = 2

	memset(DE04, 0, sizeof(DE04)); //fix dorcel de04 bug

	nextEcm=ecm88Data;

		//detecte nano E0
	while (ecm88Len)
	{
		// 80 33 nano 80 (ecm) + len (33)
		if(ecm88Data[0]==0x80) { // nano 80, give ecm len
			curEcm88len=ecm88Data[1];
			nextEcm=ecm88Data+curEcm88len+2;
			ecm88Data += 2;
			ecm88Len -= 2;

			if (ecm88Data[0]==0x90  && ecm88Data[1]==0x07)
			{
				curnumber_ecm =(ecm88Data[6]<<8) | (ecm88Data[7]);
				//if number_ecm & nano E0 ecm  not suported
				if ((reader->last_geo.number_ecm == curnumber_ecm )&&(ecm88Data[9] == 0xE0))
				{
					cs_log("[viaccess-reader] ECM: Invalid ECM nano E0 Rejecting");
					return ERROR;
				}
			}
			ecm88Data=nextEcm;
			ecm88Len-=curEcm88len;
			continue; //loop to next ecm
		} else  ecm88Len = 0; //exit while
	}

	//return original parametre
	ecm88Data=er->ecm+4; //XXX what is the 4th byte for ??
	ecm88Len=SCT_LEN(er->ecm)-4;
	curEcm88len=0;
	nextEcm=ecm88Data;

	while (ecm88Len && !rc) {

		if(ecm88Data[0] ==0x00 &&  ecm88Data[1] == 0x00) {
			// nano 0x00  and len 0x00 aren't valid ... something is obviously wrong with this ecm.
			cs_log("[viaccess-reader] ECM: Invalid ECM structure. Rejecting");
			return ERROR;
		}

		// 80 33 nano 80 (ecm) + len (33)
		if(ecm88Data[0]==0x80) { // nano 80, give ecm len
			curEcm88len=ecm88Data[1];
			nextEcm=ecm88Data+curEcm88len+2;
			ecm88Data += 2;
			ecm88Len -= 2;
		}

		if(!curEcm88len) { //there was no nano 80 -> simple ecm
			curEcm88len=ecm88Len;
		}

		// d2 02 0d 02 -> D2 nano, len 2,  select the AES key to be used
		if(ecm88Data[0]==0xd2) {
			// test if need post or pre AES decrypt
			if(ecm88Data[2]==0x0b)
			{
				nanoD2 = 1;
				cs_debug_mask(D_READER, "[viaccess-reader] ECM: nano D2 0x0b");
			}
			if(ecm88Data[2]==0x0d)
			{
				nanoD2 = 2;
				cs_debug_mask(D_READER, "[viaccess-reader] ECM: nano D2 0x0d");
			}
			// use the d2 arguments to get the key # to be used
			int32_t len = ecm88Data[1] + 2;
			D2KeyID=ecm88Data[3];
			ecm88Data += len;
			ecm88Len -= len;
			curEcm88len -=len;
			hasD2 = 1;
		}
		else
			hasD2 = 0;


		// 40 07 03 0b 00  -> nano 40, len =7  ident 030B00 (tntsat), key #0  <== we're pointing here
		// 09 -> use key #9 
		// 05 67 00
		if ((ecm88Data[0]==0x90 || ecm88Data[0]==0x40) && (ecm88Data[1]==0x03 || ecm88Data[1]==0x07 ) )
		{
			uchar ident[3], keynr;
			uchar *ecmf8Data=0;
			int32_t ecmf8Len=0;

			nanoLen=ecm88Data[1] + 2;
			keynr=ecm88Data[4]&0x0F;        

			// 40 07 03 0b 00  -> nano 40, len =7  ident 030B00 (tntsat), key #0  <== we're pointing here
			// 09 -> use key #9 
			if(nanoLen>5) {
				curnumber_ecm =(ecm88Data[6]<<8) | (ecm88Data[7]);
				cs_debug_mask(D_READER, "checking if the ecm number (%x) match the card one (%x)",curnumber_ecm,reader->last_geo.number_ecm);
				// if we have an ecm number we check it.
				// we can't assume that if the nano len is 5 or more we have an ecm number
				// as some card don't support this
				//force use ecm 00 provider 030B00 & 032920 & 032940
				if( reader->last_geo.number_ecm > 0 ) 
				{ 
					if(ecm88Data[2] == 0x03 && ((ecm88Data[3] == 0x0B && ecm88Data[4] == 0x00)||
						                        (ecm88Data[3] == 0x29 && ecm88Data[4] == 0x20)||
												(ecm88Data[3] == 0x29 && ecm88Data[4] == 0x40)))
					{
						if (reader->last_geo.number_ecm == curnumber_ecm && !( ecm88Data[nanoLen-1] == 0x01 )) //ecm 00
						{
							keynr=ecm88Data[5];
							cs_debug_mask(D_READER, "keyToUse = %02x, ECM ending with %02x",ecm88Data[5], ecm88Data[nanoLen-1]);
						} 
						else 
						{
							// ecm 01
							if( ecm88Data[nanoLen-1] == 0x01 )
							{
								cs_debug_mask(D_READER, "Skip ECM ending with = %02x for ecm number (%x) for provider %02x%02x%02x",ecm88Data[nanoLen-1], curnumber_ecm, ecm88Data[2], ecm88Data[3], ecm88Data[4]);
							}
							cs_debug_mask(D_READER, "Skip ECM ending with = %02x for ecm number (%x)",ecm88Data[nanoLen-1], curnumber_ecm);
							ecm88Data=nextEcm;
							ecm88Len-=curEcm88len;
							continue; //loop to next ecm
						}
					}
				}
				else { // long ecm but we don't have an ecm number so we have to try them all.
					keynr=ecm88Data[5];
					cs_debug_mask(D_READER, "keyToUse = %02x",ecm88Data[5]);
				}
			}

			memcpy (ident, &ecm88Data[2], sizeof(ident));
			provid = b2i(3, ident);
			ident[2]&=0xF0;

			if(hasD2 && reader->aes_list) {
				// check that we have the AES key to decode the CW
				// if not there is no need to send the ecm to the card
				if(!aes_present(reader->aes_list, 0x500, (uint32_t) (provid & 0xFFFFF0) , D2KeyID))
					return ERROR;
			}


			if (!chk_prov(reader, ident, keynr))
			{
				cs_debug_mask(D_READER, "[viaccess-reader] ECM: provider or key not found on card");
				snprintf( er->msglog, MSGLOGSIZE, "provider(%02x%02x%02x) or key(%d) not found on card", ident[0],ident[1],ident[2], keynr );
				return ERROR;
			}

			ecm88Data+=nanoLen;
			ecm88Len-=nanoLen;
			curEcm88len-=nanoLen;

			// DE04
			if (ecm88Data[0]==0xDE && ecm88Data[1]==0x04)
			{
				memcpy (DE04, &ecm88Data[0], 6);
				ecm88Data+=6;
			}
			//

			if( reader->last_geo.provid != provid ) 
			{
				reader->last_geo.provid = provid;
				reader->last_geo.geo_len = 0;
				reader->last_geo.geo[0]  = 0;
				write_cmd(insa4, ident); // set provider
			}

			//Nano D2 0x0b Pre AES decrypt CW        
			if ( hasD2 && nanoD2 == 1) 
			{
				uchar *ecm88DataCW = ecm88Data;
				int32_t cwStart = 0;
				//int32_t cwStartRes = 0;
				int32_t exit = 0;
				// find CW start
				while(cwStart < curEcm88len -1 && !exit)
				{
					if(ecm88Data[cwStart] == 0xEA && ecm88Data[cwStart+1] == 0x10)
					{
						ecm88DataCW = ecm88DataCW + cwStart + 2;
						exit = 1;
					}
					cwStart++;
				} 
				// use AES from list to decrypt CW
				cs_debug_mask(D_READER, "Decoding CW : using AES key id %d for provider %06x",D2KeyID, (provid & 0xFFFFF0));
				if (aes_decrypt_from_list(reader->aes_list,0x500, (uint32_t) (provid & 0xFFFFF0), D2KeyID, &ecm88DataCW[0], 16) == 0)
					snprintf( er->msglog, MSGLOGSIZE, "AES Decrypt : key id %d not found for CAID %04X , provider %06x", D2KeyID, 0x500, (provid & 0xFFFFF0) );
			}

			while(ecm88Len>0 && ecm88Data[0]<0xA0)
			{
				int32_t nanoLen=ecm88Data[1]+2;
				if (!ecmf8Data)
					ecmf8Data=(uchar *)ecm88Data;
				ecmf8Len+=nanoLen;
				ecm88Len-=nanoLen;
				curEcm88len-=nanoLen;
				ecm88Data+=nanoLen;
			}
			if(ecmf8Len)
			{
				if( reader->last_geo.geo_len!=ecmf8Len || 
					memcmp(reader->last_geo.geo, ecmf8Data, reader->last_geo.geo_len))
				{
					memcpy(reader->last_geo.geo, ecmf8Data, ecmf8Len);
					reader->last_geo.geo_len= ecmf8Len;
					insf8[3]=keynr;
					insf8[4]=ecmf8Len;
					write_cmd(insf8, ecmf8Data);
				}
			}
			ins88[2]=ecmf8Len?1:0;
			ins88[3]=keynr;
			ins88[4]= curEcm88len;
			// 
			// we should check the nano to make sure the ecm is valid
			// we should look for at least 1 E3 nano, 1 EA nano and the F0 signature nano
			//
			// DE04
			if (DE04[0]==0xDE)
			{
				memcpy(DE04+6, (uchar *)ecm88Data, curEcm88len-6);
				write_cmd(ins88, DE04); // request dcw
			}
			else
			{
				write_cmd(ins88, (uchar *)ecm88Data); // request dcw
			}
			//
			write_cmd(insc0, NULL);	// read dcw
			switch(cta_res[0])
			{
			case 0xe8: // even
				if(cta_res[1]==8) { memcpy(er->cw,cta_res+2,8); rc=1; }
				break;
			case 0xe9: // odd
				if(cta_res[1]==8) { memcpy(er->cw+8,cta_res+2,8); rc=1; }
				break;
			case 0xea: // complete
				if(cta_res[1]==16) { memcpy(er->cw,cta_res+2,16); rc=1; }
				break;
			default :
				ecm88Data=nextEcm;
				ecm88Len-=curEcm88len;
				cs_debug_mask(D_READER, "[viaccess-reader] ECM: key to use is not the current one, trying next ECM");
				snprintf( er->msglog, MSGLOGSIZE, "key to use is not the current one, trying next ECM" );
			}
		}
		else {
			ecm88Data=nextEcm;
			ecm88Len-=curEcm88len;
			cs_debug_mask(D_READER, "[viaccess-reader] ECM: Unknown ECM type");
			snprintf( er->msglog, MSGLOGSIZE, "Unknown ECM type" );
		}
	}

	if ( hasD2 && !dcw_crc(er->cw) && nanoD2 == 2) {
		cs_debug_mask(D_READER, "Decoding CW : using AES key id %d for provider %06x",D2KeyID, (provid & 0xFFFFF0));
		rc=aes_decrypt_from_list(reader->aes_list,0x500, (uint32_t) (provid & 0xFFFFF0), D2KeyID,er->cw, 16);
		if( rc == 0 )
			snprintf( er->msglog, MSGLOGSIZE, "AES Decrypt : key id %d not found for CAID %04X , provider %06x", D2KeyID, 0x500, (provid & 0xFFFFF0) );
	}

	return(rc?OK:ERROR);
}

static int32_t viaccess_get_emm_type(EMM_PACKET *ep, struct s_reader * rdr)
{
	uint32_t provid=0;
	cs_debug_mask(D_EMM, "Entered viaccess_get_emm_type ep->emm[0]=%02x",ep->emm[0]);

	if (ep->emm[3] == 0x90 && ep->emm[4] == 0x03) {
		provid = ep->emm[5] << 16 | ep->emm[6] << 8 | (ep->emm[7] & 0xFE);
		i2b_buf(4, provid, ep->provid);
	}

	switch (ep->emm[0]) {
case 0x88:
	ep->type=UNIQUE;
	memset(ep->hexserial, 0, 8);
	memcpy(ep->hexserial, ep->emm + 4, 4);
	cs_debug_mask(D_EMM, "VIACCESS EMM: UNIQUE");
	return(!memcmp(rdr->hexserial + 1, ep->hexserial, 4));

case 0x8A:
case 0x8B:
	ep->type=GLOBAL;
	cs_debug_mask(D_EMM, "VIACCESS EMM: GLOBAL");
	return TRUE;

case 0x8C:
case 0x8D:
	ep->type=SHARED;
	cs_debug_mask(D_EMM, "VIACCESS EMM: SHARED (part)");
	return FALSE;

case 0x8E:
	ep->type=SHARED;
	memset(ep->hexserial, 0, 8);
	memcpy(ep->hexserial, ep->emm + 3, 3);
	cs_debug_mask(D_EMM, "VIACCESS EMM: SHARED");

	//check for provider as serial (cccam only?)
	int8_t i;
	for (i=0;i<rdr->nprov;i++) {
		if (!memcmp(&rdr->prid[i][1], ep->hexserial, 3))
			return TRUE;
	}
	return(!memcmp(&rdr->sa[0][0], ep->hexserial, 3));

default:
	ep->type = UNKNOWN;
	cs_debug_mask(D_EMM, "VIACCESS EMM: UNKNOWN");
	return TRUE;
	}	
}

static void viaccess_get_emm_filter(struct s_reader * rdr, uchar *filter)
{
	int32_t idx = 2;

	filter[0]=0xFF;
	filter[1]=0;

	filter[idx++]=EMM_GLOBAL;
	filter[idx++]=0;
	filter[idx+0]     = 0x8D;
	filter[idx+0+16]  = 0xFE;
	//filter[idx+6]     = 0xA0; // FIXME: dummy, flood client with EMM's
	//filter[idx+6+16]  = 0xF0;
	filter[1]++;
	idx += 32;

	filter[idx++]=EMM_SHARED;
	filter[idx++]=0;
	filter[idx+0]    = 0x8E;
	filter[idx+0+16] = 0xFF;
	memcpy(filter+idx+1, &rdr->sa[0][0], 3);
	memset(filter+idx+1+16, 0xFF, 3);
	filter[1]++;
	idx += 32;

	filter[idx++]=EMM_UNIQUE;
	filter[idx++]=0;
	filter[idx+0]    = 0x88;
	filter[idx+0+16] = 0xFF;
	memcpy(filter+idx+1, rdr->hexserial + 1, 4);
	memset(filter+idx+1+16, 0xFF, 4);
	filter[1]++;
	idx += 32;

	return;
}

static int32_t viaccess_do_emm(struct s_reader * reader, EMM_PACKET *ep)
{
	def_resp;
	static const unsigned char insa4[] = { 0xca,0xa4,0x04,0x00,0x03 }; // set provider id
	unsigned char insf0[] = { 0xca,0xf0,0x00,0x01,0x22 }; // set adf
	unsigned char insf4[] = { 0xca,0xf4,0x00,0x01,0x00 }; // set adf, encrypted
	unsigned char ins18[] = { 0xca,0x18,0x01,0x01,0x00 }; // set subscription
	unsigned char ins1c[] = { 0xca,0x1c,0x01,0x01,0x00 }; // set subscription, encrypted
	static const unsigned char insc8[] = { 0xca,0xc8,0x00,0x00,0x02 }; // read extended status
	// static const unsigned char insc8Data[] = { 0x00,0x00 }; // data for read extended status

	int32_t emmdatastart=7;

	if (ep->emm[1] == 0x01) { // emm from cccam
		emmdatastart=10;
		ep->emm[1] = 0x70; // (& 0x0f) of this byte is length, so 0x01 would increase the length by 256
		ep->emm[2] -= 3; // last 3 bytes are garbage
		if (ep->type == SHARED) {
			// build missing 0x90 nano from provider at serial position
			memcpy(ep->emm+7, ep->emm+3, 3);
			ep->emm[5] = 0x90;
			ep->emm[6] = 0x03;
			ep->emm[9] |= 0x01;
			emmdatastart = 5;
		}
	}

	if (ep->type == UNIQUE) emmdatastart++;
	int32_t emmLen=SCT_LEN(ep->emm)-emmdatastart;
	int32_t rc=0;

	///cs_dump(ep->emm, emmLen+emmdatastart, "RECEIVED EMM VIACCESS");

	int32_t emmUpToEnd;
	uchar *emmParsed = ep->emm+emmdatastart;
	int32_t provider_ok = 0;
	uint32_t emm_provid;
	uchar keynr = 0;
	int32_t ins18Len = 0;
	uchar ins18Data[512];
	uchar insData[512];
	uchar *nano81Data = 0;
	uchar *nano91Data = 0;
	uchar *nano92Data = 0;
	uchar *nano9EData = 0;
	uchar *nanoF0Data = 0;

	for (emmUpToEnd=emmLen; (emmParsed[1] != 0) && (emmUpToEnd > 0); emmUpToEnd -= (2 + emmParsed[1]), emmParsed += (2 + emmParsed[1])) {
		///cs_dump (emmParsed, emmParsed[1] + 2, "NANO");

		if (emmParsed[0]==0x90 && emmParsed[1]==0x03) {
			/* identification of the service operator */

			uchar soid[3], ident[3], i;

			for (i=0; i<3; i++) {
				soid[i]=ident[i]=emmParsed[2+i];
			}
			ident[2]&=0xF0;
			emm_provid=b2i(3, ident);
			keynr=soid[2]&0x0F;
			if (chk_prov(reader, ident, keynr)) {
				provider_ok = 1;
			} else {
				cs_debug_mask(D_READER, "[viaccess-reader] EMM: provider or key not found on card (%x, %x)", ident, keynr);
				cs_log("[viaccess-reader] EMM: provider or key not found on card (%x, %x)", ident, keynr);
				return ERROR;
			}

			// check if the provider changes. If yes, set the new one. If not, don't .. card will return an error if we do.
			if( reader->last_geo.provid != emm_provid ) {
				write_cmd(insa4, ident);             
				if( cta_res[cta_lr-2]!=0x90 || cta_res[cta_lr-1]!=0x00 ) {
					cs_dump(insa4, 5, "set provider cmd:");
					cs_dump(soid, 3, "set provider data:");
					cs_log("[viaccess-reader] update error: %02X %02X", cta_res[cta_lr-2], cta_res[cta_lr-1]);
					return ERROR;
				}
			}
			// as we are maybe changing the used provider, clear the cache, so the next ecm will re-select the correct one
			reader->last_geo.provid = 0;
			reader->last_geo.geo_len = 0;
			reader->last_geo.geo[0]  = 0;

		} 
		else if (emmParsed[0]==0x9e && emmParsed[1]==0x20) {
			/* adf */

			if (!nano91Data) {
				/* adf is not crypted, so test it */

				uchar custwp;
				uchar *afd;

				custwp=reader->sa[0][3];
				afd=(uchar*)emmParsed+2;

				if( afd[31-custwp/8] & (1 << (custwp & 7)) )
					cs_debug_mask(D_READER, "[viaccess-reader] emm for our card %08X", b2i(4, &reader->sa[0][0]));
				else
					return SKIPPED;
			}

			// memorize
			nano9EData = emmParsed;

		} else if (emmParsed[0]==0x81) {
			nano81Data = emmParsed;
		} else if (emmParsed[0]==0x91 && emmParsed[1]==0x08) {
			nano91Data = emmParsed;
		} else if (emmParsed[0]==0x92 && emmParsed[1]==0x08) {
			nano92Data = emmParsed;
		} else if (emmParsed[0]==0xF0 && emmParsed[1]==0x08) {
			nanoF0Data = emmParsed;
		} else {
			/* other nanos */
			show_subs(reader, emmParsed);

			memcpy(ins18Data+ins18Len, emmParsed, emmParsed[1] + 2);
			ins18Len += emmParsed [1] + 2;
		}
	}

	if (!provider_ok) {
		cs_debug_mask(D_READER, "[viaccess-reader] provider not found in emm, continue anyway");
		// force key to 1...
		keynr = 1;
		///return ERROR;
	}

	if (!nanoF0Data) {
		cs_dump(ep->emm, ep->l, "can't find 0xf0 in emm...");
		return ERROR; // error
	}

	if (nano9EData) {
		if (!nano91Data) {
			// set adf
			insf0[3] = keynr;  // key
			insf0[4] = nano9EData[1] + 2;
			write_cmd(insf0, nano9EData); 
			if( cta_res[cta_lr-2]!=0x90 || cta_res[cta_lr-1]!=0x00 ) {
				cs_dump(insf0, 5, "set adf cmd:");
				cs_dump(nano9EData, insf0[4] , "set adf data:");
				cs_log("[viaccess-reader] update error: %02X %02X", cta_res[cta_lr-2], cta_res[cta_lr-1]);
				return ERROR;
			}
		} else {
			// set adf crypte
			insf4[3] = keynr;  // key
			insf4[4] = nano91Data[1] + 2 + nano9EData[1] + 2;
			memcpy (insData, nano91Data, nano91Data[1] + 2);
			memcpy (insData + nano91Data[1] + 2, nano9EData, nano9EData[1] + 2);
			write_cmd(insf4, insData); 
			if(( cta_res[cta_lr-2]!=0x90 && cta_res[cta_lr-2]!=0x91) || cta_res[cta_lr-1]!=0x00 ) {
				cs_dump(insf4, 5, "set adf encrypted cmd:");
				cs_dump(insData, insf4[4], "set adf encrypted data:");
				cs_log("[viaccess-reader] update error: %02X %02X", cta_res[cta_lr-2], cta_res[cta_lr-1]);
				return ERROR;
			}
		}
	}

	if (!nano92Data) {
		// send subscription 
		ins18[2] = nano9EData ? 0x01: 0x00; // found 9E nano ?
		ins18[3] = keynr;  // key
		ins18[4] = ins18Len + nanoF0Data[1] + 2;
		memcpy (insData, ins18Data, ins18Len);
		memcpy (insData + ins18Len, nanoF0Data, nanoF0Data[1] + 2);
		write_cmd(ins18, insData);
		if( (cta_res[cta_lr-2]==0x90 || cta_res[cta_lr-2]==0x91) && cta_res[cta_lr-1]==0x00 ) {
			cs_debug_mask(D_READER, "[viaccess-reader] update successfully written");
			rc=1; // written
		} else {
			cs_dump(ins18, 5, "set subscription cmd:");
			cs_dump(insData, ins18[4], "set subscription data:");
			cs_log("[viaccess-reader] update error: %02X %02X", cta_res[cta_lr-2], cta_res[cta_lr-1]);
		}

	} else {
		// send subscription encrypted

		if (!nano81Data) {
			cs_dump(ep->emm, ep->l, "0x92 found, but can't find 0x81 in emm...");
			return ERROR; // error
		}

		ins1c[2] = nano9EData ? 0x01: 0x00; // found 9E nano ?
		if (ep->type == UNIQUE) ins1c[2] = 0x02;
		ins1c[3] = keynr;  // key
		ins1c[4] = nano92Data[1] + 2 + nano81Data[1] + 2 + nanoF0Data[1] + 2;
		memcpy (insData, nano92Data, nano92Data[1] + 2);
		memcpy (insData + nano92Data[1] + 2, nano81Data, nano81Data[1] + 2);
		memcpy (insData + nano92Data[1] + 2 + nano81Data[1] + 2, nanoF0Data, nanoF0Data[1] + 2);
		write_cmd(ins1c, insData); 

		if( (cta_res[cta_lr-2]==0x90 && cta_res[cta_lr-1]==0x00) ) {
			cs_log("[viaccess-reader] update successfully written");
			rc=1; // written
		} 
		else {
			if( cta_res[cta_lr-2]&0x1 )
				cs_log("[viaccess-reader] update not written. Data already exists or unknown address");

			//if( cta_res[cta_lr-2]&0x8 ) {
			write_cmd(insc8, NULL);
			if( (cta_res[cta_lr-2]==0x90 && cta_res[cta_lr-1]==0x00) ) {
				cs_log("[viaccess-reader] extended status  %02X %02X", cta_res[0], cta_res[1]);
			}
			//} 
			return ERROR;
		}

	}

	/*
	Sub Main()
	Sc.Write("CA A4 04 00 03")
	RX
	Sc.Write("02 07 11")
	RX
	Sc.Write("CA F0 00 01 22")
	RX
	Sc.Write("9E 20")
	Sc.Write("10 10 08 8A 80 00 04 00 10 10 26 E8 54 80 1E 80")
	Sc.Write("00 01 00 00 00 00 00 50 00 00 80 02 22 00 08 50")
	RX
	Sc.Write("CA 18 01 01 11")
	RX
	Sc.Write("A9 05 34 DE 34 FF 80")
	Sc.Write("F0 08 1A 3E AF B5 2B EE E3 3B")
	RX

	End Sub
	*/
	return rc;
}

static int32_t viaccess_card_info(struct s_reader * reader)
{
	def_resp;
	int32_t i, l, scls, show_cls;
	uchar insac[] = { 0xca, 0xac, 0x00, 0x00, 0x00 }; // select data
	uchar insb8[] = { 0xca, 0xb8, 0x00, 0x00, 0x00 }; // read selected data
	uchar insa4[] = { 0xca, 0xa4, 0x00, 0x00, 0x00 }; // select issuer
	uchar insc0[] = { 0xca, 0xc0, 0x00, 0x00, 0x00 }; // read data item
	static const uchar ins24[] = { 0xca, 0x24, 0x00, 0x00, 0x09 }; // set pin

	static const uchar cls[] = { 0x00, 0x21, 0xff, 0x9f};
	static const uchar pin[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04};

	show_cls=reader->show_cls;
	reader->last_geo.provid  = 0;
	reader->last_geo.geo_len = 0;
	reader->last_geo.geo[0]  = 0;

	cs_log("[viaccess-reader] card detected"); 

	// set pin
	write_cmd(ins24, pin);

	insac[2]=0xa4; write_cmd(insac, NULL); // request unique id
	insb8[4]=0x07; write_cmd(insb8, NULL); // read unique id
	cs_log("[viaccess-reader] serial: %llu", b2ll(5, cta_res+2));

	scls=0;
	insa4[2]=0x00; write_cmd(insa4, NULL); // select issuer 0
	for (i=1; (cta_res[cta_lr-2]==0x90) && (cta_res[cta_lr-1]==0); i++)
	{
		uint32_t l_provid, l_sa;
		uchar l_name[64];
		insc0[4]=0x1a; write_cmd(insc0, NULL); // show provider properties
		cta_res[2]&=0xF0;
		l_provid=b2i(3, cta_res);

		insac[2]=0xa5; write_cmd(insac, NULL); // request sa
		insb8[4]=0x06; write_cmd(insb8, NULL); // read sa
		l_sa=b2i(4, cta_res+2);

		insac[2]=0xa7; write_cmd(insac, NULL); // request name
		insb8[4]=0x02; write_cmd(insb8, NULL); // read name nano + len
		l=cta_res[1];
		insb8[4]=l; write_cmd(insb8, NULL); // read name
		cta_res[l]=0;
		trim((char *)cta_res);
		if (cta_res[0])
			snprintf((char *)l_name, sizeof(l_name), ", name: %s", cta_res);
		else
			l_name[0]=0;

		// read GEO
		insac[2]=0xa6; write_cmd(insac, NULL); // request GEO
		insb8[4]=0x02; write_cmd(insb8, NULL); // read GEO nano + len
		l=cta_res[1];
		char tmp[l*3+1];
		insb8[4]=l; write_cmd(insb8, NULL); // read geo
		cs_ri_log(reader, "provider: %d, id: %06X%s, sa: %08X, geo: %s",
			i, l_provid, l_name, l_sa, (l<4) ? "empty" : cs_hexdump(1, cta_res, l, tmp, sizeof(tmp)));

		// read classes subscription
		insac[2]=0xa9; insac[4]=4;
		write_cmd(insac, cls); // request class subs
		scls=0;
		while( (cta_res[cta_lr-2]==0x90) && (cta_res[cta_lr-1]==0) )
		{
			insb8[4]=0x02; write_cmd(insb8, NULL); // read class subs nano + len
			if( (cta_res[cta_lr-2]==0x90) && (cta_res[cta_lr-1]==0) )
			{
				int32_t fshow;
				l=cta_res[1];
				//fshow=(client[cs_idx].dbglvl==D_DUMP)?1:(scls < show_cls)?1:0;
				fshow=(scls<show_cls);
				insb8[4]=l; write_cmd(insb8, NULL); // read class subs
				if( (cta_res[cta_lr-2]==0x90) && (fshow) && 
					(cta_res[cta_lr-1]==0x00 || cta_res[cta_lr-1]==0x08) )
				{
					show_class(reader, NULL, cta_res, cta_lr-2);
					scls++;
				}
			}
		}

		insac[4]=0;
		insa4[2]=0x02; 
		write_cmd(insa4, NULL); // select next provider
	}
	//return ERROR;
	return OK;
}

#ifdef HAVE_DVBAPI
void dvbapi_sort_nanos(unsigned char *dest, const unsigned char *src, int32_t len);

int32_t viaccess_reassemble_emm(uchar *buffer, uint32_t *len) {
	static uchar emm_global[512];
	static int32_t emm_global_len = 0;

	int32_t pos=0, i;
	uint32_t k;

	// Viaccess
	if (*len>500) return 0;

	switch(buffer[0]) {
		case 0x8c:
		case 0x8d:
			// emm-s part 1
			if (!memcmp(emm_global, buffer, *len))
				return 0;

			// copy first part of the emm-s
			memcpy(emm_global, buffer, *len);
			emm_global_len=*len;
			//cs_ddump_mask(D_READER, buffer, len, "viaccess global emm:");
			return 0;

		case 0x8e:
			// emm-s part 2
			if (!emm_global_len) return 0;

			//extract nanos from emm-gh and emm-s
			uchar emmbuf[512];

			cs_debug_mask(D_DVBAPI, "viaccess_reassemble_emm: start extracting nanos");
			//extract from emm-gh
			for (i=3; i<emm_global_len; i+=emm_global[i+1]+2) {
				//copy nano (length determined by i+1)
				memcpy(emmbuf+pos, emm_global+i, emm_global[i+1]+2);
				pos+=emm_global[i+1]+2;
			}

			if (buffer[2]==0x2c) { 
				//add 9E 20 nano + first 32 bytes of emm content
				memcpy(emmbuf+pos, "\x9E\x20", 2);
				memcpy(emmbuf+pos+2, buffer+7, 32);
				pos+=34;

				//add F0 08 nano + 8 subsequent bytes of emm content
				memcpy(emmbuf+pos, "\xF0\x08", 2);
				memcpy(emmbuf+pos+2, buffer+39, 8);
				pos+=10;
			} else {
				//extract from variable emm-s
				for (k=7; k<(*len); k+=buffer[k+1]+2) {
					//copy nano (length determined by k+1)
					memcpy(emmbuf+pos, buffer+k, buffer[k+1]+2);
					pos+=buffer[k+1]+2;
				}
			}

			cs_ddump_mask(D_DVBAPI, buffer, *len, "viaccess_reassemble_emm: %s emm-s", (buffer[2]==0x2c) ? "fixed" : "variable");

			dvbapi_sort_nanos(buffer+7, emmbuf, pos);
			pos+=7;

			//calculate emm length and set it on position 2
			buffer[2]=pos-3;

			cs_ddump_mask(D_DVBAPI, emm_global, emm_global_len, "viaccess_reassemble_emm: emm-gh");
			cs_ddump_mask(D_DVBAPI, buffer, pos, "viaccess_reassemble_emm: assembled emm");

			*len=pos;
			break;
	}
	return 1;
}
#endif

void reader_viaccess(struct s_cardsystem *ph) 
{
	ph->do_emm=viaccess_do_emm;
	ph->do_ecm=viaccess_do_ecm;
	ph->card_info=viaccess_card_info;
	ph->card_init=viaccess_card_init;
	ph->get_emm_type=viaccess_get_emm_type;
	ph->get_emm_filter=viaccess_get_emm_filter;
	ph->caids[0]=0x05;
	ph->desc="viaccess";
}
