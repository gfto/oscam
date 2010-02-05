#include "globals.h"
#include "reader-common.h"
#include "defines.h"
#include "atr.h"

uchar cta_res[CTA_RES_LEN];
ushort cta_lr;
static int cs_ptyp_orig; //reinit=1, 
extern int ICC_Async_Device_Init ();
extern int ICC_Async_CardWrite (unsigned char *cmd, unsigned short lc, unsigned char *rsp, unsigned short *lr);
extern int ICC_Async_Activate	 (ATR * atr, unsigned short deprecated);
extern int ICC_Async_GetStatus (int * card);
#define SC_IRDETO 1
#define SC_CRYPTOWORKS 2
#define SC_VIACCESS 3
#define SC_CONAX 4
#define SC_SECA 5
#define SC_VIDEOGUARD2 6
#define SC_DRE 7
#define SC_NAGRA 8

#ifdef TUXBOX
static int reader_device_type(char *device)
{
  int rc=reader[ridx].typ;
  struct stat sb;
  if (reader[ridx].typ == R_MOUSE)
  {
      if (!stat(device, &sb))
      {
        if (S_ISCHR(sb.st_mode))
        {
          int dev_major, dev_minor;
          dev_major=major(sb.st_rdev);
          dev_minor=minor(sb.st_rdev);
          if ((cs_hw==CS_HW_DBOX2) && ((dev_major==4) || (dev_major==5)))
            switch(dev_minor & 0x3F)
            {
              case 0: rc=R_DB2COM1; break;
              case 1: rc=R_DB2COM2; break;
            }
          cs_debug("device is major: %d, minor: %d, typ=%d", dev_major, dev_minor, rc);
        }
      }
  }
	reader[ridx].typ = rc;
  return(rc);
}
#endif

static void reader_nullcard(void)
{
  reader[ridx].card_system=0;
  memset(reader[ridx].hexserial, 0   , sizeof(reader[ridx].hexserial));
  memset(reader[ridx].prid     , 0xFF, sizeof(reader[ridx].prid     ));
  memset(reader[ridx].caid     , 0   , sizeof(reader[ridx].caid     ));
  memset(reader[ridx].availkeys, 0   , sizeof(reader[ridx].availkeys));
  reader[ridx].acs=0;
  reader[ridx].nprov=0;
}

int reader_cmd2icc(uchar *buf, int l)
{
	int rc;
#ifdef HAVE_PCSC
	if (reader[ridx].typ == R_PCSC) {
 	  return (pcsc_reader_do_api(&reader[ridx], buf, cta_res, &cta_lr,l)); 
	}

#endif

	cs_ddump(buf, l, "write to cardreader %s:",reader[ridx].label);
	cta_lr=sizeof(cta_res)-1;
	cs_ptyp_orig=cs_ptyp;
	cs_ptyp=D_DEVICE;
	rc=ICC_Async_CardWrite(buf, l, cta_res, &cta_lr);
	cs_ptyp=cs_ptyp_orig;
	cs_ddump(cta_res, cta_lr, "answer from cardreader %s:", reader[ridx].label);
	return rc;
}

#define CMD_LEN 5

int card_write(uchar *cmd, uchar *data)
{
  if (data) {
    uchar buf[256]; //only allocate buffer when its needed
    memcpy(buf, cmd, CMD_LEN);
    if (cmd[4]) memcpy(buf+CMD_LEN, data, cmd[4]);
    return(reader_cmd2icc(buf, CMD_LEN+cmd[4]));
  }
  else
    return(reader_cmd2icc(cmd, CMD_LEN));
}

static int reader_card_inserted(void)
{
#ifdef HAVE_PCSC
	if (reader[ridx].typ == R_PCSC) {
		return(pcsc_check_card_inserted(&reader[ridx]));
	}
#endif
	int card;
	cs_ptyp_orig=cs_ptyp;
	cs_ptyp=D_IFD;
	if (ICC_Async_GetStatus (&card)) {
		cs_log("Error getting status of terminal.");
		return 0; //corresponds with no card inside!!
	}
	cs_ptyp=cs_ptyp_orig;
	return (card);
}

static int reader_activate_card(ATR * atr, unsigned short deprecated)
{
      int i;
#ifdef HAVE_PCSC
    unsigned char atrarr[64];
    ushort atr_size = 0;
    if (reader[ridx].typ == R_PCSC) {
        if (pcsc_activate_card(&reader[ridx], atrarr, &atr_size))
            return (ATR_InitFromArray (atr, atrarr, atr_size) == ATR_OK);
        else
            return 0;
    }
#endif
	if (!reader_card_inserted())
		return 0;

  /* Activate card */
	cs_ptyp_orig=cs_ptyp;
	cs_ptyp=D_DEVICE;
  for (i=0; i<5; i++) {
		if (!ICC_Async_Activate(atr, deprecated)) {
			i = 100;
			break;
		}
		cs_log("Error activating card.");
  	cs_sleepms(500);
	}
	cs_ptyp=cs_ptyp_orig;
  if (i<100) return(0);

#ifdef CS_RDR_INIT_HIST
  reader[ridx].init_history_pos=0;
  memset(reader[ridx].init_history, 0, sizeof(reader[ridx].init_history));
#endif
//  cs_ri_log("ATR: %s", cs_hexdump(1, atr, atr_size));//FIXME
  sleep(1);
  return(1);
}

void do_emm_from_file(void)
{
  //now here check whether we have EMM's on file to load and write to card:
  if (reader[ridx].emmfile[0]) {//readnano has something filled in

    //handling emmfile
    char token[256];
    FILE *fp;
    size_t result;
    if ((reader[ridx].emmfile[0] == '/'))
      sprintf (token, "%s", reader[ridx].emmfile); //pathname included
    else
      sprintf (token, "%s%s", cs_confdir, reader[ridx].emmfile); //only file specified, look in confdir for this file
    
    if (!(fp = fopen (token, "rb")))
      cs_log ("ERROR: Cannot open EMM file '%s' (errno=%d)\n", token, errno);
    else {
      EMM_PACKET *eptmp;
      eptmp = malloc (sizeof(EMM_PACKET));
      result = fread (eptmp, sizeof(EMM_PACKET), 1, fp);      
      fclose (fp);

      uchar old_b_nano = reader[ridx].b_nano[eptmp->emm[0]]; //save old b_nano value
      reader[ridx].b_nano[eptmp->emm[0]] &= 0xfc; //clear lsb and lsb+1, so no blocking, and no saving for this nano      
          
      //if (!reader_do_emm (eptmp))
      if (!reader_emm (eptmp))
        cs_log ("ERROR: EMM read from file %s NOT processed correctly!", token);

      reader[ridx].b_nano[eptmp->emm[0]] = old_b_nano; //restore old block/save settings
      reader[ridx].emmfile[0] = 0; //clear emmfile, so no reading anymore

      free(eptmp);
      eptmp = NULL;
    }
  }
}

void reader_card_info()
{
//  int rc=-1;
  if (reader_checkhealth())
  //if (rc=reader_checkhealth())
  {
    client[cs_idx].last=time((time_t)0);
    cs_ri_brk(0);
    do_emm_from_file();
    switch(reader[ridx].card_system)
    {
      case SC_NAGRA:
        nagra2_card_info(); break;
      case SC_IRDETO:
        irdeto_card_info(); break;
      case SC_CRYPTOWORKS:
        cryptoworks_card_info(); break;
      case SC_VIACCESS:
        viaccess_card_info(); break;
      case SC_CONAX:
        conax_card_info(); break;
      case SC_VIDEOGUARD2:
        videoguard_card_info(); break;
      case SC_SECA:
         seca_card_info(); break;
      case SC_DRE:
	 dre_card_info(); break;
    }
    reader[ridx].online = 1; //do not check on rc, because error in cardinfo should not be fatal
  }
}

static int reader_get_cardsystem(ATR atr)
{
  if (nagra2_card_init(atr))		reader[ridx].card_system=SC_NAGRA; else
  if (irdeto_card_init(atr))		reader[ridx].card_system=SC_IRDETO; else
  if (conax_card_init(atr))		reader[ridx].card_system=SC_CONAX; else
  if (cryptoworks_card_init(atr))	reader[ridx].card_system=SC_CRYPTOWORKS; else
  if (seca_card_init(atr))	reader[ridx].card_system=SC_SECA; else
  if (viaccess_card_init(atr))	reader[ridx].card_system=SC_VIACCESS; else
  if (videoguard_card_init(atr))  reader[ridx].card_system=SC_VIDEOGUARD2; else
  if (dre_card_init(atr))  reader[ridx].card_system=SC_DRE; else
    cs_ri_log("card system not supported");
  cs_ri_brk(1);

  return(reader[ridx].card_system);
}

static int reader_reset(void)
{
	reader_nullcard();
	ATR atr;
	unsigned short int ret, deprecated;
	for (deprecated = reader[ridx].deprecated; deprecated < 2; deprecated++) {
		if (!reader_activate_card(&atr, deprecated)) return(0);
		ret =reader_get_cardsystem(atr);
		if (ret)
			break;
		if (!deprecated)
			cs_log("Normal mode failed, reverting to Deprecated Mode");
	}
	return(ret);
}

int reader_device_init(char *device)
{
#ifdef HAVE_PCSC
	if (reader[ridx].typ == R_PCSC) {
	   return (pcsc_reader_init(&reader[ridx], device));
	}
#endif
 
  int rc = -1; //FIXME
  cs_ptyp_orig=cs_ptyp;
  cs_ptyp=D_DEVICE;
#ifdef TUXBOX
	reader[ridx].typ = reader_device_type(device);
#endif
	if (ICC_Async_Device_Init())
    cs_log("Cannot open device: %s", device);
	else
		rc = OK;
  cs_debug("ct_init on %s: %d", device, rc);
  cs_ptyp=cs_ptyp_orig;
  return((rc!=OK) ? 2 : 0);
}

int reader_checkhealth(void)
{
  if (reader_card_inserted())
  {
    if (!(reader[ridx].card_status & CARD_INSERTED))
    {
      cs_log("card detected");
      reader[ridx].card_status  = CARD_NEED_INIT;
      reader[ridx].card_status = CARD_INSERTED | (reader_reset() ? 0 : CARD_FAILURE);
      if (reader[ridx].card_status & CARD_FAILURE)
      {
        cs_log("card initializing error");
      }
      else
      {
        client[cs_idx].au=ridx;
        reader_card_info();
      }

      int i;
      for( i=1; i<CS_MAXPID; i++ ) {
        if( client[i].pid && client[i].typ=='c' && client[i].usr[0] ) {
          kill(client[i].pid, SIGQUIT);
        }
      }
    }
  }
  else
  {
    if (reader[ridx].card_status & CARD_INSERTED)
    {
      reader_nullcard();
      client[cs_idx].lastemm=0;
      client[cs_idx].lastecm=0;
      client[cs_idx].au=-1;
      extern int io_serial_need_dummy_char;
      io_serial_need_dummy_char=0;
      cs_log("card ejected");
    }
    reader[ridx].card_status=0;
    reader[ridx].online=0;
  }
  return reader[ridx].card_status==CARD_INSERTED;
}

void reader_post_process(void)
{
  // some systems eg. nagra2/3 needs post process after receiving cw from card
  // To save ECM/CW time we added this function after writing ecm answer
  switch(reader[ridx].card_system)
    {
      case SC_NAGRA:
        nagra2_post_process(); break;
      default: break;
    }
}

int reader_ecm(ECM_REQUEST *er)
{
  int rc=-1;
  if( (rc=reader_checkhealth()) )
  {
    if( (reader[ridx].caid[0]>>8)==((er->caid>>8)&0xFF) )
    {
      client[cs_idx].last_srvid=er->srvid;
      client[cs_idx].last_caid=er->caid;
      client[cs_idx].last=time((time_t)0);
      switch(reader[ridx].card_system)
      {
      	case SC_NAGRA:
          rc=(nagra2_do_ecm(er)) ? 1 : 0; break;
        case SC_IRDETO:
          rc=(irdeto_do_ecm(er)) ? 1 : 0; break;
        case SC_CRYPTOWORKS:
          rc=(cryptoworks_do_ecm(er)) ? 1 : 0; break;
        case SC_VIACCESS:
          rc=(viaccess_do_ecm(er)) ? 1 : 0; break;
        case SC_CONAX:
          rc=(conax_do_ecm(er)) ? 1 : 0; break;
        case SC_SECA:
          rc=(seca_do_ecm(er)) ? 1 : 0; break;
        case SC_VIDEOGUARD2:
          rc=(videoguard_do_ecm(er)) ? 1 : 0; break;
	case SC_DRE:
	  rc=(dre_do_ecm(er)) ? 1: 0; break;
        default: rc=0;
      }
    }
    else
      rc=0;
  }
  return(rc);
}

int reader_emm(EMM_PACKET *ep)
{
  int rc=-1;

  rc=reader_checkhealth();
  if (rc)
  {
    client[cs_idx].last=time((time_t)0);
    if (reader[ridx].b_nano[ep->emm[0]] & 0x02) //should this nano be saved?
    {
      char token[256];
      FILE *fp;

      time_t rawtime;
      time (&rawtime);
      struct tm *timeinfo;
      timeinfo = localtime (&rawtime);	/* to access LOCAL date/time info */
      char buf[80];
      strftime (buf, 80, "%Y%m%d_%H_%M_%S", timeinfo);

      sprintf (token, "%swrite_%s_%s.%s", cs_confdir, (ep->emm[0] == 0x82) ? "UNIQ" : "SHARED", buf, "txt");
      if (!(fp = fopen (token, "w")))
      {
        cs_log ("ERROR: Cannot open EMM.txt file '%s' (errno=%d)\n", token, errno);
      }
      else
      {
    	cs_log ("Succesfully written text EMM to %s.", token);
    	int emm_length = ((ep->emm[1] & 0x0f) << 8) | ep->emm[2];
    	fprintf (fp, "%s", cs_hexdump (0, ep->emm, emm_length + 3));
    	fclose (fp);
      }

      //sprintf (token, "%s%s.%s", cs_confdir, buf,"emm");
      sprintf (token, "%swrite_%s_%s.%s", cs_confdir, (ep->emm[0] == 0x82) ? "UNIQ" : "SHARED", buf, "emm");
      if (!(fp = fopen (token, "wb")))
      {
    	cs_log ("ERROR: Cannot open EMM.emm file '%s' (errno=%d)\n", token, errno);
      }
      else 
      {
    	if (fwrite(ep, sizeof (*ep), 1, fp) == 1)
        {
        	cs_log ("Succesfully written binary EMM to %s.", token);
        }
        else
        {
        	cs_log ("ERROR: Cannot write binary EMM to %s (errno=%d)\n", token, errno);
        }
    	fclose (fp);
      }
    }

    if (reader[ridx].b_nano[ep->emm[0]] & 0x01) //should this nano be blcoked?
      return 3;

    switch(reader[ridx].card_system)
    {
      case SC_NAGRA:
        rc=nagra2_do_emm(ep); break;
      case SC_IRDETO:
        rc=irdeto_do_emm(ep); break;
      case SC_CRYPTOWORKS:
        rc=cryptoworks_do_emm(ep); break;
      case SC_VIACCESS:
        rc=viaccess_do_emm(ep); break;
      case SC_CONAX:
        rc=conax_do_emm(ep); break;
      case SC_SECA:
        rc=seca_do_emm(ep); break;
      case SC_VIDEOGUARD2:
        rc=videoguard_do_emm(ep); break;
      case SC_DRE:
	rc=dre_do_emm(ep); break;
      default: rc=0;
    }
  }
  return(rc);
}
