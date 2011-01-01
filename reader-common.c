#include "globals.h"
#include "reader-common.h"
#include "defines.h"
#include "atr.h"
#include "icc_async_exports.h"
#ifdef AZBOX
#include "csctapi/ifd_azbox.h"
#endif

#if defined(TUXBOX) && defined(PPC) //dbox2 only
#include "csctapi/mc_global.h"
static int reader_device_type(struct s_reader * reader)
{
  int rc=reader->typ;
  struct stat sb;
  if (reader->typ == R_MOUSE)
  {
      if (!stat(reader->device, &sb))
      {
        if (S_ISCHR(sb.st_mode))
        {
          int dev_major, dev_minor;
          dev_major=major(sb.st_rdev);
          dev_minor=minor(sb.st_rdev);
          if (((dev_major==4) || (dev_major==5)))
            switch(dev_minor & 0x3F)
            {
              case 0: rc=R_DB2COM1; break;
              case 1: rc=R_DB2COM2; break;
            }
          cs_debug_mask(D_READER, "device is major: %d, minor: %d, typ=%d", dev_major, dev_minor, rc);
        }
      }
  }
	reader->typ = rc;
  return(rc);
}
#endif

static void reader_nullcard(struct s_reader * reader)
{
  reader->card_system=0;
  memset(reader->hexserial, 0   , sizeof(reader->hexserial));
  memset(reader->prid     , 0xFF, sizeof(reader->prid     ));
  memset(reader->caid     , 0   , sizeof(reader->caid     ));
  memset(reader->availkeys, 0   , sizeof(reader->availkeys));
  reader->acs=0;
  reader->nprov=0;
}

int reader_cmd2icc(struct s_reader * reader, const uchar *buf, const int l, uchar * cta_res, ushort * p_cta_lr)
{
	int rc;
	*p_cta_lr=CTA_RES_LEN-1; //FIXME not sure whether this one is necessary 
	cs_ddump_mask(D_READER, buf, l, "write to cardreader %s:",reader->label);
	rc=ICC_Async_CardWrite(reader, (uchar *)buf, (unsigned short)l, cta_res, p_cta_lr);
	return rc;
}

#define CMD_LEN 5

int card_write(struct s_reader * reader, const uchar *cmd, const uchar *data, uchar *response, ushort * response_length)
{
  uchar buf[260];
  // always copy to be able to be able to use const buffer without changing all code  
  memcpy(buf, cmd, CMD_LEN); 

  if (data) {
    if (cmd[4]) memcpy(buf+CMD_LEN, data, cmd[4]);
    return(reader_cmd2icc(reader, buf, CMD_LEN+cmd[4], response, response_length));
  }
  else
    return(reader_cmd2icc(reader, buf, CMD_LEN, response, response_length));
}

int check_sct_len(const uchar *data, int off)
{
	int l = SCT_LEN(data);
	if (l+off > MAX_LEN) {
		cs_debug_mask(D_READER, "check_sct_len(): smartcard section too long %d > %d", l, MAX_LEN-off);
		l = -1;
	}
	return(l);
}


static int reader_card_inserted(struct s_reader * reader)
{
#ifndef USE_GPIO
	if ((reader->detect&0x7f) > 3)
		return 1;
#endif
	int card;
	if (ICC_Async_GetStatus (reader, &card)) {
		cs_log("Error getting status of terminal.");
		return 0; //corresponds with no card inside!!
	}
	return (card);
}

static int reader_activate_card(struct s_reader * reader, ATR * atr, unsigned short deprecated)
{
  int i,ret;
	if (!reader_card_inserted(reader))
		return 0;

  /* Activate card */
  for (i=0; i<3; i++) {
		ret = ICC_Async_Activate(reader, atr, deprecated);
		if (!ret)
			break;
		cs_log("Error activating card.");
#ifdef QBOXHD_LED
		qboxhd_led_blink(QBOXHD_LED_COLOR_MAGENTA,QBOXHD_LED_BLINK_MEDIUM);
#endif
  	cs_sleepms(500);
	}
  if (ret) return(0);

  reader->init_history_pos=0;

//  cs_ri_log("ATR: %s", cs_hexdump(1, atr, atr_size));//FIXME
  cs_sleepms(1000);
  return(1);
}

static void do_emm_from_file(struct s_reader * reader)
{
  //now here check whether we have EMM's on file to load and write to card:
  if (reader->emmfile != NULL) {//readnano has something filled in

    //handling emmfile
    char token[256];
    FILE *fp;
    size_t result;
    if ((reader->emmfile[0] == '/'))
      sprintf (token, "%s", reader->emmfile); //pathname included
    else
      sprintf (token, "%s%s", cs_confdir, reader->emmfile); //only file specified, look in confdir for this file
    
    if (!(fp = fopen (token, "rb")))
      cs_log ("ERROR: Cannot open EMM file '%s' (errno=%d)\n", token, errno);
    else {
      EMM_PACKET *eptmp;
      eptmp = malloc (sizeof(EMM_PACKET));
      result = fread (eptmp, sizeof(EMM_PACKET), 1, fp);      
      fclose (fp);

      uchar old_b_nano = reader->b_nano[eptmp->emm[0]]; //save old b_nano value
      reader->b_nano[eptmp->emm[0]] &= 0xfc; //clear lsb and lsb+1, so no blocking, and no saving for this nano      
          
      //if (!reader_do_emm (eptmp))
      if (!reader_emm (reader, eptmp))
        cs_log ("ERROR: EMM read from file %s NOT processed correctly!", token);

      reader->b_nano[eptmp->emm[0]] = old_b_nano; //restore old block/save settings
			free (reader->emmfile);
      reader->emmfile = NULL; //clear emmfile, so no reading anymore

      free(eptmp);
      eptmp = NULL;
    }
  }
}

void reader_card_info(struct s_reader * reader)
{
  if ((reader->card_status == CARD_NEED_INIT) || (reader->card_status == CARD_INSERTED))
  {
    cur_client()->last=time((time_t)0);
    cs_ri_brk(reader, 0);

	if (cardsystem[reader->card_system-1].card_info) {
		cardsystem[reader->card_system-1].card_info(reader);
	}
  }
}

static int reader_get_cardsystem(struct s_reader * reader, ATR atr)
{
	int i;
	for (i=0; i<CS_MAX_MOD; i++) {
		if (cardsystem[i].card_init) {
			if (cardsystem[i].card_init(reader, atr)) {
				reader->card_system=i+1;
				cs_log("found cardsystem");
#ifdef QBOXHD_LED 
				qboxhd_led_blink(QBOXHD_LED_COLOR_YELLOW,QBOXHD_LED_BLINK_MEDIUM);
				qboxhd_led_blink(QBOXHD_LED_COLOR_GREEN,QBOXHD_LED_BLINK_MEDIUM);
				qboxhd_led_blink(QBOXHD_LED_COLOR_YELLOW,QBOXHD_LED_BLINK_MEDIUM);
				qboxhd_led_blink(QBOXHD_LED_COLOR_GREEN,QBOXHD_LED_BLINK_MEDIUM);
#endif
				break;
			}
		}
	}

	if (reader->card_system==0)
#ifdef QBOXHD_LED 
	{
		cs_ri_log(reader, "card system not supported");
		qboxhd_led_blink(QBOXHD_LED_COLOR_MAGENTA,QBOXHD_LED_BLINK_MEDIUM);
	}
#else
		cs_ri_log(reader, "card system not supported");
#endif



	cs_ri_brk(reader, 1);

	return(reader->card_system);
}

static int reader_reset(struct s_reader * reader)
{
  reader_nullcard(reader);
  ATR atr;
  unsigned short int ret = 0;
#ifdef AZBOX
  int i;
  if (reader->typ == R_INTERNAL) {
    if (reader->mode != -1) {
      Azbox_SetMode(reader->mode);
      if (!reader_activate_card(reader, &atr, 0)) return(0);
      ret = reader_get_cardsystem(reader, atr);
    } else {
      for (i = 0; i < AZBOX_MODES; i++) {
        Azbox_SetMode(i);
        if (!reader_activate_card(reader, &atr, 0)) return(0);
        ret = reader_get_cardsystem(reader, atr);
        if (ret)
          break;
      }
    }
  } else {
#endif
  unsigned short int deprecated;
	for (deprecated = reader->deprecated; deprecated < 2; deprecated++) {
		if (!reader_activate_card(reader, &atr, deprecated)) return(0);
		ret = reader_get_cardsystem(reader, atr);
		if (ret)
			break;
		if (!deprecated)
			cs_log("Normal mode failed, reverting to Deprecated Mode");
	}
#ifdef AZBOX
  }
#endif
	return(ret);
}

int reader_device_init(struct s_reader * reader)
{
	int rc = -1; //FIXME
#if defined(TUXBOX) && defined(PPC)
	struct stat st;
	if (!stat(DEV_MULTICAM, &st))
		reader->typ = reader_device_type(reader);
#endif
	if (ICC_Async_Device_Init(reader))
		cs_log("Cannot open device: %s", reader->device);
	else
		rc = OK;
  return((rc!=OK) ? 2 : 0); //exit code 2 means keep retrying, exit code 0 means all OK
}

int reader_checkhealth(struct s_reader * reader)
{
  if (reader_card_inserted(reader))
  {
    if (reader->card_status == NO_CARD)
    {
      cs_log("%s card detected", reader->label);
#ifdef QBOXHD_LED
      qboxhd_led_blink(QBOXHD_LED_COLOR_YELLOW,QBOXHD_LED_BLINK_SLOW);
#endif
      reader->card_status = CARD_NEED_INIT;
      if (!reader_reset(reader)) 
      {
        reader->card_status = CARD_FAILURE;
        cs_log("card initializing error");
#ifdef QBOXHD_LED 
        qboxhd_led_blink(QBOXHD_LED_COLOR_MAGENTA,QBOXHD_LED_BLINK_MEDIUM);
#endif
      }
      else
      {
        cur_client()->aureader = cur_client()->reader;
        reader_card_info(reader);
        reader->card_status = CARD_INSERTED;
        do_emm_from_file(reader);
      }
    }
  }
  else
  {
    if (reader->card_status == CARD_INSERTED)
    {
      reader_nullcard(reader);
      cur_client()->lastemm = 0;
      cur_client()->lastecm = 0;
      cur_client()->aureader = NULL;
      cs_log("card ejected slot = %i", reader->slot);
#ifdef QBOXHD_LED 
      qboxhd_led_blink(QBOXHD_LED_COLOR_YELLOW,QBOXHD_LED_BLINK_SLOW);
#endif
    }
    reader->card_status = NO_CARD;
  }
  return reader->card_status == CARD_INSERTED;
}

void reader_post_process(struct s_reader * reader)
{
  // some systems eg. nagra2/3 needs post process after receiving cw from card
  // To save ECM/CW time we added this function after writing ecm answer
	if (!reader->card_system)
		return;
	if (cardsystem[reader->card_system-1].post_process) {
		cardsystem[reader->card_system-1].post_process(reader);
	}
}

int reader_ecm(struct s_reader * reader, ECM_REQUEST *er)
{
  int rc=-1;
  if( (rc=reader_checkhealth(reader)) )
  {
    if((reader->caid[0] >> 8) == ((er->caid >> 8) & 0xFF))
    {
      cur_client()->last_srvid=er->srvid;
      cur_client()->last_caid=er->caid;
      cur_client()->last=time((time_t)0);

	if (cardsystem[reader->card_system-1].do_ecm) 
		rc=cardsystem[reader->card_system-1].do_ecm(reader, er);
	else
		rc=0;

    }
    else
      rc=0;
  }
  return(rc);
}

int reader_get_emm_type(EMM_PACKET *ep, struct s_reader * rdr) //rdr differs from calling reader!
{
	cs_debug_mask(D_EMM, "Entered reader_get_emm_type cardsystem %i",rdr->card_system);
	int rc;

	if (rdr->card_system<1)
		return 0;

	if (cardsystem[rdr->card_system-1].get_emm_type) 
		rc=cardsystem[rdr->card_system-1].get_emm_type(ep, rdr);
	else
		rc=0;

	return rc;
}

int get_cardsystem(ushort caid) {
	int i,j;
	for (i=0; i<CS_MAX_MOD; i++) {
		if (cardsystem[i].caids) {
			for (j=0;j<2;j++) {
				if ((cardsystem[i].caids[j]==caid >> 8)) {
					return i+1;
				}
			}
		}
	}
	return 0;
}

void get_emm_filter(struct s_reader * rdr, uchar *filter) {
	filter[0]=0xFF;
	filter[1]=0;

	if (cardsystem[rdr->card_system-1].get_emm_filter) {
		cardsystem[rdr->card_system-1].get_emm_filter(rdr, filter);
	}

	return;
}

int reader_emm(struct s_reader * reader, EMM_PACKET *ep)
{
  int rc=-1;

  rc=reader_checkhealth(reader);
  if (rc)
  {
    if (reader->b_nano[ep->emm[0]] & 0x01) //should this nano be blcoked?
      return 3;

	if (cardsystem[reader->card_system-1].do_emm) 
		rc=cardsystem[reader->card_system-1].do_emm(reader, ep);
	else
		rc=0;
  }
  return(rc);
}

int check_emm_cardsystem(struct s_reader * rdr, EMM_PACKET *ep)
{
	return (rdr->fd && (rdr->caid[0] == b2i(2,ep->caid) || rdr->typ == R_CCCAM));
}
