#include "globals.h"
#include "reader-common.h"

#include <termios.h>
#include <unistd.h>
#ifdef OS_LINUX
#include <linux/serial.h>
#endif

#define VG1_EMMTYPE_MASK 0xC0
#define VG1_EMMTYPE_G 0
#define VG1_EMMTYPE_U 1
#define VG1_EMMTYPE_S 2

#define write_cmd_vg(cmd, data) (card_write(reader, cmd, data, cta_res, &cta_lr) == 0)

//////  ====================================================================================

int VG1_BASEYEAR = 1992;

static int cw_is_valid(unsigned char *cw)	//returns 1 if cw_is_valid, returns 0 if cw is all zeros
{
  int i;
  for (i = 0; i < 8; i++)
    if (cw[i] != 0) {		//test if cw = 00
      return OK;
    }
  return ERROR;
}

static const unsigned short NdTabB001[0x15][0x20] = {
  {0xEAF1, 0x0237, 0x29D0, 0xBAD2, 0xE9D3, 0x8BAE, 0x2D6D, 0xCD1B, 0x538D, 0xDE6B, 0xA634, 0xF81A, 0x18B5, 0x5087, 0x14EA, 0x672E,
   0xF0FC, 0x055E, 0x62E5, 0xB78F, 0x5D09, 0x0003, 0xE4E8, 0x2DCE, 0x6BE0, 0xAC4E, 0xF485, 0x6967, 0xF28C, 0x97A0, 0x01EF, 0x0100},
  {0xC539, 0xF5B9, 0x9099, 0x013A, 0xD4B9, 0x6AB5, 0xEA67, 0x7EB4, 0x6C30, 0x4BF0, 0xB810, 0xB0B5, 0xB76D, 0xA751, 0x1AE7, 0x14CA,
   0x4F4F, 0x1586, 0x2608, 0x10B1, 0xE7E1, 0x48BE, 0x7DDD, 0x5ECB, 0xCFBF, 0x323B, 0x8B31, 0xB131, 0x0F1A, 0x664B, 0x0140, 0x0100},
  {0x3C7D, 0xBDC4, 0xFEC7, 0x26A6, 0xB0A0, 0x6E55, 0xF710, 0xF9BF, 0x0023, 0xE81F, 0x41CA, 0xBE32, 0xB461, 0xE92D, 0xF1AF, 0x409F,
   0xFC85, 0xFE5B, 0x7FCE, 0x17F5, 0x01AB, 0x4A46, 0xEB05, 0xA251, 0xDC6F, 0xF0C0, 0x10F0, 0x1D51, 0xEFAA, 0xE9BF, 0x0100, 0x0100},
  {0x1819, 0x0CAA, 0x9067, 0x607A, 0x7576, 0x1CBC, 0xE51D, 0xBF77, 0x7EC6, 0x839E, 0xB695, 0xF096, 0xDC10, 0xCB69, 0x4654, 0x8E68,
   0xD62D, 0x4F1A, 0x4227, 0x92AC, 0x9064, 0x6BD1, 0x1E75, 0x2747, 0x00DA, 0xA6A6, 0x6CF1, 0xD151, 0xBE56, 0x3E33, 0x0128, 0x0100},
  {0x4091, 0x09ED, 0xD494, 0x6054, 0x1869, 0x71D5, 0xB572, 0x7BF1, 0xE925, 0xEE2D, 0xEEDE, 0xA13C, 0x6613, 0x9BAB, 0x122D, 0x7AE4,
   0x5268, 0xE6C9, 0x50CB, 0x79A1, 0xF212, 0xA062, 0x6B48, 0x70B3, 0xF6B0, 0x06D5, 0xF8AB, 0xECF5, 0x6255, 0xEDD8, 0x79D2, 0x290A},
  {0xD3CF, 0x014E, 0xACB3, 0x8F6B, 0x0F2C, 0xA5D8, 0xE8E0, 0x863D, 0x80D5, 0x5705, 0x658A, 0x8BC2, 0xEE46, 0xD3AE, 0x0199, 0x0100, 0x4A35,
   0xABE4, 0xF976, 0x935A, 0xA8A5, 0xBAE9, 0x24D0, 0x71AA, 0xB3FE, 0x095E, 0xAB06, 0x4CD5, 0x2F0D, 0x1ACB, 0x59F3, 0x4C50},
  {0xFD27, 0x0F8E, 0x191A, 0xEEE7, 0x2F49, 0x3A05, 0x3267, 0x4F88, 0x38AE, 0xFCE9, 0x9476, 0x18C6, 0xF961, 0x4EF0, 0x39D0, 0x42E6,
   0xB747, 0xE625, 0xB68E, 0x5100, 0xF92A, 0x86FE, 0xE79B, 0xEE91, 0x21D5, 0x4C3C, 0x683D, 0x5AD1, 0x1B49, 0xF407, 0x0194, 0x0100},
  {0x4BF9, 0xDC0D, 0x9478, 0x5174, 0xCB4A, 0x8A89, 0x4D6A, 0xFED8, 0xF123, 0xA8CD, 0xEEE7, 0xA6D1, 0xB763, 0xF5E2, 0xE085, 0x01EF,
   0xE466, 0x9FA3, 0x2F68, 0x2190, 0x423F, 0x287F, 0x7F3F, 0x09F6, 0x2111, 0xA963, 0xD0BB, 0x674A, 0xBA72, 0x45F9, 0xF186, 0xB8F5},
  {0x0010, 0xD1B9, 0xB164, 0x9E87, 0x1F49, 0x6950, 0x2DBF, 0x38D3, 0x2EB0, 0x3E8E, 0x91E6, 0xF688, 0x7E41, 0x566E, 0x01B0, 0x0100,
   0x24A1, 0x73D8, 0xA0C3, 0xF71B, 0xA0A5, 0x2A06, 0xBA46, 0xFEC3, 0xDD4C, 0x52CC, 0xF9BC, 0x3B7E, 0x3812, 0x0666, 0xB74B, 0x40F8},
  {0x28F2, 0x7C81, 0xFC92, 0x6FBD, 0x53D6, 0x72A3, 0xBBDF, 0xB6FC, 0x9CE5, 0x2331, 0xD4F6, 0xC5BB, 0xE8BB, 0x6676, 0x02D9, 0x2F0E,
   0xD009, 0xD136, 0xCD09, 0x7551, 0x1826, 0x9D9B, 0x63EA, 0xFC63, 0x68CD, 0x3672, 0xCB95, 0xD28E, 0xF1CD, 0x20CA, 0x014C, 0x0100},
  {0xE539, 0x55B7, 0x989D, 0x21C4, 0x463A, 0xE68F, 0xF8B5, 0xE5C5, 0x662B, 0x35BF, 0x3C50, 0x0131, 0xF4BF, 0x38B2, 0x41BC, 0xB829,
   0x02B7, 0x6B8F, 0xA25C, 0xAFD2, 0xD84A, 0x2243, 0x53EB, 0xC6C9, 0x2E14, 0x181F, 0x8F96, 0xDF0E, 0x0D4C, 0x30F6, 0xFFE1, 0x9DDA},
  {0x30B6, 0x777E, 0xDA3D, 0xAF77, 0x205E, 0xC90B, 0x856B, 0xB451, 0x3BCC, 0x76C2, 0x8ACF, 0xDCB1, 0xA5E5, 0xDD64, 0x0197, 0x0100,
   0xE751, 0xB661, 0x0404, 0xDB4A, 0xE9DD, 0xA400, 0xAF26, 0x3F5E, 0x904B, 0xA924, 0x09E0, 0xE72B, 0x825B, 0x2C50, 0x6FD0, 0x0D52},
  {0x2730, 0xC2BA, 0x9E44, 0x5815, 0xFC47, 0xB21D, 0x67B8, 0xF8B9, 0x047D, 0xB0AF, 0x9F14, 0x741B, 0x4668, 0xBE54, 0xDE16, 0xDB14,
   0x7CB7, 0xF2B8, 0x0683, 0x762C, 0x09A0, 0x9507, 0x7F92, 0x022C, 0xBA6A, 0x7D52, 0x0AF4, 0x1BC3, 0xB46A, 0xC4FD, 0x01C2, 0x0100},
  {0x7611, 0x66F3, 0xEE87, 0xEDD3, 0xC559, 0xEFD4, 0xDC59, 0xF86B, 0x6D1C, 0x1C85, 0x9BB1, 0x3373, 0x763F, 0x4EBE, 0x1BF3, 0x99B5,
   0xD721, 0x978F, 0xCF5C, 0xAC51, 0x0984, 0x7462, 0x8F0C, 0x2817, 0x4AD9, 0xFD41, 0x6678, 0x7C85, 0xD330, 0xC9F8, 0x1D9A, 0xC622},
  {0x5AE4, 0xE16A, 0x60F6, 0xFD45, 0x668C, 0x29D6, 0x0285, 0x6B92, 0x92C2, 0x21DE, 0x45E0, 0xEF3D, 0x8B0D, 0x02CD, 0x0198, 0x0100,
   0x9E6D, 0x4D38, 0xDEF9, 0xE6F2, 0xF72E, 0xB313, 0x14F2, 0x390A, 0x2D67, 0xC71E, 0xCB69, 0x7F66, 0xD3CF, 0x7F8A, 0x81D9, 0x9DDE},
  {0x85E3, 0x8F29, 0x36EB, 0xC968, 0x3696, 0x59F6, 0x7832, 0xA78B, 0xA1D8, 0xF5CF, 0xAB64, 0x646D, 0x7A2A, 0xBAF8, 0xAA87, 0x41C7,
   0x5120, 0xDE78, 0x738D, 0xDC1A, 0x268D, 0x5DF8, 0xED69, 0x1C8A, 0xBC85, 0x3DCD, 0xAE30, 0x0F8D, 0xEC89, 0x3ABD, 0x0166, 0x0100},
  {0xB8BD, 0x643B, 0x748E, 0xBD63, 0xEC6F, 0xE23A, 0x9493, 0xDD76, 0x0A62, 0x774F, 0xCD68, 0xA67A, 0x9A23, 0xC8A8, 0xBDE5, 0x9D1B,
   0x2B86, 0x8B36, 0x5428, 0x1DFB, 0xCD1D, 0x0713, 0x29C2, 0x8E8E, 0x5207, 0xA13F, 0x6005, 0x4F5E, 0x52E0, 0xE7C8, 0x6D1C, 0x3E34},
  {0x581D, 0x2BFA, 0x5E1D, 0xA891, 0x1069, 0x1DA4, 0x39A0, 0xBE45, 0x5B9A, 0x7333, 0x6F3E, 0x8637, 0xA550, 0xC9E9, 0x5C6C, 0x42BA,
   0xA712, 0xC3EA, 0x3808, 0x0910, 0xAA4D, 0x5B25, 0xABCD, 0xE680, 0x96AD, 0x2CEC, 0x8EBB, 0xA47D, 0x1690, 0xE8FB, 0x01C8, 0x0100},
  {0x73B9, 0x82BC, 0x9EBC, 0xB130, 0x0DA5, 0x8617, 0x9F7B, 0x9766, 0x205D, 0x752D, 0xB05C, 0x2A17, 0xA75C, 0x18EF, 0x8339, 0xFD34,
   0x8DA2, 0x7970, 0xD0B4, 0x70F1, 0x3765, 0x7380, 0x7CAF, 0x570E, 0x6440, 0xBC44, 0x0743, 0x2D02, 0x0419, 0xA240, 0x2113, 0x1AD4},
  {0x1EB5, 0xBBFF, 0x39B1, 0x3209, 0x705F, 0x15F4, 0xD7AD, 0x340B, 0xC2A6, 0x25CA, 0xF412, 0x9570, 0x0F4F, 0xE4D5, 0x1614, 0xE464,
   0x911A, 0x0F0E, 0x07DA, 0xA929, 0x2379, 0xD988, 0x0AA6, 0x3B57, 0xBF63, 0x71FB, 0x72D5, 0x26CE, 0xB0AF, 0xCF45, 0x011B, 0x0100},
  {0x9999, 0x98FE, 0xA108, 0x6588, 0xF90B, 0x4554, 0xFF38, 0x4642, 0x8F5F, 0x6CC3, 0x4E8E, 0xFF7E, 0x64C2, 0x50CA, 0x0E7F, 0xAD7D,
   0x6AAB, 0x33C1, 0xE1F4, 0x6165, 0x7894, 0x83B9, 0x0A0C, 0x38AF, 0x5803, 0x18C0, 0xFA36, 0x592C, 0x4548, 0xABB8, 0x1527, 0xAEE9}
};

static const unsigned short Hash3[] = { 0x0123, 0x4567, 0x89AB, 0xCDEF, 0xF861, 0xCB52 };
static const unsigned char Hash4[] = { 0x0B, 0x04, 0x07, 0x08, 0x05, 0x09, 0x0B, 0x0A, 0x07, 0x02, 0x0A, 0x05, 0x04, 0x08, 0x0D, 0x0F };

//////  ====================================================================================

static unsigned char CW1[8], CW2[8];

extern int io_serial_need_dummy_char;

static void Manage_Tag(unsigned char *Answer)
{
  unsigned char Tag, Len, Len2;
  bool Valid_0x55 = 0;
  unsigned char *Body;
  unsigned char Buffer[0x10];
  int a = 0x13;
  Len2 = Answer[4];
  while (a < Len2) {
    Tag = Answer[a];
    Len = Answer[a + 1];
    Body = Answer + a + 2;
    switch (Tag) {
    case 0x55:
      {
	if (Body[0] == 0x84)	//Tag 0x56 has valid data...
	  Valid_0x55 = 1;
      }
      break;
    case 0x56:
      {
	memcpy(Buffer + 8, Body, 8);
      }
      break;
    }
    a += Len + 2;

  }
  if (Valid_0x55) {
    memcpy(Buffer, Answer + 5, 8);	//Copy original DW 
    memcpy(CW1, Buffer, 8);	//Now copy calculated DW in right place
  }
}

static int status_ok(const unsigned char *status)
{
  //cs_log("[videoguard1-reader] check status %02x%02x", status[0],status[1]);
  return (status[0] == 0x90 || status[0] == 0x91)
      && (status[1] == 0x00 || status[1] == 0x01 || status[1] == 0x20 || status[1] == 0x21 || status[1] == 0x80 || status[1] == 0x81 || status[1] == 0xa0 || status[1] == 0xa1);
}

static int read_cmd_len(struct s_reader *reader, const unsigned char *cmd)
{
  def_resp;
  unsigned char cmd2[5];
  memcpy(cmd2, cmd, 5);
  cmd2[3] = 0x00;		// NDS1 try 0x00 not 0x80
  cmd2[4] = 0x01;
  // some card reply with L 91 00 (L being the command length).

  if (!write_cmd_vg(cmd2, NULL) || !status_ok(cta_res + 1)) {
    cs_debug("[videoguard1-reader] failed to read %02x%02x cmd length (%02x %02x)", cmd[1], cmd[2], cta_res[1], cta_res[2]);
    return -1;
  }
  return cta_res[0];
}

static int do_cmd(struct s_reader *reader, const unsigned char *ins, const unsigned char *txbuff, unsigned char *rxbuff, unsigned char *cta_res)
{
  ushort cta_lr;
  unsigned char ins2[5];
  memcpy(ins2, ins, 5);
  unsigned char len = 0;
  len = ins2[4];

  unsigned char tmp[264];
  if (!rxbuff) {
    rxbuff = tmp;
  }

  if (txbuff == NULL) {
    if (!write_cmd_vg(ins2, NULL) || !status_ok(cta_res + len)) {
      return -1;
    }
    memcpy(rxbuff, ins2, 5);
    memcpy(rxbuff + 5, cta_res, len);
    memcpy(rxbuff + 5 + len, cta_res + len, 2);
  } else {
    if (!write_cmd_vg(ins2, (uchar *) txbuff) || !status_ok(cta_res)) {
      return -2;
    }
    memcpy(rxbuff, ins2, 5);
    memcpy(rxbuff + 5, txbuff, len);
    memcpy(rxbuff + 5 + len, cta_res, 2);
  }

  if (ins2[1] == 0x54) {
    memcpy(CW1, rxbuff + 5, 8);
    //set to 0 so client will know it is not valid if not overwritten with valid cw
    memset(CW2, 0, 8);
    int ind;
    for (ind = 13; ind < len + 13 - 8; ind++) {
      if (rxbuff[ind] == 0x25) {
	//memcpy(CW2,rxbuff+5+ind+2,8);
	//tested on viasat 093E, sky uk 0963, sky it 919
	//don't care whether cw is 0 or not
	memcpy(CW2, rxbuff + ind + 3, 8);
	break;
      }
    }
  }

  Manage_Tag(rxbuff);
  return len;
}

static void rev_date_calc(const unsigned char *Date, int *year, int *mon, int *day, int *hh, int *mm, int *ss)
{
  *year = (Date[0] / 12) + VG1_BASEYEAR;
  *mon = (Date[0] % 12) + 1;
  *day = Date[1] & 0x1f;
  *hh = Date[2] / 8;
  *mm = (0x100 * (Date[2] - *hh * 8) + Date[3]) / 32;
  *ss = (Date[3] - *mm * 32) * 2;
}

static void read_tiers(struct s_reader *reader)
{
  def_resp;
  static const unsigned char ins2a[5] = {  0x48, 0x2a, 0x00, 0x00, 0x00  };
  int l;

  return; // Not working at present so just do nothing

  l = do_cmd(reader, ins2a, NULL, NULL, cta_res);
//  if (l < 0 || !status_ok(cta_res + l))
//  {
//    return;
//  }
  static unsigned char ins76[5] = { 0x48, 0x76, 0x00, 0x00, 0x00 };
  ins76[3] = 0x7f;
  ins76[4] = 2;
  if (!write_cmd_vg(ins76, NULL) || !status_ok(cta_res + 2)) {
    return;
  }
  ins76[3] = 0;
  ins76[4] = 0x0a;
  int num = cta_res[1];
  int i;
#ifdef CS_RDR_INIT_HIST
  reader->init_history_pos = 0;	//reset for re-read
  memset(reader->init_history, 0, sizeof(reader->init_history));
#endif
  for (i = 0; i < num; i++) {
    ins76[2] = i;
    l = do_cmd(reader, ins76, NULL, NULL, cta_res);
    if (l < 0 || !status_ok(cta_res + l)) {
      return;
    }
    if (cta_res[2] == 0 && cta_res[3] == 0) {
      break;
    }
    int y, m, d, H, M, S;
    rev_date_calc(&cta_res[4], &y, &m, &d, &H, &M, &S);
    unsigned short tier_id = (cta_res[2] << 8) | cta_res[3];
    char *tier_name = get_tiername(tier_id, reader->caid[0]);
    cs_ri_log(reader, "[videoguard1-reader] tier: %04x, expiry date: %04d/%02d/%02d-%02d:%02d:%02d %s", tier_id, y, m, d, H, M, S, tier_name);
  }
}

int videoguard1_card_init(struct s_reader *reader, ATR newatr)
{

  /* known class 48 only atrs */
    NDS_ATR_ENTRY nds1_atr_table[]={ // {atr}, atr len, base year, description
        {{ 0x3F, 0x78, 0x13, 0x25, 0x04, 0x40, 0xB0, 0x09, 0x4A, 0x50, 0x01, 0x4E, 0x5A }, 13, 1992, "VideoGuard Sky New Zealand (0969)"},
        {{0},0,0,NULL},
        };

  get_hist;
  // 40 B0 09 4A 50 01 4E 5A 
  if ((hist_size < 7) || (hist[1] != 0xB0) || (hist[2] != 0x09) || (hist[3] != 0x4A) || (hist[4] != 0x50)) {
    return ERROR;
    cs_log("history size = %i, hist1 = 0x%x, hist2 = 0x%x, hist3 = 0x%x, hist4 = 0x%x", hist_size, hist[1], hist[2], hist[3], hist[4]);
  }

  cs_log("history size = %i, hist1 = 0x%x, hist2 = 0x%x, hist3 = 0x%x, hist4 = 0x%x", hist_size, hist[1], hist[2], hist[3], hist[4]);

  get_atr;
  def_resp;
    int i=0;
    while(nds1_atr_table[i].desc) {
        if ((atr_size == nds1_atr_table[i].atr_len) && (memcmp (atr, nds1_atr_table[i].atr, atr_size) == 0)) {
            VG1_BASEYEAR=nds1_atr_table[i].base_year;
            cs_ri_log(reader, "[videoguard1-reader] type: %s", nds1_atr_table[i].desc);
            break;
        }
        i++;
    }
    if(!nds1_atr_table[i].desc)
        return ERROR; // unknown ATR... probably not NDS1

  // NDS1 NZ Class 48 cards do not respond to do_cmd(ins7416)
  // nor do they return list of valid command therefore do not even try
  // Need to tell class 48 only cards the length as they do not return the real length

  cs_log("[videoguard1-reader] This version is in test and is not working, please submit -d 255 logs.  Thanks");


  int l = 0;
  unsigned char buff[256];

  unsigned char ins36[5] = { 0x48, 0x36, 0x00, 0x00, 0x90 };
  unsigned char boxID[4];

  // NDS V1 NZ Cards return 9 as length
  // use this to check we have the right card
  l = read_cmd_len(reader, ins36);
  if (l != 9) {
    cs_log("[videoguard1-reader] ins36 length 0x%x", l);
    //return ERROR;
  }

// if (reader->boxid > 0)
//  {
//    /* the boxid is specified in the config */
//    int i;
//    for (i = 0; i < 4; i++)
//    {
//      boxID[i] = (reader->boxid >> (8 * (3 - i))) % 0x100;
//    }
//  }
//  else
//  { 

  /* we can try to get the boxid from the card */
  int boxidOK = 0;
  l = do_cmd(reader, ins36, NULL, buff, cta_res);
  if (buff[7] > 0x0F) {
    cs_log("[videoguard1-reader] ins36: encrypted - can't parse");
  } else {
    /* skipping the initial fixed fields: cmdecho (4) + length (1) + encr/rev++ (4) */
    int i = 9;
    int gotUA = 0;
    while (i < l) {
      if (!gotUA && buff[i] < 0xF0) {	/* then we guess that the next 4 bytes is the UA */
	gotUA = 1;
	i += 4;
      } else {
	switch (buff[i]) {	/* object length vary depending on type */
	case 0x00:		/* padding */
	  {
	    i += 1;
	    break;
	  }
	case 0xEF:		/* card status */
	  {
	    i += 3;
	    break;
	  }
	case 0xD1:
	  {
	    i += 4;
	    break;
	  }
	case 0xDF:		/* next server contact */
	  {
	    i += 5;
	    break;
	  }
	case 0xF3:		/* boxID */
	  {
	    memcpy(&boxID, &buff[i + 1], sizeof(boxID));
	    boxidOK = 1;
	    i += 5;
	    break;
	  }
	case 0xF6:
	  {
	    i += 6;
	    break;
	  }
	case 0xFC:		/* No idea seems to with with NDS1 */
	  {
	    i += 14;
	    break;
	  }
	case 0x01:		/* date & time */
	  {
	    i += 7;
	    break;
	  }
	case 0xFA:
	  {
	    i += 9;
	    break;
	  }
	case 0x5E:
	case 0x67:		/* signature */
	case 0xDE:
	case 0xE2:
	case 0xE9:		/* tier dates */
	case 0xF8:		/* Old PPV Event Record */
	case 0xFD:
	  {
	    i += buff[i + 1] + 2;	/* skip length + 2 bytes (type and length) */
	    break;
	  }
	default:		/* default to assume a length byte */
	  {
	    cs_log("[videoguard1-reader] ins36 returned unknown type=0x%02X - parsing may fail", buff[i]);
	    i += buff[i + 1] + 2;
	  }
	}
      }
    }
  }

  if (!boxidOK) {
    cs_log("[videoguard1-reader] no boxID available");
    // return ERROR;
  } else {
    cs_log("[videguard1nz-reader] calculated BoxID: %02X%02X%02X%02X", boxID[0], boxID[1], boxID[2], boxID[3]);
  }
  // }

  // Move this here on a temp basis
  if (reader->boxid > 0) {
    /* the boxid is specified in the config */
    int i;
    for (i = 0; i < 4; i++) {
      boxID[i] = (reader->boxid >> (8 * (3 - i))) % 0x100;
    }
    cs_log("[videguard1nz-reader] config BoxID: %02X%02X%02X%02X", boxID[0], boxID[1], boxID[2], boxID[3]);
  }

  // Send BoxID
  unsigned char ins4C[5] = { 0x48, 0x4C, 0x00, 0x00, 0x09 };
  unsigned char payload4C[9] = { 0, 0, 0, 0, 3, 0, 0, 0, 4 };
  memcpy(payload4C, boxID, 4);
  if (!write_cmd_vg(ins4C, payload4C) || !status_ok(cta_res + l)) {
    cs_log("[videoguard1-reader] sending boxid failed");
    // return ERROR;
  }
  // NDS1 Class 48 only needs a very basic initialisation
  // Need to tell ins58 the length

  unsigned char ins58[5] = { 0x48, 0x58, 0x00, 0x00, 0x17 };

  // temp test what command length returns - comment out as breaks initialisation
//  l = read_cmd_len(reader, ins58);
//  cs_log("[videoguard1-reader] ins58 length 0x%x", l);

  l = do_cmd(reader, ins58, NULL, buff, cta_res);
  if (l < 0) {
    cs_log("[videoguard1-reader] cmd ins58 failed");
    return ERROR;
  }

  memset(reader->hexserial, 0, 8);
  memcpy(reader->hexserial + 2, cta_res + 1, 4);
  memcpy(reader->sa, cta_res + 1, 3);
  reader->caid[0] = cta_res[24] * 0x100 + cta_res[25];
  /* we have one provider, 0x0000 */
  reader->nprov = 1;
  memset(reader->prid, 0x00, sizeof(reader->prid));
  cs_ri_log(reader,
	    "[videoguard1-reader] type: VideoGuard, caid: %04X, serial: %02X%02X%02X%02X, BoxID: %02X%02X%02X%02X",
	    reader->caid[0], reader->hexserial[2], reader->hexserial[3], reader->hexserial[4], reader->hexserial[5], boxID[0], boxID[1], boxID[2], boxID[3]);

  /* Force caid until can figure out how to get it */
  reader->caid[0] = 0x9 * 0x100 + 0x69;
  cs_ri_log(reader,
	    "[videoguard1-reader] type: VideoGuard, caid: %04X, serial: %02X%02X%02X%02X, BoxID: %02X%02X%02X%02X",
	    reader->caid[0], reader->hexserial[2], reader->hexserial[3], reader->hexserial[4], reader->hexserial[5], boxID[0], boxID[1], boxID[2], boxID[3]);
  cs_log("[videoguard1-reader] Testing ONLY - ready for requests");



  return OK;
}

static void do_post_dw_hash(unsigned char *cw, unsigned char *ecm_header_data)
{
  int i, ecmi, ecm_header_count;
  unsigned char buffer[0x80];
  unsigned char md5_digest[0x10];
  //ecm_header_data = 01 03 b0 01 01
  if (!cw_is_valid(cw))		//if cw is all zero, keep it that way
  {
    return;
  }
  ecm_header_count = ecm_header_data[0];
  for (i = 0, ecmi = 1; i < ecm_header_count; i++) {
    if (ecm_header_data[ecmi + 1] != 0xb0) {
      ecmi += ecm_header_data[ecmi] + 1;
    } else {
      switch (ecm_header_data[ecmi + 2]) {	//b0 01
      case 1:
	{
	  unsigned short hk[8], i, j, m = 0;
	  for (i = 0; i < 6; i++)
	    hk[2 + i] = Hash3[i];
	  for (i = 0; i < 2; i++) {
	    for (j = 0; j < 0x48; j += 2) {
	      if (i) {
		hk[0] = ((hk[3] & hk[5]) | ((~hk[5]) & hk[4]));
	      } else {
		hk[0] = ((hk[3] & hk[4]) | ((~hk[3]) & hk[5]));
	      }
	      if (j < 8) {
		hk[0] = (hk[0] + ((cw[j + 1] << 8) | cw[j]));
	      }
	      if (j == 8) {
		hk[0] = (hk[0] + 0x80);
	      }
	      hk[0] = (hk[0] + hk[2] + (0xFF & NdTabB001[ecm_header_data[ecmi + 3]][m >> 1] >> ((m & 1) << 3)));
	      hk[1] = hk[2];
	      hk[2] = hk[3];
	      hk[3] = hk[4];
	      hk[4] = hk[5];
	      hk[5] = hk[6];
	      hk[6] = hk[7];
	      hk[7] = hk[2] + (((hk[0] << Hash4[m & 0xF]) | (hk[0] >> (0x10 - Hash4[m & 0xF]))));
	      m = (m + 1) & 0x3F;
	    }
	  }
	  for (i = 0; i < 6; i++) {
	    hk[2 + i] += Hash3[i];
	  }
	  for (i = 0; i < 7; i++) {
	    cw[i] = hk[2 + (i >> 1)] >> ((i & 1) << 3);
	  }
	  cw[3] = (cw[0] + cw[1] + cw[2]) & 0xFF;
	  cw[7] = (cw[4] + cw[5] + cw[6]) & 0xFF;
	  cs_ddump(cw, 8, "Postprocessed2 Case 1 DW:");
	  break;
	}
      case 3:
	{
	  memset(buffer, 0, sizeof(buffer));
	  memcpy(buffer, cw, 8);
	  memcpy(buffer + 8, &ecm_header_data[ecmi + 3], ecm_header_data[ecmi] - 2);
	  MD5(buffer, 8 + ecm_header_data[ecmi] - 2, md5_digest);
	  memcpy(cw, md5_digest, 8);
	  cs_ddump(cw, 8, "Postprocessed2 Case 3 DW:");
	  break;
	}
      case 2:
	{
	  /* Method 2 left out */
	  //memcpy(DW_OUTPUT, DW_INPUT, 8);
	  break;
	}
      }
    }
  }
}

int videoguard1_do_ecm(struct s_reader *reader, ECM_REQUEST * er)
{
  unsigned char cta_res[CTA_RES_LEN];
  static unsigned char ins40[5] = { 0x48, 0x40, 0x00, 0x80, 0xFF };
  static const unsigned char ins54[5] = { 0x48, 0x54, 0x00, 0x00, 0x2C };
  int posECMpart2 = er->ecm[6] + 7;
  int lenECMpart2 = er->ecm[posECMpart2] + 1;
  unsigned char tbuff[264];
  tbuff[0] = 0;
  memcpy(&tbuff[1], &(er->ecm[posECMpart2 + 1]), lenECMpart2 - 1);
  ins40[4] = lenECMpart2;
  int l;
  l = do_cmd(reader, ins40, tbuff, NULL, cta_res);
  if (l > 0 && status_ok(cta_res)) {
    l = do_cmd(reader, ins54, NULL, NULL, cta_res);
    if (l > 0 && status_ok(cta_res + l)) {
      if (!cw_is_valid(CW1))	//sky cards report 90 00 = ok but send cw = 00 when channel not subscribed
      {
	snprintf(er->msglog, MSGLOGSIZE, "9000 but cw=00 -> channel not subscribed ");
	return ERROR;
      }
      if (er->ecm[0] & 1) {
	memcpy(er->cw + 8, CW1, 8);
	memcpy(er->cw + 0, CW2, 8);
      } else {
	memcpy(er->cw + 0, CW1, 8);
	memcpy(er->cw + 8, CW2, 8);
      }

      //test for postprocessing marker
      int posB0 = -1;
      int i;
      for (i = 6; i < posECMpart2; i++) {
	if (er->ecm[i - 3] == 0x80 && er->ecm[i] == 0xB0 && ((er->ecm[i + 1] == 0x01) || (er->ecm[i + 1] == 0x02) || (er->ecm[i + 1] == 0x03))) {
	  posB0 = i;
	  break;
	}
      }

      if (posB0 != -1) {
	do_post_dw_hash(er->cw + 0, &er->ecm[posB0 - 2]);
	do_post_dw_hash(er->cw + 8, &er->ecm[posB0 - 2]);
      }

      return OK;
    }
  }
  snprintf(er->msglog, MSGLOGSIZE, "(%d) status not ok %02x %02x", l, cta_res[0], cta_res[1]);
  return ERROR;
}

static int num_addr(const unsigned char *data)
{
  return ((data[3] & 0x30) >> 4) + 1;
}

/*
Example of GLOBAL EMM's
This one has IRD-EMM + Card-EMM
82 70 20 00 02 06 02 7D 0E 89 53 71 16 90 14 40
01 ED 17 7D 9E 1F 28 CF 09 97 54 F1 8E 72 06 E7
51 AF F5
This one has only IRD-EMM
82 70 6D 00 07 69 01 30 07 14 5E 0F FF FF 00 06 
00 0D 01 00 03 01 00 00 00 0F 00 00 00 5E 01 00 
01 0C 2E 70 E4 55 B6 D2 34 F7 44 86 9E 5C 91 14
81 FC DF CB D0 86 65 77 DF A9 E1 6B A8 9F 9B DE
90 92 B9 AA 6C B3 4E 87 D2 EC 92 DA FC 71 EF 27 
B3 C3 D0 17 CF 0B D6 5E 8C DB EB B3 37 55 6E 09 
7F 27 3C F1 85 29 C9 4E 0B EE DF 68 BE 00 C9 00
*/
static const unsigned char *payload_addr(uchar emmtype, const unsigned char *data, const unsigned char *a)
{
  int s;
  int l;
  const unsigned char *ptr = NULL;
  int position = -1;
  int numAddrs = 0;
  switch (emmtype) {
  case SHARED:
    {
      s = 3;
      break;
    }
  case UNIQUE:
    {
      s = 4;
      break;
    }
  default:
    {
      s = 0;
    }
  }

  numAddrs = num_addr(data);
  if (s > 0) {
    for (l = 0; l < numAddrs; l++) {
      if (!memcmp(&data[l * 4 + 4], a + 2, s)) {
	position = l;
	break;
      }
    }
  }

  int num_filter = (position == -1) ? 0 : numAddrs;
  /* skip header and the filter list */
  ptr = data + 4 + 4 * num_filter;
  if (*ptr != 0x02 && *ptr != 0x07)	// some clients omit 00 00 separator */
  {
    ptr += 2;			// skip 00 00 separator
    if (*ptr == 0x00)
      ptr++;			// skip optional 00
    ptr++;			// skip the 1st bitmap len
  }

  /* check for IRD-EMM */
  if (*ptr != 0x02 && *ptr != 0x07) {
    return NULL;
  }

  /* skip IRD-EMM part, 02 00 or 02 06 xx aabbccdd yy */
  ptr += 2 + ptr[1];
  /* check for EMM boundaries - ptr should not exceed EMM length */
  if ((int) (ptr - (data + 3)) >= data[2]) {
    return NULL;
  }

  for (l = 0; l < position; l++) {
    /* skip the payload of the previous sub-EMM */
    ptr += 1 + ptr[0];
    /* check for EMM boundaries - ptr should not exceed EMM length */
    if ((int) (ptr - (data + 3)) >= data[2]) {
      return NULL;
    }

    /* skip optional 00 */
    if (*ptr == 0x00) {
      ptr++;
    }

    /* skip the bitmap len */
    ptr++;
    /* check for IRD-EMM */
    if (*ptr != 0x02 && *ptr != 0x07) {
      return NULL;
    }

    /* skip IRD-EMM part, 02 00 or 02 06 xx aabbccdd yy */
    ptr += 2 + ptr[1];
  }

  return ptr;
}

int videoguard1_get_emm_type(EMM_PACKET * ep, struct s_reader *rdr)
{

/*
82 30 ad 70 00 XX XX XX 00 XX XX XX 00 XX XX XX 00 XX XX XX 00 00 
d3 02 00 22 90 20 44 02 4a 50 1d 88 ab 02 ac 79 16 6c df a1 b1 b7 77 00 ba eb 63 b5 c9 a9 30 2b 43 e9 16 a9 d5 14 00 
d3 02 00 22 90 20 44 02 13 e3 40 bd 29 e4 90 97 c3 aa 93 db 8d f5 6b e4 92 dd 00 9b 51 03 c9 3d d0 e2 37 44 d3 bf 00
d3 02 00 22 90 20 44 02 97 79 5d 18 96 5f 3a 67 70 55 bb b9 d2 49 31 bd 18 17 2a e9 6f eb d8 76 ec c3 c9 cc 53 39 00 
d2 02 00 21 90 1f 44 02 99 6d df 36 54 9c 7c 78 1b 21 54 d9 d4 9f c1 80 3c 46 10 76 aa 75 ef d6 82 27 2e 44 7b 00
*/

  int i, pos;
  int serial_count = ((ep->emm[3] >> 4) & 3) + 1;
  int serial_len = (ep->emm[3] & 0x80) ? 3 : 4;
  uchar emmtype = (ep->emm[3] & VG1_EMMTYPE_MASK) >> 6;
  pos = 4 + (serial_len * serial_count) + 2;
  switch (emmtype) {
  case VG1_EMMTYPE_G:
    {
      ep->type = GLOBAL;
      cs_debug_mask(D_EMM, "VIDEOGUARD1 EMM: GLOBAL");
      return TRUE;
    }
  case VG1_EMMTYPE_U:
    {
      cs_debug_mask(D_EMM, "VIDEOGUARD1 EMM: UNIQUE");
      ep->type = UNIQUE;
      if (ep->emm[1] == 0)	// detected UNIQUE EMM from cccam (there is no serial)
      {
	return TRUE;
      }

      for (i = 1; i <= serial_count; i++) {
	if (!memcmp(rdr->hexserial + 2, ep->emm + (serial_len * i), serial_len)) {
	  memcpy(ep->hexserial, ep->emm + (serial_len * i), serial_len);
	  return TRUE;
	}

	pos = pos + ep->emm[pos + 5] + 5;
      }
      return FALSE;		// if UNIQUE but no serial match return FALSE
    }
  case VG1_EMMTYPE_S:
    {
      ep->type = SHARED;
      cs_debug_mask(D_EMM, "VIDEOGUARD1 EMM: SHARED");
      return TRUE;		// FIXME: no check for SA
    }
  default:
    {
      if (ep->emm[pos - 2] != 0x00 && ep->emm[pos - 1] != 0x00 && ep->emm[pos - 1] != 0x01) {
	//remote emm without serial
	ep->type = UNKNOWN;
	return TRUE;
      }
      return FALSE;
    }
  }
}

void videoguard1_get_emm_filter(struct s_reader *rdr, uchar * filter)
{
  filter[0] = 0xFF;
  filter[1] = 3;
  //ToDo videoguard1_get_emm_filter basic construction
  filter[2] = UNIQUE;
  filter[3] = 0;
  filter[4 + 0] = 0x82;
  filter[4 + 0 + 16] = 0xFF;
  memcpy(filter + 4 + 2, rdr->hexserial + 2, 4);
  memset(filter + 4 + 2 + 16, 0xFF, 4);
  filter[36] = UNIQUE;
  filter[37] = 0;
  filter[38 + 0] = 0x82;
  filter[38 + 0 + 16] = 0xFF;
  memcpy(filter + 38 + 6, rdr->hexserial + 2, 4);
  memset(filter + 38 + 6 + 16, 0xFF, 4);
  filter[70] = UNIQUE;
  filter[71] = 0;
  filter[72 + 0] = 0x82;
  filter[72 + 0 + 16] = 0xFF;
  memcpy(filter + 72 + 10, rdr->hexserial + 2, 4);
  memset(filter + 72 + 10 + 16, 0xFF, 4);
  /* filter[104]=UNIQUE;
     filter[105]=0;

     filter[106+0]    = 0x82;
     filter[106+0+16] = 0xFF;

     memcpy(filter+106+14, rdr->hexserial+2, 2);
     memset(filter+106+14+16, 0xFF, 2); */
  return;
}

int videoguard1_do_emm(struct s_reader *reader, EMM_PACKET * ep)
{
  unsigned char cta_res[CTA_RES_LEN];
  unsigned char ins42[5] = {
    0x48, 0x42, 0x00, 0x00, 0xFF
  };
  int rc = ERROR;
  const unsigned char *payload = payload_addr(ep->type, ep->emm, reader->hexserial);
  while (payload) {
    ins42[4] = *payload;
    int l = do_cmd(reader, ins42, payload + 1, NULL, cta_res);
    if (l > 0 && status_ok(cta_res)) {
      rc = OK;
    }

    cs_debug_mask(D_EMM, "[videoguard1-reader] EMM request return code : %02X%02X", cta_res[0], cta_res[1]);
    //cs_dump(ep->emm, 64, "EMM:");
    if (status_ok(cta_res) && (cta_res[1] & 0x01)) {
      read_tiers(reader);
    }

    if (num_addr(ep->emm) == 1 && (int) (&payload[1] - &ep->emm[0]) + *payload + 1 < ep->l) {
      payload += *payload + 1;
      if (*payload == 0x00) {
	++payload;
      }
      ++payload;
      if (*payload != 0x02) {
	break;
      }
      payload += 2 + payload[1];
    } else {
      payload = 0;
    }

  }

  return (rc);
}

int videoguard1_card_info(struct s_reader *reader)
{
  /* info is displayed in init, or when processing info */
  cs_log("[videoguard1-reader] card detected");
  cs_log("[videoguard1-reader] type: VideoGuard");
  read_tiers(reader);
  return OK;
}
