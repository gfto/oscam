#include "globals.h"
#include "reader-common.h"

extern uchar cta_cmd[], cta_res[];
extern ushort cta_lr;

#define CMD_LEN 5

static unsigned char nds_Seed[] = {
  0x56, 0x01, 0x40, 0x00, 0x20, 0x00,
  0xB9, 0xD5, 0xEF, 0xD5, 0xF5, 0xD5, 0xFB, 0xD5, 0x31, 0xD6, 0x43, 0xD6, 0x55, 0xD6, 0x61, 0xD6, 0x85, 0xD6, 0x9D,
    0xD6, 0xAF, 0xD6, 0xC7, 0xD6, 0xD9, 0xD6, 0x09, 0xD7, 0x15, 0xD7, 0x21, 0xD7, 0x27, 0xD7, 0x3F, 0xD7, 0x45, 0xD7,
    0xB1, 0xD7, 0xBD, 0xD7, 0xDB, 0xD7, 0x11, 0xD8, 0x23, 0xD8, 0x29, 0xD8, 0x2F, 0xD8, 0x4D, 0xD8, 0x8F, 0xD8, 0xA1,
    0xD8, 0xAD, 0xD8, 0xBF, 0xD8, 0xD7, 0xD8,
  0x01, 0x00, 0xCF, 0x13, 0xE0, 0x60, 0x54, 0xAC, 0xAB, 0x99, 0xE6, 0x0C, 0x9F, 0x5B, 0x91, 0xB9, 0x72, 0x72, 0x4D,
    0x5B, 0x5F, 0xD3, 0xB7, 0x5B, 0x01, 0x4D, 0xEF, 0x9E, 0x6B, 0x8A, 0xB9, 0xD1, 0xC9, 0x9F, 0xA1, 0x2A, 0x8D, 0x86,
    0xB6, 0xD6, 0x39, 0xB4, 0x64, 0x65, 0x13, 0x77, 0xA1, 0x0A, 0x0C, 0xCF, 0xB4, 0x2B, 0x3A, 0x2F, 0xD2, 0x09, 0x92,
    0x15, 0x40, 0x47, 0x66, 0x5C, 0xDA, 0xC9
};

static const u32 Te4[256] = {
  0x63636363U, 0x7c7c7c7cU, 0x77777777U, 0x7b7b7b7bU,
  0xf2f2f2f2U, 0x6b6b6b6bU, 0x6f6f6f6fU, 0xc5c5c5c5U,
  0x30303030U, 0x01010101U, 0x67676767U, 0x2b2b2b2bU,
  0xfefefefeU, 0xd7d7d7d7U, 0xababababU, 0x76767676U,
  0xcacacacaU, 0x82828282U, 0xc9c9c9c9U, 0x7d7d7d7dU,
  0xfafafafaU, 0x59595959U, 0x47474747U, 0xf0f0f0f0U,
  0xadadadadU, 0xd4d4d4d4U, 0xa2a2a2a2U, 0xafafafafU,
  0x9c9c9c9cU, 0xa4a4a4a4U, 0x72727272U, 0xc0c0c0c0U,
  0xb7b7b7b7U, 0xfdfdfdfdU, 0x93939393U, 0x26262626U,
  0x36363636U, 0x3f3f3f3fU, 0xf7f7f7f7U, 0xccccccccU,
  0x34343434U, 0xa5a5a5a5U, 0xe5e5e5e5U, 0xf1f1f1f1U,
  0x71717171U, 0xd8d8d8d8U, 0x31313131U, 0x15151515U,
  0x04040404U, 0xc7c7c7c7U, 0x23232323U, 0xc3c3c3c3U,
  0x18181818U, 0x96969696U, 0x05050505U, 0x9a9a9a9aU,
  0x07070707U, 0x12121212U, 0x80808080U, 0xe2e2e2e2U,
  0xebebebebU, 0x27272727U, 0xb2b2b2b2U, 0x75757575U,
  0x09090909U, 0x83838383U, 0x2c2c2c2cU, 0x1a1a1a1aU,
  0x1b1b1b1bU, 0x6e6e6e6eU, 0x5a5a5a5aU, 0xa0a0a0a0U,
  0x52525252U, 0x3b3b3b3bU, 0xd6d6d6d6U, 0xb3b3b3b3U,
  0x29292929U, 0xe3e3e3e3U, 0x2f2f2f2fU, 0x84848484U,
  0x53535353U, 0xd1d1d1d1U, 0x00000000U, 0xededededU,
  0x20202020U, 0xfcfcfcfcU, 0xb1b1b1b1U, 0x5b5b5b5bU,
  0x6a6a6a6aU, 0xcbcbcbcbU, 0xbebebebeU, 0x39393939U,
  0x4a4a4a4aU, 0x4c4c4c4cU, 0x58585858U, 0xcfcfcfcfU,
  0xd0d0d0d0U, 0xefefefefU, 0xaaaaaaaaU, 0xfbfbfbfbU,
  0x43434343U, 0x4d4d4d4dU, 0x33333333U, 0x85858585U,
  0x45454545U, 0xf9f9f9f9U, 0x02020202U, 0x7f7f7f7fU,
  0x50505050U, 0x3c3c3c3cU, 0x9f9f9f9fU, 0xa8a8a8a8U,
  0x51515151U, 0xa3a3a3a3U, 0x40404040U, 0x8f8f8f8fU,
  0x92929292U, 0x9d9d9d9dU, 0x38383838U, 0xf5f5f5f5U,
  0xbcbcbcbcU, 0xb6b6b6b6U, 0xdadadadaU, 0x21212121U,
  0x10101010U, 0xffffffffU, 0xf3f3f3f3U, 0xd2d2d2d2U,
  0xcdcdcdcdU, 0x0c0c0c0cU, 0x13131313U, 0xececececU,
  0x5f5f5f5fU, 0x97979797U, 0x44444444U, 0x17171717U,
  0xc4c4c4c4U, 0xa7a7a7a7U, 0x7e7e7e7eU, 0x3d3d3d3dU,
  0x64646464U, 0x5d5d5d5dU, 0x19191919U, 0x73737373U,
  0x60606060U, 0x81818181U, 0x4f4f4f4fU, 0xdcdcdcdcU,
  0x22222222U, 0x2a2a2a2aU, 0x90909090U, 0x88888888U,
  0x46464646U, 0xeeeeeeeeU, 0xb8b8b8b8U, 0x14141414U,
  0xdedededeU, 0x5e5e5e5eU, 0x0b0b0b0bU, 0xdbdbdbdbU,
  0xe0e0e0e0U, 0x32323232U, 0x3a3a3a3aU, 0x0a0a0a0aU,
  0x49494949U, 0x06060606U, 0x24242424U, 0x5c5c5c5cU,
  0xc2c2c2c2U, 0xd3d3d3d3U, 0xacacacacU, 0x62626262U,
  0x91919191U, 0x95959595U, 0xe4e4e4e4U, 0x79797979U,
  0xe7e7e7e7U, 0xc8c8c8c8U, 0x37373737U, 0x6d6d6d6dU,
  0x8d8d8d8dU, 0xd5d5d5d5U, 0x4e4e4e4eU, 0xa9a9a9a9U,
  0x6c6c6c6cU, 0x56565656U, 0xf4f4f4f4U, 0xeaeaeaeaU,
  0x65656565U, 0x7a7a7a7aU, 0xaeaeaeaeU, 0x08080808U,
  0xbabababaU, 0x78787878U, 0x25252525U, 0x2e2e2e2eU,
  0x1c1c1c1cU, 0xa6a6a6a6U, 0xb4b4b4b4U, 0xc6c6c6c6U,
  0xe8e8e8e8U, 0xddddddddU, 0x74747474U, 0x1f1f1f1fU,
  0x4b4b4b4bU, 0xbdbdbdbdU, 0x8b8b8b8bU, 0x8a8a8a8aU,
  0x70707070U, 0x3e3e3e3eU, 0xb5b5b5b5U, 0x66666666U,
  0x48484848U, 0x03030303U, 0xf6f6f6f6U, 0x0e0e0e0eU,
  0x61616161U, 0x35353535U, 0x57575757U, 0xb9b9b9b9U,
  0x86868686U, 0xc1c1c1c1U, 0x1d1d1d1dU, 0x9e9e9e9eU,
  0xe1e1e1e1U, 0xf8f8f8f8U, 0x98989898U, 0x11111111U,
  0x69696969U, 0xd9d9d9d9U, 0x8e8e8e8eU, 0x94949494U,
  0x9b9b9b9bU, 0x1e1e1e1eU, 0x87878787U, 0xe9e9e9e9U,
  0xcecececeU, 0x55555555U, 0x28282828U, 0xdfdfdfdfU,
  0x8c8c8c8cU, 0xa1a1a1a1U, 0x89898989U, 0x0d0d0d0dU,
  0xbfbfbfbfU, 0xe6e6e6e6U, 0x42424242U, 0x68686868U,
  0x41414141U, 0x99999999U, 0x2d2d2d2dU, 0x0f0f0f0fU,
  0xb0b0b0b0U, 0x54545454U, 0xbbbbbbbbU, 0x16161616U,
};

static unsigned char d0_b4_00_00_40_Value[0x40];
static unsigned char oldHBuffer[0x10];
static unsigned char d0BCKey[0x10];
static unsigned char d3BEKey[0x10];


static void nSwap (unsigned char i_key[16], unsigned char o_key[16]);
static void eSwap (unsigned char i_key[16], unsigned char o_key[16]);
static void nLookup (unsigned char i_key[16], unsigned char o_key[16]);

static void xor16 (unsigned char i_val1[16], unsigned char i_val2[16], unsigned char o_val[16]);

static void do_d0b4 (unsigned char *msgBody);
static void extractModule (unsigned char seedBuffer[0x86], unsigned char *outBuffer);
static void processD0BC (unsigned char exp_seedBuffer[0x86], unsigned char *outbuffer);
static void handle_d0_Class (unsigned char *msgFrmCard, unsigned char *msgBody, unsigned char *msgStatus);
static void handle_d1_Class (unsigned char *msgFrmCard, unsigned char *msgBody, unsigned char *msgStatus);
static void handle_d3_Class (unsigned char *msgFrmCard, unsigned char *msgBody, unsigned char *msgStatus);

static unsigned char cw1[0x8];
static unsigned char cw2[0x8];

static int ndsRouteClass (unsigned char *msgFrmCard, int msgFrmCardsize, unsigned char *cw1, unsigned char *cw2);
static void get_D0_B4_PublicModule (unsigned char *module);

static int CommandSendCardCAM (unsigned char *command, char *answer);
static int CommandSendCAMCard (unsigned char *command, char *status, unsigned char *payload);

static unsigned char nds_SC_UA[4] = { 0, 0, 0, 0 };

static unsigned int nds_SC_CAID = 0x0900;
static unsigned char nds_IRD_BoxID[4] = { 0, 0, 0, 0 };

static unsigned char nds_supportedIns[0xFF];
static unsigned char ndsCommand[0xFF];

static unsigned char CardAnswer[0xFF];
static unsigned char d3BEKey[0x10];
static char DCW1[19];

///====================================================================================================
/*
static int card_write(uchar *cmd, const uchar *data, int wflag)
{
  int l;
  uchar buf[MAX_LEN];
  memcpy(buf, cmd, CMD_LEN);
  l=wflag ? cmd[4] : 0;
  if (l && data) memcpy(buf+CMD_LEN, data, l);
  //cs_log("EMM: %s",cs_hexdump(1,buf,CMD_LEN+l));
  l=reader_cmd2icc(buf, CMD_LEN+l);
  return(l);
}

#define write_cmd(cmd, data) \
{ \
        if (card_write(cmd, data, 1)) return(0); \
}

#define read_cmd(cmd) \
{ \
        if (card_write(cmd, NULL, 0)) return(0); \
}
*/
//==============================================================

static AES_KEY aeskey;

static void nds_aes_set_key (char *key)
{
  AES_set_encrypt_key (key, 128, &aeskey);
}

static int CommandSendCardCAM(unsigned char *command, char *answer_payload)
{
  int insLenData = command[4];

  if (!reader_cmd2icc (command, CMD_LEN)) {
    answer_payload[0] = command[1];
    memcpy (&answer_payload[1], cta_res, insLenData);
    return 0; //success
  }
  else
    return -1;//error

}

static int CommandSendCAMCard (unsigned char *command, char *status, unsigned char *answer_payload)
{
  int insLenData = command[4];
  unsigned char tmpPayLoad[0xFF];

  memcpy (tmpPayLoad, command, 5);
  memcpy (tmpPayLoad + 5, answer_payload, insLenData);

  if (!reader_cmd2icc (tmpPayLoad, CMD_LEN + insLenData)) {
    memcpy (status, &cta_res[cta_lr - 2], 2);
  }
  else
    return -1;

  return 0;
}

static void nSwap (unsigned char i_val[16], unsigned char o_val[16])
{
  int i, y, a = 0;
  for (i = 0; i < 0x4; i++) {
    for (y = 0; y < 0x4; y++) {
      o_val[a] = i_val[(y * 4) + i];
      a++;
    }
  }
}

static void nLookup (unsigned char i_key[16], unsigned char o_key[16])
{
  int i;
  unsigned char flg, lastVal;

  flg = (i_key[0xF] % 2) << 7;
  for (i = 0; i < 0x10; i++) {
    lastVal = i_key[i];
    o_key[i] = Te4[(i_key[i] >> 1) | flg] & 0xFF;
    flg = (lastVal % 2) << 7;
  }
}


static void xor16 (unsigned char i_val1[16], unsigned char i_val2[16], unsigned char o_val[16])
{
  int i;
  for (i = 0; i < 0x10; i++) {
    o_val[i] = i_val1[i] ^ i_val2[i];
  }
}



static int ndsRouteClass (unsigned char *msgFrmCard, int msgFrmCardsize, unsigned char *cw1, unsigned char *cw2)
{
  unsigned char *msgBody;
  unsigned char *msgStatus;
  int i;
  msgBody = msgFrmCard + 5;
  msgStatus = msgFrmCard + msgFrmCardsize - 2;
  switch (msgFrmCard[0]) {
  case 0xD0:
    handle_d0_Class (msgFrmCard, msgBody, msgStatus);
    break;
  case 0xD1:
    handle_d1_Class (msgFrmCard, msgBody, msgStatus);
    break;
  case 0xD3:
    handle_d3_Class (msgFrmCard, msgBody, msgStatus);
    if (msgFrmCard[1] == 0x54) {
      for (i = 0; i < 8; i++) {
	cw1[i] = msgBody[i];
	cw2[i] = msgBody[0x24 + i];
      }
    }
    break;
  }
  return 0;
}


static void get_D0_B4_PublicModule (unsigned char *module)
{
  extractModule (nds_Seed, module);
}

static void handle_d0_Class (unsigned char *msgFrmCard, unsigned char *msgBody, unsigned char *msgStatus)
{
  switch (msgFrmCard[1]) {
  case 0xB4:
    do_d0b4 (msgBody);
    break;
  case 0xBC:
    processD0BC (nds_Seed, msgBody);
    break;
  }
}

static void do_d0b4 (unsigned char *msgBody)
{
  int i;
  for (i = 0; i < 0x40; i++) {
    d0_b4_00_00_40_Value[i] = msgBody[i];
  }
}



static void recalc_Module (unsigned short *buffer, unsigned short *index, unsigned short value, unsigned int sumValue)
{
  int i = 0, a = 0;
  unsigned int tmpBuff;
  if (*index != 0) {
    do {
      tmpBuff = buffer[a];
      tmpBuff = tmpBuff * value;
      tmpBuff = tmpBuff + sumValue;
      buffer[a] = tmpBuff;
      sumValue = tmpBuff >> 16;
      i++;
      a++;
    } while (i < *index);
  }
  if (sumValue != 0) {
    buffer[*index] = sumValue;
    *index = *index + 1;
  }
}

static void extractModule (unsigned char seedBuffer[0x86], unsigned char *outBuffer)
{
  int i, a;
  unsigned short index[1], tmpVal;
  unsigned short tmpSeedBuffer[0x20];
  unsigned short tmpSeedBufferOut[0x20];
  a = 0;
  for (i = 0; i < 0x20; i++) {
    tmpVal = seedBuffer[a + 6];
    tmpSeedBuffer[i] = seedBuffer[a + 1 + 6] << 8 | tmpVal;
    a = a + 2;
  }
  index[0] = 0x1;
  tmpSeedBufferOut[0] = 1;
  for (i = 0; i < 0x20; i++) {
    recalc_Module (tmpSeedBufferOut, index, tmpSeedBuffer[i], 0);
  }
  for (i = 0; i < 0x20; i++) {
    outBuffer[(i * 2)] = tmpSeedBufferOut[i] & 0xFF;
    outBuffer[(i * 2) + 1] = (tmpSeedBufferOut[i] >> 8) & 0xFF;
  }

}

static void extractExponent (unsigned char seedBuffer[0x86], unsigned char *outBuffer)
{
  int i;
  for (i = 0; i < 0x40;) {
    outBuffer[i] = seedBuffer[i + 0x46 + 1];
    outBuffer[i + 1] = seedBuffer[i + 0x46];
    i = i + 2;
  }
}

static unsigned short lmul (unsigned short value)
{
  unsigned int var1;
  var1 = ((value * 4) + value);
  var1 = (var1 << 4) + var1;
  var1 = (var1 << 8) + var1;
  var1 = (((var1 * 2) + value) >> 16) & 0xFFFF;
  return var1;

}

static void recalc_BC_Expo (unsigned short value, unsigned int index, unsigned short *expoBuffer,
			    unsigned short *seedBuffer)
{
  unsigned int i, a, val3;
  unsigned short val1, val2, tmpExp, tmpSed;
  if (index != 0) {
    tmpExp = expoBuffer[index - 1];
    tmpSed = seedBuffer[index];
    val1 = tmpSed - tmpExp;
    a = index - 2;
    for (i = 0; (signed) i < index - 1; i++) {
      val3 = seedBuffer[a] * val1;
      val3 = val3 % seedBuffer[index];
      val1 = val3 - expoBuffer[a];
      if (val1 > val3) {
	val1 = val1 + tmpSed;
      }
      a--;
    }
    val2 = val1 + value;
    if (value > val2 || val2 > seedBuffer[index]) {
      val2 = val2 - seedBuffer[index];
    }
    val3 = expoBuffer[index] * val2;
    expoBuffer[index] = val3 % seedBuffer[index];

  }
  else {
    expoBuffer[index] = value;
  }
}

static void processD0BC (unsigned char exp_seedBuffer[0x86], unsigned char *outbuffer)
{
  unsigned short seedBuffer[0x20];
  unsigned short expoBuffer[0x20];
  unsigned short dataBuffer[0x20];
  unsigned int i, a, x, value, tmpVal;
  unsigned short seedVal;
  unsigned short index[1];

  a = 0;
  for (i = 0; i < 0x20; i++) {
    expoBuffer[i] = exp_seedBuffer[a + 0x46 + 1] << 8 | exp_seedBuffer[a + 0x46];
    a = a + 2;
  }

  a = 0;
  for (i = 0; i < 0x20; i++) {
    seedBuffer[i] = exp_seedBuffer[a + 0x6 + 1] << 8 | exp_seedBuffer[a + 0x6];
    a = a + 2;
  }

  a = 0;
  for (i = 0; i < 0x20; i++) {
    dataBuffer[i] = outbuffer[a + 1] << 8 | outbuffer[a];
    a = a + 2;
  }
  for (x = 0; x < 0x20; x++) {
    seedVal = seedBuffer[x] & 0xFFFF;
    value = 0;
    for (i = 0x20; i > 0; i--) {
      tmpVal = value << 16 | dataBuffer[i - 1];
      tmpVal = tmpVal / seedVal;
      value = dataBuffer[i - 1] - (tmpVal * seedVal) & 0xFFFF;
    }

    tmpVal = lmul (seedVal) | 1;
    a = 1;
    while (tmpVal != 0) {
      if (tmpVal % 2 == 1) {
	a = a * value % seedVal & 0xFFFF;
      }
      value = value * value % seedVal & 0xFFFF;
      tmpVal = tmpVal / 2;
    }
    recalc_BC_Expo ((unsigned short) a, x, expoBuffer, seedBuffer);
  }
  a = 0x1F;
  index[0] = 0;
  for (i = 0; i < 0x20; i++) {
    recalc_Module (dataBuffer, index, seedBuffer[a], expoBuffer[a]);
    a = a - 1;
  }
  for (i = 0; i < 0x20; i++) {
    outbuffer[(i * 2)] = dataBuffer[i] & 0xFF;
    outbuffer[(i * 2) + 1] = (dataBuffer[i] >> 8) & 0xFF;
  }
  nSwap (outbuffer, d0BCKey);
  nds_aes_set_key (d0BCKey);
}



static void handle_d1_Class (unsigned char *msgFrmCard, unsigned char *msgBody, unsigned char *msgStatus)
{
  int msgLen, a, rounds, roundIndex = 0;
  unsigned char insHeader[0x10];
  unsigned char insBody[0x10];
  unsigned char buffer[0x10];
  unsigned char tmpbuff1[0x10];
  unsigned char tmpbuff2[0x10];

  msgLen = msgStatus - msgBody;
  rounds = msgLen / 0x10;

  memset (tmpbuff1, 0, 0x10);
  memset (tmpbuff2, 0, 0x10);
  memset (buffer, 0, 0x10);

  memset (insBody, 0, 0x10);
  memset (insHeader, 0, 0x10);

  memcpy (insHeader, msgFrmCard, 0x5);


  xor16 (insHeader, oldHBuffer, tmpbuff1);
  memcpy (oldHBuffer, tmpbuff1, 0x10);

  for (a = 0; a < rounds + 2; a++) {
    if (a == rounds) {
      memset (insBody, 0, 0x10);
      memcpy (insBody, msgBody + roundIndex, (msgLen) % 0x10);
    }
    else if (a == rounds + 1) {
      memset (insBody, 0, 0x10);
      memcpy (insBody + 5, msgStatus, 0x2);
    }
    else {
      memcpy (insBody, msgBody + roundIndex, 0x10);
    }
    xor16 (tmpbuff1, insBody, tmpbuff2);

    nSwap (tmpbuff2, buffer);
    AES_encrypt (buffer, buffer, &aeskey);
    nSwap (buffer, tmpbuff2);
    roundIndex = roundIndex + 0x10;
    xor16 (tmpbuff2, oldHBuffer, tmpbuff1);

  }
  memcpy (oldHBuffer, tmpbuff2, 0x10);
}





static void handle_d3_Class (unsigned char *msgFrmCard, unsigned char *msgBody, unsigned char *msgStatus)
{
  int i, msgLen, rounds, roundIndex = 0;
  unsigned char insHeader[0x10];
  unsigned char insBody[0x10];
  unsigned char insStatus[0x10];
  unsigned char tmpbuff1[0x10];
  unsigned char tmpbuff2[0x10];
  unsigned char wBuffer[0x10];
  unsigned char dispBuffer[0x100];

  //aes_context ctx;

  if (msgFrmCard[4] > 0x10) {
    msgFrmCard[4] = msgFrmCard[4] - 0x10;
  }

  if (msgFrmCard[1] == 0xBE) {
    memset (oldHBuffer, 0, 0x10);
  }
  memcpy (tmpbuff1, oldHBuffer, 0x10);	// Get from oldHbuffer


  memset (wBuffer, 0, 0x10);
  memset (insHeader, 0, 0x10);
  memcpy (insHeader, msgFrmCard, 0x5);

  memset (insStatus, 0, 0x10);
  memcpy (insStatus + 5, msgStatus, 0x2);

  memset (insBody, 0, 0x10);
  memcpy (insBody, msgBody, 0x10);

  xor16 (insHeader, oldHBuffer, oldHBuffer);

  msgLen = msgFrmCard[4];
  rounds = msgLen / 0x10;
  /*Rounds */
  if (msgFrmCard[1] != 0xBE) {
    rounds++;
  }
  for (i = 0; i < rounds; i++) {
    wBuffer[0] = wBuffer[0] + i;
    xor16 (wBuffer, oldHBuffer, wBuffer);

    nSwap (wBuffer, tmpbuff2);
    AES_encrypt (tmpbuff2, tmpbuff2, &aeskey);
    nSwap (tmpbuff2, wBuffer);
    memcpy (tmpbuff1, msgBody + roundIndex, 0x10);

    xor16 (wBuffer, tmpbuff1, dispBuffer + roundIndex);
    if (i == msgLen / 0x10) {
      memset (dispBuffer + roundIndex + (msgLen - roundIndex), 0, 0x10 - (msgLen - roundIndex));
    }
    xor16 (dispBuffer + roundIndex, oldHBuffer, oldHBuffer);
    nLookup (oldHBuffer, oldHBuffer);

    roundIndex = roundIndex + 0x10;
  }
  xor16 (oldHBuffer, insStatus, oldHBuffer);
  nSwap (oldHBuffer, tmpbuff2);
  AES_encrypt (tmpbuff2, tmpbuff2, &aeskey);
  nSwap (tmpbuff2, oldHBuffer);

  /*Get Phase from Last 16 Bytes */
  memcpy (oldHBuffer, msgStatus - 0x10, 0x10);

  nSwap (oldHBuffer, tmpbuff2);
  AES_encrypt (tmpbuff2, tmpbuff2, &aeskey);
  nSwap (tmpbuff2, oldHBuffer);

  memcpy (msgBody, dispBuffer, msgLen);

  if (msgFrmCard[1] == 0xBE) {
    nSwap (dispBuffer, d3BEKey);
    nds_aes_set_key (d3BEKey);
  }

}


static int nds_getInsParams (unsigned char *insHeader, unsigned char *dir, unsigned char *len)
{
  int i, a, retval;
  retval = 1;
  a = 4;
  for (i = 0; i < nds_supportedIns[2]; i++) {
    if (insHeader[1] == nds_supportedIns[a + 1]) {
      *len = nds_supportedIns[a + 2];
      *dir = nds_supportedIns[a + 3];
      retval = 0;
    }
    a = a + 4;
  }
  return retval;
}

static void nds_createEcmInsFromRawEcm (unsigned char *rawEcm, unsigned char *ecmIns)
{
  unsigned char ecmINSHeader[5] = { 0xD1, 0x40, 0x40, 0x80, 0xFF };
  int insLen;
  insLen = rawEcm[2] - 0xF;
  ecmINSHeader[4] = insLen;
  memset (ecmIns, 0, 0xFF);
  memcpy (ecmIns, ecmINSHeader, 5);
  memcpy (ecmIns + 6, rawEcm + 19, insLen + 0x12);
  //cs_log("ECM: %s",cs_hexdump(0,ecmIns,ecmINSHeader[4]+5));
}

static int nds_AskInsLen (unsigned char ins[5])
{
  unsigned char oldP2;
  int error = 0;
  oldP2 = ins[3];
  ins[3] = 0x80;		// getLengh 
  ins[4] = 0x01;		// getLengh 
  error = CommandSendCardCAM (ins, (char *) CardAnswer);
  ins[3] = oldP2;		// getLengh
  if (error) {
    return -1;
  }
  else {
    ins[4] = CardAnswer[1];	// update lenght
  }
  return 0;
}

static int nds_buildIncomingCommandWSB (unsigned char *isoHeader, unsigned char *commandPayload,
					unsigned char *statusBytes, unsigned char *outCommand)
{
  unsigned int len;
  memcpy(outCommand, isoHeader, 5);
  len = 5;
  memcpy(outCommand + len, commandPayload, isoHeader[4]);
  len += isoHeader[4];
  memcpy(outCommand + len, statusBytes,2);
  len += 2;
  return len;
}

static int nds_buildIncomingCommand (unsigned char *isoHeader, unsigned char *cardResponse, unsigned char *outCommand)
{
  unsigned int len;
  memcpy(outCommand, isoHeader, 5);
  len = 5;
  memcpy(outCommand + len, cardResponse + 1, isoHeader[4] + 2);
  len += isoHeader[4] + 2;
  return len;
}

static void nds_parseUAInfo (unsigned char *uaInsData)
{
  nds_SC_UA[0] = uaInsData[8];
  nds_SC_UA[1] = uaInsData[9];
  nds_SC_UA[2] = uaInsData[10];
  nds_SC_UA[3] = uaInsData[11];

  nds_SC_CAID = (uaInsData[0x1D] << 8) | (uaInsData[0x1E]);
}

static void nds_parseBoxIDInfo (unsigned char *boxIDData)
{
  if (reader[ridx].pincode[0])
    return;

  int i;
  //int index=0;
  for (i = 0; i < 0x8F; i++) {
    if ((boxIDData[i] == 0x00) && (boxIDData[i + 1] == 0xF3)) {
      //index=i+1;
      memcpy (&nds_IRD_BoxID, &boxIDData[i + 2], sizeof (nds_IRD_BoxID));
    }
  }

  //nds_IRD_BoxID[0]=boxIDData[index+1];
  //nds_IRD_BoxID[1]=boxIDData[index+2];
  //nds_IRD_BoxID[2]=boxIDData[index+3];
  //nds_IRD_BoxID[3]=boxIDData[index+4];  
}


static unsigned int nds_getSupportedIns (void)
{
  unsigned int retval = 0;
  static unsigned char ndsBoot_GetSupportedIns[] = { 0xd0, 0x74, 0x01, 0x00, 0xFF };
  nds_AskInsLen (ndsBoot_GetSupportedIns);
  CommandSendCardCAM (ndsBoot_GetSupportedIns, (char *) CardAnswer);
  memcpy (nds_supportedIns, CardAnswer + 1, ndsBoot_GetSupportedIns[4]);
  return retval;
}

static unsigned int nds_sendCommandToCard (unsigned char *insHeader, unsigned char *cmdPayload, unsigned char *cmdOut)
{
  unsigned char dir, len, cmdLen;
  nds_getInsParams (insHeader, &dir, &len);
  if ((len == 0xFF) & (dir == 2)) {
    nds_AskInsLen (insHeader);
  }
  if (len != 0xFF) {
    insHeader[4] = len;
  }
  if (insHeader[0] == 0xD3) {
    insHeader[4] = len + 0x10;
  }
  if (dir >= 2) {		//Card -> Cam
    CommandSendCardCAM (insHeader, (char *) CardAnswer);
    cmdLen = nds_buildIncomingCommand (insHeader, CardAnswer, cmdOut);
  }
  if (dir <= 1) {		//Cam -> Card
    CommandSendCAMCard (insHeader, (char *) CardAnswer, cmdPayload);
    cmdLen = nds_buildIncomingCommandWSB (insHeader, cmdPayload, CardAnswer, cmdOut);
  }

  ndsRouteClass (cmdOut, cmdLen, cw1, cw2);
  return 0;
}

static unsigned int nds_getUAandBoxId ()
{
  static unsigned char ndsBoot_GetPhoneInfo[] = { 0xd0, 0x36, 0x00, 0x00, 0x00 };
  static unsigned char ndsBoot_SendBoxid[] = { 0xd0, 0x4C, 0x00, 0x00, 0x00 };
  static unsigned char ndsBoxID_Payload[] = { 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x02, 0x04 };
  static unsigned char ndsBoot_GetUAInfo[] = { 0xd0, 0x58, 0x00, 0x00, 0x00 };
  nds_sendCommandToCard (ndsBoot_GetPhoneInfo, NULL, ndsCommand);
  nds_parseBoxIDInfo (ndsCommand);
  memcpy (ndsBoxID_Payload, nds_IRD_BoxID, 4);
  nds_sendCommandToCard (ndsBoot_SendBoxid, ndsBoxID_Payload, ndsCommand);
  cs_log ("BoxID: %02X%02X%02X%02X (%02X %02X)", ndsBoxID_Payload[0], ndsBoxID_Payload[1], ndsBoxID_Payload[2],
	  ndsBoxID_Payload[3], cta_res[cta_lr - 2], cta_res[cta_lr - 1]);
  nds_sendCommandToCard (ndsBoot_GetUAInfo, NULL, ndsCommand);
  nds_parseUAInfo (ndsCommand);
  return 0;
}

static unsigned int nds_getUAandBoxId_D1 ()
{
  static unsigned char ndsBoot_SendBoxid[] = { 0xd1, 0x4C, 0x00, 0x00, 0x00 };
  static unsigned char ndsBoxID_Payload[] = { 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x02, 0x04 };
  static unsigned char ndsBoot_GetUAInfo[] = { 0xd1, 0x58, 0x00, 0x00, 0x00 };
  memcpy (ndsBoxID_Payload, nds_IRD_BoxID, 4);
  nds_sendCommandToCard (ndsBoot_GetUAInfo, NULL, ndsCommand);
  nds_sendCommandToCard (ndsBoot_SendBoxid, ndsBoxID_Payload, ndsCommand);
  cs_log ("BoxID: %02X%02X%02X%02X (%02X %02X)", ndsBoxID_Payload[0], ndsBoxID_Payload[1], ndsBoxID_Payload[2],
	  ndsBoxID_Payload[3], cta_res[cta_lr - 2], cta_res[cta_lr - 1]);
  return 0;
}


static unsigned int nds_getCamCryptKeys ()
{
  static unsigned char ndsBoot_SendModul[] = { 0xd0, 0xb4, 0x00, 0x00, 0x00 };
  static unsigned char ndsBoot_AskD0Key[] = { 0xd0, 0xbc, 0x00, 0x00, 0x00 };
  static unsigned char ndsBoot_AskD3Key[] = { 0xd3, 0xbe, 0x00, 0x00, 0x00 };

  static unsigned char ndsModul_Payload[0x40];
  get_D0_B4_PublicModule (ndsModul_Payload);
  nds_sendCommandToCard (ndsBoot_SendModul, ndsModul_Payload, ndsCommand);
  nds_sendCommandToCard (ndsBoot_AskD0Key, NULL, ndsCommand);

  nds_sendCommandToCard (ndsBoot_AskD3Key, NULL, ndsCommand);

  return 0;
}


static int ndsBoot (void)
{
  static unsigned char ndsBoot_Get7416[] = { 0xd0, 0x74, 0x16, 0x00, 0x00 };

  nds_getSupportedIns ();
  nds_sendCommandToCard (ndsBoot_Get7416, NULL, ndsCommand);
  nds_getUAandBoxId ();
  nds_getCamCryptKeys ();
  nds_getUAandBoxId_D1 ();

  return 1;
}


///====================================================================================================
int nds_card_init (uchar * atr, int atrsize)
{
  if (atrsize < 14 || (atr[10] != 0x69 && atr[11] != 0xFF && atr[12] != 0x4A && atr[13] != 0x50))
    return (0);

  if (reader[ridx].pincode[0]) {
    nds_IRD_BoxID[0] = (gethexval (reader[ridx].pincode[0]) << 4) | gethexval (reader[ridx].pincode[1]);
    nds_IRD_BoxID[1] = (gethexval (reader[ridx].pincode[2]) << 4) | gethexval (reader[ridx].pincode[3]);
    nds_IRD_BoxID[2] = (gethexval (reader[ridx].pincode[4]) << 4) | gethexval (reader[ridx].pincode[5]);
    nds_IRD_BoxID[3] = (gethexval (reader[ridx].pincode[6]) << 4) | gethexval (reader[ridx].pincode[7]);
  }

  ndsBoot ();
  reader[ridx].caid[0] = nds_SC_CAID;
  reader[ridx].hexserial[0] = nds_SC_UA[0];
  reader[ridx].hexserial[1] = nds_SC_UA[1];
  reader[ridx].hexserial[2] = nds_SC_UA[2];
  reader[ridx].hexserial[3] = nds_SC_UA[3];

  cs_ri_log ("type: nds, card: %c%c.%d, boxID: %02X%02X%02X%02X, caid: %04X, ascii serial: %ld, hex serial: %s",
	     atr[17], atr[18], atr[19],
	     nds_IRD_BoxID[0], nds_IRD_BoxID[1], nds_IRD_BoxID[2], nds_IRD_BoxID[3], reader[ridx].caid[0],
	     (reader[ridx].hexserial[0] << 24 | reader[ridx].hexserial[1] << 16 | reader[ridx].
	      hexserial[2] << 8 | reader[ridx].hexserial[3]), cs_hexdump (0, reader[ridx].hexserial, 4));

  reader[ridx].nprov = 1;
  memset (reader[ridx].prid, 0, sizeof (reader[ridx].prid));
  memset (reader[ridx].sa, 0xFF, sizeof (reader[ridx].sa));
  memcpy (reader[ridx].sa, reader[ridx].hexserial, 3);
  reader[ridx].sa[0][3] = 0;

  cs_ri_log ("NDS-Provider:%d", reader[ridx].nprov);

  int j;
  for (j = 0; j < reader[ridx].nprov; j++) {
    cs_ri_log ("Provider:%d  Provider-Id:%06X", j + 1, b2ll (4, reader[ridx].prid[j]));
    cs_ri_log ("Provider:%d  SharedAddress:%08X", j + 1, b2ll (4, reader[ridx].sa[j]));
  }

  cs_log ("ready for requests");
  return (1);
}

int nds_do_ecm (ECM_REQUEST * er)
{
  static unsigned char ndsEcm_GetDW[] = { 0xd3, 0x54, 0x00, 0x00, 0x00 };

  unsigned char insHeader[5];
  nds_createEcmInsFromRawEcm (er->ecm, CardAnswer);
  memcpy (insHeader, CardAnswer, 5);
  memcpy (ndsCommand, CardAnswer + 5, insHeader[4]);

  nds_sendCommandToCard (insHeader, ndsCommand, CardAnswer);
  nds_sendCommandToCard (ndsEcm_GetDW, NULL, CardAnswer);

  if (er->ecm[0] == 0x80)
    memcpy (er->cw, cw1, 8);

  if (er->ecm[0] == 0x81)
    memcpy (er->cw + 8, cw1, 8);

  if (er->cw[0] == 0 && er->cw[8] == 0)
    return 0;
  return 1;
}

static int nds_AddrMode (unsigned char *data)
{
  switch (data[3] & 0xC0) {
  case 0x40:
    return 3;
  case 0x80:
    return 2;
  default:
    return 0;
  }
}

static unsigned int nds_NumAddr (unsigned char *data)
{
  return ((data[3] & 0x30) >> 4) + 1;
}

static unsigned char *nds_PayloadStart (unsigned char *data)
{
  //return &data[4 + NumAddr(data)*4 + 2];
  if (nds_AddrMode (data) == 0)
    return &data[4];
  else
    return &data[4 + nds_NumAddr (data) * 4];
}

int nds_do_emm (EMM_PACKET * ep)
{
  unsigned char insEMM[] = { 0xD1, 0x42, 0x00, 0x00, 0x00 };

  int lenEMM, rc = 0;

  unsigned char *payloaddata = nds_PayloadStart (ep->emm);
  switch (payloaddata[0]) {
  case 2:
    lenEMM = payloaddata[payloaddata[1] + 2];
    payloaddata += 3 + payloaddata[1];	// skip len specifier
    break;
  default:
    //EMM: bad payload type byte
    return 0;
  }

  if (lenEMM <= 8 || lenEMM > 188) {
    return 0;
  }

  insEMM[4] = lenEMM;
  nds_sendCommandToCard (insEMM, payloaddata, ndsCommand);
  //cs_log("EMM A: %s",cs_hexdump(1,cta_res,cta_lr));
  rc = ((cta_res[cta_lr - 2] == 0x90) && (cta_res[cta_lr - 1] == 0x00));

  return (rc);
}

static void nds_RevDateCalc (const unsigned char *Date, int *year, int *mon, int *day, int *hh, int *mm, int *ss)
{
  *year = (Date[0] / 12) + 2000;
  *mon = (Date[0] % 12) + 1;
  *day = Date[1];
  *hh = Date[2] / 8;
  *mm = (0x100 * (Date[2] - *hh * 8) + Date[3]) / 32;
  *ss = (Date[3] - *mm * 32) * 2;
}

int nds_card_info (void)
{
  int i = 0;

  unsigned char ins2a[] = { 0xd0, 0x2a, 0x00, 0x00, 0x00 };
  nds_sendCommandToCard (ins2a, NULL, ndsCommand);

  unsigned char ins76[] = { 0xd0, 0x76, 0x00, 0x00, 0x00 };
  ins76[3] = 0x7f;
  ins76[4] = 2;

  nds_sendCommandToCard (ins76, NULL, ndsCommand);
  //cs_log("A: %s...",cs_hexdump(1,cta_res,cta_lr));
  //cs_log("A: %s...",cs_hexdump(1,ndsCommand,cta_lr));
  ins76[3] = 0;
  ins76[4] = 0;
  int num = cta_res[1];

  for (i = 0; i < num; i++) {
    ins76[2] = i;
    nds_sendCommandToCard (ins76, NULL, ndsCommand);
    //cs_log("A: %s...",cs_hexdump(1,cta_res,cta_lr));
    if (cta_res[5 + 2] == 0 && cta_res[5 + 3] == 0)
      break;
    int y, m, d, H, M, S;
    nds_RevDateCalc (&cta_res[5 + 4], &y, &m, &d, &H, &M, &S);
    cs_ri_log ("chid: %02x%02x, date: %04d-%02d-%02d %02d:%02d:%02d", cta_res[5 + 2], cta_res[5 + 3], y, m, d, H, M, S);
  }

  return (1);
}
