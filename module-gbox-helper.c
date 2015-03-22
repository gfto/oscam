#define MODULE_LOG_PREFIX "gbox"

#include "globals.h"

#ifdef MODULE_GBOX
#include "minilzo/minilzo.h"
#include "oscam-string.h"


uint16_t gbox_get_caid(uint32_t caprovid)
{
        if ((caprovid >> 24) == 0x05)
                { return 0x0500; }
        else
                { return caprovid >> 16; }
}

uint32_t gbox_get_provid(uint32_t caprovid)
{
        uint32_t provid = 0;

        switch(caprovid >> 24)
        {
                //ViXS
        case 0x05:
                provid = caprovid & 0xFFFFFF;
                break;
                //Cryptoworx
        case 0x0D:
                provid = (caprovid >> 8) & 0xFF;
                break;
        default:
                provid = caprovid & 0xFFFF;
                break;
        }
        return provid;
}

uint32_t gbox_get_caprovid(uint16_t caid, uint32_t prid)
{
        uint32_t caprovid = 0;

        switch(caid >> 8)
        {
                // ViXS
        case 0x05:
                caprovid = (caid >> 8) << 24 | (prid & 0xFFFFFF);
                break;
                // Cryptoworx
        case 0x0D:
                caprovid = (caid >> 8) << 24 | (caid & 0xFF) << 16 |
                        ((prid << 8) & 0xFF00);
                break;
                // N@gr@
        case 0x18:
                caprovid = (caid >> 8) << 24 | (caid & 0xFF) << 16;
                break;
        default:
                caprovid = (caid >> 8) << 24 | (caid & 0xFF) << 16 |
                        (prid & 0xFFFF);
                break;
        }
        return caprovid;
}

static void gbox_convert_pw(uchar *password, uint32_t pw)
{
        int32_t i;
        for(i = 3; i >= 0; i--)
        {
                password[3 - i] = (pw >> (8 * i)) & 0xff;
        }
}

uint32_t gbox_get_ecmchecksum(uchar *ecm, uint16_t ecmlen)
{
        uint8_t checksum[4];
        int32_t counter;

        checksum[3] = ecm[0];
        checksum[2] = ecm[1];
        checksum[1] = ecm[2];
        checksum[0] = ecm[3];

        for(counter = 1; counter < (ecmlen / 4) - 4; counter++)
        {
                checksum[3] ^= ecm[counter * 4];
                checksum[2] ^= ecm[counter * 4 + 1];
                checksum[1] ^= ecm[counter * 4 + 2];
                checksum[0] ^= ecm[counter * 4 + 3];
        }

        return checksum[3] << 24 | checksum[2] << 16 | checksum[1] << 8 | checksum[0];
}

////////////////////////////////////////////////////////////////////////////////
// GBOX BUFFER ENCRYPTION/DECRYPTION (thanks to dvbcrypt@gmail.com)
////////////////////////////////////////////////////////////////////////////////
static unsigned char Lookup_Table[0x40] =
{
        0x25, 0x38, 0xD4, 0xCD, 0x17, 0x7A, 0x5E, 0x6C, 0x52, 0x42, 0xFE, 0x68, 0xAB, 0x3F, 0xF7, 0xBE,
        0x47, 0x57, 0x71, 0xB0, 0x23, 0xC1, 0x26, 0x6C, 0x41, 0xCE, 0x94, 0x37, 0x45, 0x04, 0xA2, 0xEA,
        0x07, 0x58, 0x35, 0x55, 0x08, 0x2A, 0x0F, 0xE7, 0xAC, 0x76, 0xF0, 0xC1, 0xE6, 0x09, 0x10, 0xDD,
        0xC5, 0x8D, 0x2E, 0xD9, 0x03, 0x9C, 0x3D, 0x2C, 0x4D, 0x41, 0x0C, 0x5E, 0xDE, 0xE4, 0x90, 0xAE
};

static void gbox_encrypt8(unsigned char *buffer, unsigned char *pass)
{
        int passcounter;
        int bufcounter;
        unsigned char temp;
        for(passcounter = 0; passcounter < 4; passcounter++)
                for(bufcounter = 7; bufcounter >= 0; bufcounter--)
                {
                        temp = pass[3];
                        pass[3] = (pass[3] / 2) + (pass[2] & 1) * 0x80;
                        pass[2] = (pass[2] / 2) + (pass[1] & 1) * 0x80;
                        pass[1] = (pass[1] / 2) + (pass[0] & 1) * 0x80;
                        pass[0] = (pass[0] / 2) + (temp   & 1) * 0x80;
                        buffer[(bufcounter + 1) & 7] = buffer[(bufcounter + 1) & 7 ] - Lookup_Table[(buffer[bufcounter] >> 2) & 0x3F ];
                        buffer[(bufcounter + 1) & 7] = Lookup_Table[(buffer[bufcounter] - pass[(bufcounter + 1) & 3]) & 0x3F ] ^ buffer[(bufcounter + 1) & 7 ];
                        buffer[(bufcounter + 1) & 7] = buffer[(bufcounter + 1) & 7 ] - pass[(bufcounter & 3)];
                }
}

static void gbox_decrypt8(unsigned char *buffer, unsigned char *pass)
{
        unsigned char temp;
        int bufcounter;
        int passcounter;
        for(passcounter = 3; passcounter >= 0; passcounter--)
                for(bufcounter = 0; bufcounter <= 7; bufcounter++)
                {
                        buffer[(bufcounter + 1) & 7] = pass[bufcounter & 3] + buffer[(bufcounter + 1) & 7];
                        temp = buffer[bufcounter] -  pass[(bufcounter + 1) & 3];
                        buffer[(bufcounter + 1) & 7] = Lookup_Table[temp & 0x3F] ^ buffer[(bufcounter + 1) & 7];
                        temp = buffer[bufcounter] >> 2;
                        buffer[(bufcounter + 1) & 7] =  Lookup_Table[temp & 0x3F] + buffer[(bufcounter + 1) & 7];
                        temp = pass[0] & 0x80;
                        pass[0] = ((pass[1] & 0x80) >> 7) + (pass[0] << 1);
                        pass[1] = ((pass[2] & 0x80) >> 7) + (pass[1] << 1);
                        pass[2] = ((pass[3] & 0x80) >> 7) + (pass[2] << 1);
                        pass[3] = (temp >> 7) + (pass[3] << 1);
                }
}

static void gbox_decryptB(unsigned char *buffer, int bufsize, uchar *localkey)
{
        int counter;
        gbox_encrypt8(&buffer[bufsize - 9], localkey);
        gbox_decrypt8(buffer, localkey);
        for(counter = bufsize - 2; counter >= 0; counter--)
                { buffer[counter] = buffer[counter + 1] ^ buffer[counter]; }
}

static void gbox_encryptB(unsigned char *buffer, int bufsize, uchar *key)
{
        int counter;
        for(counter = 0; counter < (bufsize - 1); counter++)
                { buffer[counter] = buffer[counter + 1] ^ buffer[counter]; }
        gbox_encrypt8(buffer, key);
        gbox_decrypt8(&buffer[bufsize - 9], key);
}

static void gbox_encryptA(unsigned char *buffer, unsigned char *pass)
{
        int counter;
        unsigned char temp;
        for(counter = 0x1F; counter >= 0; counter--)
        {
                temp = pass[3] & 1;
                pass[3] = ((pass[2] & 1) << 7) + (pass[3] >> 1);
                pass[2] = ((pass[1] & 1) << 7) + (pass[2] >> 1);
                pass[1] = ((pass[0] & 1) << 7) + (pass[1] >> 1);
                pass[0] = (temp << 7) + (pass[0] >> 1);
                temp = (pass[(counter + 1) & 3] ^ buffer[counter & 7]) >> 2;
                buffer[(counter + 1) & 7] = Lookup_Table[temp & 0x3F] * 2  +  buffer[(counter + 1) & 7 ];
                temp = buffer[counter & 7] - pass[(counter + 1) & 3];
                buffer[(counter + 1) & 7] = Lookup_Table[temp & 0x3F] ^ buffer[(counter + 1) & 7];
                buffer[(counter + 1) & 7] = pass[counter & 3] + buffer[(counter + 1) & 7];
        }
}

static void gbox_decryptA(unsigned char *buffer, unsigned char *pass)
{
        int counter;
        unsigned char temp;
        for(counter = 0; counter <= 0x1F; counter++)
        {
                buffer[(counter + 1) & 7] = buffer[(counter + 1) & 7] - pass[counter & 3];
                temp = buffer[counter & 7] - pass[(counter + 1) & 3];
                buffer[(counter + 1) & 7] = Lookup_Table[temp & 0x3F] ^ buffer[(counter + 1) & 7];
                temp = (pass[(counter + 1) & 3] ^ buffer[counter & 7]) >> 2;
                buffer[(counter + 1) & 7] = buffer[(counter + 1) & 7] - Lookup_Table[temp & 0x3F] * 2;
                temp = pass[0] & 0x80;
                pass[0] = ((pass[1] & 0x80) >> 7) + (pass[0] << 1);
                pass[1] = ((pass[2] & 0x80) >> 7) + (pass[1] << 1);
                pass[2] = ((pass[3] & 0x80) >> 7) + (pass[2] << 1);
                pass[3] = (temp >> 7) + (pass[3] << 1);
        }
}

void gbox_encrypt(uchar *buffer, int bufsize, uint32_t key)
{
        uchar pass[4];
        gbox_convert_pw(&pass[0], key);
        gbox_encryptA(buffer, &pass[0]);
        gbox_encryptB(buffer, bufsize, &pass[0]);
}

void gbox_decrypt(uchar *buffer, int bufsize, uint32_t localkey)
{
        uchar pass[4];
        gbox_convert_pw(&pass[0], localkey);
        gbox_decryptB(buffer, bufsize, &pass[0]);
        gbox_decryptA(buffer, &pass[0]);
}

void gbox_compress(uchar *buf, int32_t unpacked_len, int32_t *packed_len)
{
        unsigned char *tmp, *tmp2;
        lzo_voidp wrkmem;
        if(!cs_malloc(&tmp, 0x40000))
        {
                return;
        }
        if(!cs_malloc(&tmp2, 0x40000))
        {
                NULLFREE(tmp);
                return;
        }
        if(!cs_malloc(&wrkmem, unpacked_len * 0x1000))
        {
                NULLFREE(tmp);
                NULLFREE(tmp2);
                return;
        }
        unpacked_len -= 12;
        memcpy(tmp2, buf + 12, unpacked_len);
        lzo_init();
        lzo_uint pl = 0;
        if(lzo1x_1_compress(tmp2, unpacked_len, tmp, &pl, wrkmem) != LZO_E_OK)
                { cs_log("compression failed!"); }
        memcpy(buf + 12, tmp, pl);
        pl += 12;
        NULLFREE(tmp);
        NULLFREE(tmp2);
        NULLFREE(wrkmem);
        *packed_len = pl;
}

void gbox_decompress(uchar *buf, int32_t *unpacked_len)
{
        uchar *tmp;
        if(!cs_malloc(&tmp, 0x40000))
                { return; }
        int err;
        int len = *unpacked_len - 12;
        *unpacked_len = 0x40000;
        lzo_init();
        cs_log_dbg(D_READER, "decompressing %d bytes", len);
        if((err = lzo1x_decompress_safe(buf + 12, len, tmp, (lzo_uint *)unpacked_len, NULL)) != LZO_E_OK)
                { cs_log_dbg(D_READER, "gbox: decompression failed! errno=%d", err); }
        memcpy(buf + 12, tmp, *unpacked_len);
        *unpacked_len += 12;
        NULLFREE(tmp);
}
#endif
