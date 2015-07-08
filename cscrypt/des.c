// Copyright (C) 1995-1996 Eric Young (eay@mincom.oz.au)
// Java port Copyright 1996 Frank O'Dwyer (fod@brd.ie)
//           Copyright 1996 Rainbow Diamond Limited
// All rights reserved.
//
// The ie.brd.crypto.algorithms.DES package is substantially derived from
// part of an SSL implementation written in 'C' by Eric Young (eay@mincom.oz.au).
// See below for the terms and conditions that apply to that code. This section
// describes the additional terms and conditions for this Java port only:
//
// NOTICE TO USER:
// THIS IS A CONTRACT BETWEEN YOU AND RAINBOW DIAMOND LIMITED ("RAINBOW DIAMOND"),
// AN IRISH LIMITED COMPANY. BY INSTALLING THIS SOFTWARE, YOU ACCEPT ALL THE
// TERMS AND CONDITIONS OF THIS AGREEMENT. ADDITIONALLY, NOTHING OTHER THAN
// ACCEPTING THE TERMS OF THIS AGREEMENT ENTITLES YOU TO COPY OR REDISTRIBUTE
// THIS SOFTWARE.
//
// This set of classes is FREE FOR COMMERCIAL AND NON-COMMERCIAL USE
// as long as the following conditions are adhered to:
//
// Copyright remains with the authors and as such any Copyright notices in
// the code are not to be removed.  If this code is used in a product,
// Eric Young and Rainbow Diamond Limited should be given attribution as the
// authors of the parts used. This can be in the form of a textual message at
// program startup or in documentation (online or textual) provided with the
// package.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 1. Redistributions of source code must retain the copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
// 3. All advertising materials mentioning features or use of this software
//    must display the following acknowledgement:
//    This product includes software developed by Eric Young (eay@mincom.oz.au)
//    Java port by Frank O'Dwyer (fod@brd.ie) for Rainbow Diamond Limited.
// 4. You agree that the software will not be shipped, transferred or exported
//    into any country or used in any manner prohibited by applicable export
//    laws, restrictions or regulations. You agree to indemnify and save
//    harmless Rainbow Diamond Limited, its employees, and suppliers against
//    any loss, injury, damage or expense whatsover either to it, or any third
//    party as a result of your own acts, defaults, or neglect in exporting
//    or transferring the software.
// 5. RAINBOW DIAMOND LIMITED IS PROVIDING YOU WITH THIS SOFTWARE FREE OF CHARGE
//    FOR DEMONSTRATION PURPOSES ON AN "AS IS" BASIS. RAINBOW DIAMOND AND ITS
//    SUPPLIERS DO NOT AND CANNOT WARRANT THE PERFORMANCE OR RESULTS YOU MAY
//    OBTAIN BY USING THE SOFTWARE OR DOCUMENTATION. SAVE FOR ANY WARRANTY WHICH
//    CANNOT BE EXCLUDED BY COMPULSORY LAW IN IRELAND, RAINBOW DIAMOND AND ITS
//    SUPPLIERS MAKE NO WARRANTIES OR CONDITIONS, EXPRESS OR IMPLIED, AS TO
//    NONINFRINGEMENT OF THIRD PARTY RIGHTS, MERCHANTIBILITY, SATISFACTORY QUALITY
//    OR FITNESS FOR ANY PARTICULAR PURPOSE. IN NO EVENT WILL RAINBOW DIAMOND
//    OR ITS SUPPLIERS BE LIABLE TO YOU FOR ANY DAMAGES WHATSOEVER (INCLUDING,
//    WITHOUT LIMITATION CONSEQUENTIAL, INCIDENTAL OR SPECIAL DAMAGES, INCLUDING
//    ANY LOST PROFITS OR LOST SAVINGS) ARISING OUT OF THE USE OR INABILITY TO
//    USE THE SOFTWARE EVEN IF A RAINBOW DIAMOND REPRESENTATIVE HAS BEEN ADVISED
//    OF THE POSSIBILITY OF SUCH DAMAGES, OR FOR ANY CLAIM BY A THIRD PARTY. WHERE
//    LEGALLY LIABILITY CANNOT BE EXCLUDED, BUT IT MAY BE LIMITED, RAINBOW
//    DIAMOND'S LIABILITY AND THAT OF ITS SUPPLIERS SHALL BE LIMITED TO THE SUM
//    OF TWENTY FIVE POUNDS (£25) IN TOTAL.
//
//    The contractual rights which you enjoy by virtue of Section 12, 13, 14, and
//    15 of the Sale of Goods Act, 1893 (as amended) are in no way prejudiced
//    by anything contained in this Agreement save (if you are not dealing as
//    a consumer or in the case of an international sale of goods) to the extent
//    permitted by law.
//
//    Section 39 of the Sale of Goods and Supply of Services Act, 1980 is hereby
//    excluded with respect to the supply of this software. The contractual rights
//    which you enjoy by virtue of the provisions of Section 39 of the Sale of Goods
//    and Supply of Services Act, 1980 are in no way prejudiced by anything contained
//    in these terms and conditions save to the extent permitted by law.
//
//    Rainbow Diamond Limited is acting on behalf its suppliers for the purpose of
//    disclaiming, excluding and/or restricting obligations, warranties and
//    liability as provided in this clause 5, but in no other respects and for
//    no other purpose.
// 6. This agreeement is governed by Irish law and you submit to the jurisdiction
//    of the Irish courts in relation to any matter or dispute arising hereunder.
//
// The licence and distribution terms for any publically available version or
// derivative of this code cannot be changed.  i.e. this code cannot simply be
// copied and put under another distribution licence
// [including the GNU Public Licence.]

/* original eay copyright notice follows:*/

/* Copyright (C) 1995-1996 Eric Young (eay@mincom.oz.au)
 * All rights reserved.
 *
 * This file is part of an SSL implementation written
 * by Eric Young (eay@mincom.oz.au).
 * The implementation was written so as to conform with Netscapes SSL
 * specification.  This library and applications are
 * FREE FOR COMMERCIAL AND NON-COMMERCIAL USE
 * as long as the following conditions are aheared to.
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.  If this code is used in a product,
 * Eric Young should be given attribution as the author of the parts used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    This product includes software developed by Eric Young (eay@mincom.oz.au)
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#include "../globals.h"
#include "../oscam-string.h"
#include "des.h"

static const uint8_t weak_keys[16][8] = {
		// weak keys
		{0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01},
		{0xFE,0xFE,0xFE,0xFE,0xFE,0xFE,0xFE,0xFE},
		{0x1F,0x1F,0x1F,0x1F,0x1F,0x1F,0x1F,0x1F},
		{0xE0,0xE0,0xE0,0xE0,0xE0,0xE0,0xE0,0xE0},
		// semi-weak keys
		{0x01,0xFE,0x01,0xFE,0x01,0xFE,0x01,0xFE},
		{0xFE,0x01,0xFE,0x01,0xFE,0x01,0xFE,0x01},
		{0x1F,0xE0,0x1F,0xE0,0x0E,0xF1,0x0E,0xF1},
		{0xE0,0x1F,0xE0,0x1F,0xF1,0x0E,0xF1,0x0E},
		{0x01,0xE0,0x01,0xE0,0x01,0xF1,0x01,0xF1},
		{0xE0,0x01,0xE0,0x01,0xF1,0x01,0xF1,0x01},
		{0x1F,0xFE,0x1F,0xFE,0x0E,0xFE,0x0E,0xFE},
		{0xFE,0x1F,0xFE,0x1F,0xFE,0x0E,0xFE,0x0E},
		{0x01,0x1F,0x01,0x1F,0x01,0x0E,0x01,0x0E},
		{0x1F,0x01,0x1F,0x01,0x0E,0x01,0x0E,0x01},
		{0xE0,0xFE,0xE0,0xFE,0xF1,0xFE,0xF1,0xFE},
		{0xFE,0xE0,0xFE,0xE0,0xFE,0xF1,0xFE,0xF1}};

static const uint8_t odd_parity[] ={
 		1,  1,  2,  2,  4,  4,  7,  7,  8,  8, 11, 11, 13, 13, 14, 14,
		16, 16, 19, 19, 21, 21, 22, 22, 25, 25, 26, 26, 28, 28, 31, 31,
		32, 32, 35, 35, 37, 37, 38, 38, 41, 41, 42, 42, 44, 44, 47, 47,
		49, 49, 50, 50, 52, 52, 55, 55, 56, 56, 59, 59, 61, 61, 62, 62,
		64, 64, 67, 67, 69, 69, 70, 70, 73, 73, 74, 74, 76, 76, 79, 79,
		81, 81, 82, 82, 84, 84, 87, 87, 88, 88, 91, 91, 93, 93, 94, 94,
		97, 97, 98, 98, 100,100,103,103,104,104,107,107,109,109,110,110,
		112,112,115,115,117,117,118,118,121,121,122,122,124,124,127,127,
		128,128,131,131,133,133,134,134,137,137,138,138,140,140,143,143,
		145,145,146,146,148,148,151,151,152,152,155,155,157,157,158,158,
		161,161,162,162,164,164,167,167,168,168,171,171,173,173,174,174,
		176,176,179,179,181,181,182,182,185,185,186,186,188,188,191,191,
		193,193,194,194,196,196,199,199,200,200,203,203,205,205,206,206,
		208,208,211,211,213,213,214,214,217,217,218,218,220,220,223,223,
		224,224,227,227,229,229,230,230,233,233,234,234,236,236,239,239,
		241,241,242,242,244,244,247,247,248,248,251,251,253,253,254,254};

static const uint8_t shifts2[16] = {0,0,1,1,1,1,1,1,0,1,1,1,1,1,1,0};

static const uint32_t des_skb[8][64] = {
		{
		0x00000000,0x00000010,0x20000000,0x20000010,
		0x00010000,0x00010010,0x20010000,0x20010010,
		0x00000800,0x00000810,0x20000800,0x20000810,
		0x00010800,0x00010810,0x20010800,0x20010810,
		0x00000020,0x00000030,0x20000020,0x20000030,
		0x00010020,0x00010030,0x20010020,0x20010030,
		0x00000820,0x00000830,0x20000820,0x20000830,
		0x00010820,0x00010830,0x20010820,0x20010830,
		0x00080000,0x00080010,0x20080000,0x20080010,
		0x00090000,0x00090010,0x20090000,0x20090010,
		0x00080800,0x00080810,0x20080800,0x20080810,
		0x00090800,0x00090810,0x20090800,0x20090810,
		0x00080020,0x00080030,0x20080020,0x20080030,
		0x00090020,0x00090030,0x20090020,0x20090030,
		0x00080820,0x00080830,0x20080820,0x20080830,
		0x00090820,0x00090830,0x20090820,0x20090830,
		},{

		0x00000000,0x02000000,0x00002000,0x02002000,
		0x00200000,0x02200000,0x00202000,0x02202000,
		0x00000004,0x02000004,0x00002004,0x02002004,
		0x00200004,0x02200004,0x00202004,0x02202004,
		0x00000400,0x02000400,0x00002400,0x02002400,
		0x00200400,0x02200400,0x00202400,0x02202400,
		0x00000404,0x02000404,0x00002404,0x02002404,
		0x00200404,0x02200404,0x00202404,0x02202404,
		0x10000000,0x12000000,0x10002000,0x12002000,
		0x10200000,0x12200000,0x10202000,0x12202000,
		0x10000004,0x12000004,0x10002004,0x12002004,
		0x10200004,0x12200004,0x10202004,0x12202004,
		0x10000400,0x12000400,0x10002400,0x12002400,
		0x10200400,0x12200400,0x10202400,0x12202400,
		0x10000404,0x12000404,0x10002404,0x12002404,
		0x10200404,0x12200404,0x10202404,0x12202404,
		},{

		0x00000000,0x00000001,0x00040000,0x00040001,
		0x01000000,0x01000001,0x01040000,0x01040001,
		0x00000002,0x00000003,0x00040002,0x00040003,
		0x01000002,0x01000003,0x01040002,0x01040003,
		0x00000200,0x00000201,0x00040200,0x00040201,
		0x01000200,0x01000201,0x01040200,0x01040201,
		0x00000202,0x00000203,0x00040202,0x00040203,
		0x01000202,0x01000203,0x01040202,0x01040203,
		0x08000000,0x08000001,0x08040000,0x08040001,
		0x09000000,0x09000001,0x09040000,0x09040001,
		0x08000002,0x08000003,0x08040002,0x08040003,
		0x09000002,0x09000003,0x09040002,0x09040003,
		0x08000200,0x08000201,0x08040200,0x08040201,
		0x09000200,0x09000201,0x09040200,0x09040201,
		0x08000202,0x08000203,0x08040202,0x08040203,
		0x09000202,0x09000203,0x09040202,0x09040203,
		},{

		0x00000000,0x00100000,0x00000100,0x00100100,
		0x00000008,0x00100008,0x00000108,0x00100108,
		0x00001000,0x00101000,0x00001100,0x00101100,
		0x00001008,0x00101008,0x00001108,0x00101108,
		0x04000000,0x04100000,0x04000100,0x04100100,
		0x04000008,0x04100008,0x04000108,0x04100108,
		0x04001000,0x04101000,0x04001100,0x04101100,
		0x04001008,0x04101008,0x04001108,0x04101108,
		0x00020000,0x00120000,0x00020100,0x00120100,
		0x00020008,0x00120008,0x00020108,0x00120108,
		0x00021000,0x00121000,0x00021100,0x00121100,
		0x00021008,0x00121008,0x00021108,0x00121108,
		0x04020000,0x04120000,0x04020100,0x04120100,
		0x04020008,0x04120008,0x04020108,0x04120108,
		0x04021000,0x04121000,0x04021100,0x04121100,
		0x04021008,0x04121008,0x04021108,0x04121108,
		},{

		0x00000000,0x10000000,0x00010000,0x10010000,
		0x00000004,0x10000004,0x00010004,0x10010004,
		0x20000000,0x30000000,0x20010000,0x30010000,
		0x20000004,0x30000004,0x20010004,0x30010004,
		0x00100000,0x10100000,0x00110000,0x10110000,
		0x00100004,0x10100004,0x00110004,0x10110004,
		0x20100000,0x30100000,0x20110000,0x30110000,
		0x20100004,0x30100004,0x20110004,0x30110004,
		0x00001000,0x10001000,0x00011000,0x10011000,
		0x00001004,0x10001004,0x00011004,0x10011004,
		0x20001000,0x30001000,0x20011000,0x30011000,
		0x20001004,0x30001004,0x20011004,0x30011004,
		0x00101000,0x10101000,0x00111000,0x10111000,
		0x00101004,0x10101004,0x00111004,0x10111004,
		0x20101000,0x30101000,0x20111000,0x30111000,
		0x20101004,0x30101004,0x20111004,0x30111004,
		},{

		0x00000000,0x08000000,0x00000008,0x08000008,
		0x00000400,0x08000400,0x00000408,0x08000408,
		0x00020000,0x08020000,0x00020008,0x08020008,
		0x00020400,0x08020400,0x00020408,0x08020408,
		0x00000001,0x08000001,0x00000009,0x08000009,
		0x00000401,0x08000401,0x00000409,0x08000409,
		0x00020001,0x08020001,0x00020009,0x08020009,
		0x00020401,0x08020401,0x00020409,0x08020409,
		0x02000000,0x0A000000,0x02000008,0x0A000008,
		0x02000400,0x0A000400,0x02000408,0x0A000408,
		0x02020000,0x0A020000,0x02020008,0x0A020008,
		0x02020400,0x0A020400,0x02020408,0x0A020408,
		0x02000001,0x0A000001,0x02000009,0x0A000009,
		0x02000401,0x0A000401,0x02000409,0x0A000409,
		0x02020001,0x0A020001,0x02020009,0x0A020009,
		0x02020401,0x0A020401,0x02020409,0x0A020409,
		},{

		0x00000000,0x00000100,0x00080000,0x00080100,
		0x01000000,0x01000100,0x01080000,0x01080100,
		0x00000010,0x00000110,0x00080010,0x00080110,
		0x01000010,0x01000110,0x01080010,0x01080110,
		0x00200000,0x00200100,0x00280000,0x00280100,
		0x01200000,0x01200100,0x01280000,0x01280100,
		0x00200010,0x00200110,0x00280010,0x00280110,
		0x01200010,0x01200110,0x01280010,0x01280110,
		0x00000200,0x00000300,0x00080200,0x00080300,
		0x01000200,0x01000300,0x01080200,0x01080300,
		0x00000210,0x00000310,0x00080210,0x00080310,
		0x01000210,0x01000310,0x01080210,0x01080310,
		0x00200200,0x00200300,0x00280200,0x00280300,
		0x01200200,0x01200300,0x01280200,0x01280300,
		0x00200210,0x00200310,0x00280210,0x00280310,
		0x01200210,0x01200310,0x01280210,0x01280310,
		},{

		0x00000000,0x04000000,0x00040000,0x04040000,
		0x00000002,0x04000002,0x00040002,0x04040002,
		0x00002000,0x04002000,0x00042000,0x04042000,
		0x00002002,0x04002002,0x00042002,0x04042002,
		0x00000020,0x04000020,0x00040020,0x04040020,
		0x00000022,0x04000022,0x00040022,0x04040022,
		0x00002020,0x04002020,0x00042020,0x04042020,
		0x00002022,0x04002022,0x00042022,0x04042022,
		0x00000800,0x04000800,0x00040800,0x04040800,
		0x00000802,0x04000802,0x00040802,0x04040802,
		0x00002800,0x04002800,0x00042800,0x04042800,
		0x00002802,0x04002802,0x00042802,0x04042802,
		0x00000820,0x04000820,0x00040820,0x04040820,
		0x00000822,0x04000822,0x00040822,0x04040822,
		0x00002820,0x04002820,0x00042820,0x04042820,
		0x00002822,0x04002822,0x00042822,0x04042822,
}};

static const uint32_t des_SPtrans[8][64] = {
	{
		0x00820200, 0x00020000, 0x80800000, 0x80820200,
		0x00800000, 0x80020200, 0x80020000, 0x80800000,
		0x80020200, 0x00820200, 0x00820000, 0x80000200,
		0x80800200, 0x00800000, 0x00000000, 0x80020000,
		0x00020000, 0x80000000, 0x00800200, 0x00020200,
		0x80820200, 0x00820000, 0x80000200, 0x00800200,
		0x80000000, 0x00000200, 0x00020200, 0x80820000,
		0x00000200, 0x80800200, 0x80820000, 0x00000000,
		0x00000000, 0x80820200, 0x00800200, 0x80020000,
		0x00820200, 0x00020000, 0x80000200, 0x00800200,
		0x80820000, 0x00000200, 0x00020200, 0x80800000,
		0x80020200, 0x80000000, 0x80800000, 0x00820000,
		0x80820200, 0x00020200, 0x00820000, 0x80800200,
		0x00800000, 0x80000200, 0x80020000, 0x00000000,
		0x00020000, 0x00800000, 0x80800200, 0x00820200,
		0x80000000, 0x80820000, 0x00000200, 0x80020200,
		},{

		0x10042004, 0x00000000, 0x00042000, 0x10040000,
		0x10000004, 0x00002004, 0x10002000, 0x00042000,
		0x00002000, 0x10040004, 0x00000004, 0x10002000,
		0x00040004, 0x10042000, 0x10040000, 0x00000004,
		0x00040000, 0x10002004, 0x10040004, 0x00002000,
		0x00042004, 0x10000000, 0x00000000, 0x00040004,
		0x10002004, 0x00042004, 0x10042000, 0x10000004,
		0x10000000, 0x00040000, 0x00002004, 0x10042004,
		0x00040004, 0x10042000, 0x10002000, 0x00042004,
		0x10042004, 0x00040004, 0x10000004, 0x00000000,
		0x10000000, 0x00002004, 0x00040000, 0x10040004,
		0x00002000, 0x10000000, 0x00042004, 0x10002004,
		0x10042000, 0x00002000, 0x00000000, 0x10000004,
		0x00000004, 0x10042004, 0x00042000, 0x10040000,
		0x10040004, 0x00040000, 0x00002004, 0x10002000,
		0x10002004, 0x00000004, 0x10040000, 0x00042000,
		},{

		0x41000000, 0x01010040, 0x00000040, 0x41000040,
		0x40010000, 0x01000000, 0x41000040, 0x00010040,
		0x01000040, 0x00010000, 0x01010000, 0x40000000,
		0x41010040, 0x40000040, 0x40000000, 0x41010000,
		0x00000000, 0x40010000, 0x01010040, 0x00000040,
		0x40000040, 0x41010040, 0x00010000, 0x41000000,
		0x41010000, 0x01000040, 0x40010040, 0x01010000,
		0x00010040, 0x00000000, 0x01000000, 0x40010040,
		0x01010040, 0x00000040, 0x40000000, 0x00010000,
		0x40000040, 0x40010000, 0x01010000, 0x41000040,
		0x00000000, 0x01010040, 0x00010040, 0x41010000,
		0x40010000, 0x01000000, 0x41010040, 0x40000000,
		0x40010040, 0x41000000, 0x01000000, 0x41010040,
		0x00010000, 0x01000040, 0x41000040, 0x00010040,
		0x01000040, 0x00000000, 0x41010000, 0x40000040,
		0x41000000, 0x40010040, 0x00000040, 0x01010000,
		},{

		0x00100402, 0x04000400, 0x00000002, 0x04100402,
		0x00000000, 0x04100000, 0x04000402, 0x00100002,
		0x04100400, 0x04000002, 0x04000000, 0x00000402,
		0x04000002, 0x00100402, 0x00100000, 0x04000000,
		0x04100002, 0x00100400, 0x00000400, 0x00000002,
		0x00100400, 0x04000402, 0x04100000, 0x00000400,
		0x00000402, 0x00000000, 0x00100002, 0x04100400,
		0x04000400, 0x04100002, 0x04100402, 0x00100000,
		0x04100002, 0x00000402, 0x00100000, 0x04000002,
		0x00100400, 0x04000400, 0x00000002, 0x04100000,
		0x04000402, 0x00000000, 0x00000400, 0x00100002,
		0x00000000, 0x04100002, 0x04100400, 0x00000400,
		0x04000000, 0x04100402, 0x00100402, 0x00100000,
		0x04100402, 0x00000002, 0x04000400, 0x00100402,
		0x00100002, 0x00100400, 0x04100000, 0x04000402,
		0x00000402, 0x04000000, 0x04000002, 0x04100400,
		},{

		0x02000000, 0x00004000, 0x00000100, 0x02004108,
		0x02004008, 0x02000100, 0x00004108, 0x02004000,
		0x00004000, 0x00000008, 0x02000008, 0x00004100,
		0x02000108, 0x02004008, 0x02004100, 0x00000000,
		0x00004100, 0x02000000, 0x00004008, 0x00000108,
		0x02000100, 0x00004108, 0x00000000, 0x02000008,
		0x00000008, 0x02000108, 0x02004108, 0x00004008,
		0x02004000, 0x00000100, 0x00000108, 0x02004100,
		0x02004100, 0x02000108, 0x00004008, 0x02004000,
		0x00004000, 0x00000008, 0x02000008, 0x02000100,
		0x02000000, 0x00004100, 0x02004108, 0x00000000,
		0x00004108, 0x02000000, 0x00000100, 0x00004008,
		0x02000108, 0x00000100, 0x00000000, 0x02004108,
		0x02004008, 0x02004100, 0x00000108, 0x00004000,
		0x00004100, 0x02004008, 0x02000100, 0x00000108,
		0x00000008, 0x00004108, 0x02004000, 0x02000008,
		},{

		0x20000010, 0x00080010, 0x00000000, 0x20080800,
		0x00080010, 0x00000800, 0x20000810, 0x00080000,
		0x00000810, 0x20080810, 0x00080800, 0x20000000,
		0x20000800, 0x20000010, 0x20080000, 0x00080810,
		0x00080000, 0x20000810, 0x20080010, 0x00000000,
		0x00000800, 0x00000010, 0x20080800, 0x20080010,
		0x20080810, 0x20080000, 0x20000000, 0x00000810,
		0x00000010, 0x00080800, 0x00080810, 0x20000800,
		0x00000810, 0x20000000, 0x20000800, 0x00080810,
		0x20080800, 0x00080010, 0x00000000, 0x20000800,
		0x20000000, 0x00000800, 0x20080010, 0x00080000,
		0x00080010, 0x20080810, 0x00080800, 0x00000010,
		0x20080810, 0x00080800, 0x00080000, 0x20000810,
		0x20000010, 0x20080000, 0x00080810, 0x00000000,
		0x00000800, 0x20000010, 0x20000810, 0x20080800,
		0x20080000, 0x00000810, 0x00000010, 0x20080010,
		},{

		0x00001000, 0x00000080, 0x00400080, 0x00400001,
		0x00401081, 0x00001001, 0x00001080, 0x00000000,
		0x00400000, 0x00400081, 0x00000081, 0x00401000,
		0x00000001, 0x00401080, 0x00401000, 0x00000081,
		0x00400081, 0x00001000, 0x00001001, 0x00401081,
		0x00000000, 0x00400080, 0x00400001, 0x00001080,
		0x00401001, 0x00001081, 0x00401080, 0x00000001,
		0x00001081, 0x00401001, 0x00000080, 0x00400000,
		0x00001081, 0x00401000, 0x00401001, 0x00000081,
		0x00001000, 0x00000080, 0x00400000, 0x00401001,
		0x00400081, 0x00001081, 0x00001080, 0x00000000,
		0x00000080, 0x00400001, 0x00000001, 0x00400080,
		0x00000000, 0x00400081, 0x00400080, 0x00001080,
		0x00000081, 0x00001000, 0x00401081, 0x00400000,
		0x00401080, 0x00000001, 0x00001001, 0x00401081,
		0x00400001, 0x00401080, 0x00401000, 0x00001001,
		},{

		0x08200020, 0x08208000, 0x00008020, 0x00000000,
		0x08008000, 0x00200020, 0x08200000, 0x08208020,
		0x00000020, 0x08000000, 0x00208000, 0x00008020,
		0x00208020, 0x08008020, 0x08000020, 0x08200000,
		0x00008000, 0x00208020, 0x00200020, 0x08008000,
		0x08208020, 0x08000020, 0x00000000, 0x00208000,
		0x08000000, 0x00200000, 0x08008020, 0x08200020,
		0x00200000, 0x00008000, 0x08208000, 0x00000020,
		0x00200000, 0x00008000, 0x08000020, 0x08208020,
		0x00008020, 0x08000000, 0x00000000, 0x00208000,
		0x08200020, 0x08008020, 0x08008000, 0x00200020,
		0x08208000, 0x00000020, 0x00200020, 0x08008000,
		0x08208020, 0x00200000, 0x08200000, 0x08000020,
		0x00208000, 0x00008020, 0x08008020, 0x08200000,
		0x00000020, 0x08208000, 0x00208020, 0x00000000,
		0x08000000, 0x08200020, 0x00008000, 0x00208020,
	}};

static const int32_t DES_KEY_SZ=8;

void des_set_odd_parity(uint8_t* key)
{
	int32_t i;
	
	for (i=0; i < DES_KEY_SZ; i++)
		key[i]=odd_parity[key[i]&0xff];
}

int8_t check_parity(const uint8_t* key)
{
	int32_t i;
	
	for (i=0; i < DES_KEY_SZ; i++) {
            if (key[i] != odd_parity[key[i]&0xff])
			return 0;
	}
	return 1;
}

int8_t des_is_weak_key(const uint8_t* key)
{
	int32_t i, j;
	
	for (i=0; i < 16; i++) {
		for(j=0;j < DES_KEY_SZ; j++) {
			if (weak_keys[i][j] != key[j]) {
				// not weak
				continue;
			}
		}
		// weak
		return 1;
	}
	return 0;
}

static uint32_t Get32bits(const uint8_t* key, int32_t kindex) {
	return(((key[kindex+3]&0xff)<<24) + ((key[kindex+2]&0xff)<<16) + ((key[kindex+1]&0xff)<<8) + (key[kindex]&0xff));
}

int8_t des_set_key(const uint8_t* key, uint32_t* schedule)
{
	uint32_t c,d,t,s;
	int32_t inIndex;
	int32_t kIndex;
	int32_t i;

	//if (!check_parity(key)) {
   	//	return 0;
	//}

   	//if (des_is_weak_key(key)) {
   	//	return 0;
   	//}

	inIndex=0;
	kIndex=0;

	c =Get32bits(key, inIndex);
	d =Get32bits(key, inIndex+4);

	t=(((d>>4)^c)&0x0f0f0f0f);
	c^=t;
	d^=(t<<4);

	t=(((c<<(16-(-2)))^c)&0xcccc0000);
	c=c^t^(t>>(16-(-2)));

	t=((d<<(16-(-2)))^d)&0xcccc0000;
	d=d^t^(t>>(16-(-2)));

	t=((d>>1)^c)&0x55555555;
	c^=t;
	d^=(t<<1);

	t=((c>>8)^d)&0x00ff00ff;
	d^=t;
	c^=(t<<8);

	t=((d>>1)^c)&0x55555555;
	c^=t;
	d^=(t<<1);

	d=	(((d&0x000000ff)<<16)| (d&0x0000ff00) |((d&0x00ff0000)>>16)|((c&0xf0000000)>>4));
	c&=0x0fffffff;

	for (i=0; i < 16; i++) {
		if (shifts2[i]) {
			c=((c>>2)|(c<<26));
			d=((d>>2)|(d<<26));
		} else {
			c=((c>>1)|(c<<27));
			d=((d>>1)|(d<<27));
		}

		c&=0x0fffffff;
		d&=0x0fffffff;

		s=	des_skb[0][ (c    )&0x3f                ]|
			des_skb[1][((c>> 6)&0x03)|((c>> 7)&0x3c)]|
			des_skb[2][((c>>13)&0x0f)|((c>>14)&0x30)]|
			des_skb[3][((c>>20)&0x01)|((c>>21)&0x06) |
					  ((c>>22)&0x38)];
		t=	des_skb[4][ (d    )&0x3f                ]|
			des_skb[5][((d>> 7)&0x03)|((d>> 8)&0x3c)]|
			des_skb[6][ (d>>15)&0x3f                ]|
			des_skb[7][((d>>21)&0x0f)|((d>>22)&0x30)];

		schedule[kIndex++]=((t<<16)|(s&0x0000ffff))&0xffffffff;

		s=((s>>16)|(t&0xffff0000));

		s=(s<<4)|(s>>28);

		schedule[kIndex++]=s&0xffffffff;
	}
	
	return 1;
}

static uint32_t _lrotr(uint32_t i) {
	return((i>>4) | ((i&0xff)<<28));
}

static void des_encrypt_int(uint32_t* data, const uint32_t* ks, int8_t do_encrypt)
{
	uint32_t l,r,t,u;
	int32_t i;

	u=data[0];
	r=data[1];

	{
		uint32_t tt;

		tt=((r>>4)^u)&0x0f0f0f0f;
		u^=tt;
		r^=(tt<<4);
		tt=(((u>>16)^r)&0x0000ffff);
		r^=tt;
		u^=(tt<<16);
		tt=(((r>>2)^u)&0x33333333);
		u^=tt;
		r^=(tt<<2);
		tt=(((u>>8)^r)&0x00ff00ff);
		r^=tt;
		u^=(tt<<8);
		tt=(((r>>1)^u)&0x55555555);
		u^=tt;
		r^=(tt<<1);
	}

	l=(r<<1)|(r>>31);
	r=(u<<1)|(u>>31);


	l&=0xffffffff;
	r&=0xffffffff;

	if (do_encrypt) {
		for (i=0; i < 32; i+=8) {
			{ u=(r^ks[i+0 ]); t=r^ks[i+0+1]; t=(_lrotr(t)); l^= des_SPtrans[1][(t )&0x3f]| des_SPtrans[3][(t>> 8)&0x3f]| des_SPtrans[5][(t>>16)&0x3f]| des_SPtrans[7][(t>>24)&0x3f]| des_SPtrans[0][(u )&0x3f]| des_SPtrans[2][(u>> 8)&0x3f]| des_SPtrans[4][(u>>16)&0x3f]| des_SPtrans[6][(u>>24)&0x3f]; };
			{ u=(l^ks[i+2 ]); t=l^ks[i+2+1]; t=(_lrotr(t)); r^= des_SPtrans[1][(t )&0x3f]| des_SPtrans[3][(t>> 8)&0x3f]| des_SPtrans[5][(t>>16)&0x3f]| des_SPtrans[7][(t>>24)&0x3f]| des_SPtrans[0][(u )&0x3f]| des_SPtrans[2][(u>> 8)&0x3f]| des_SPtrans[4][(u>>16)&0x3f]| des_SPtrans[6][(u>>24)&0x3f]; };
			{ u=(r^ks[i+4 ]); t=r^ks[i+4+1]; t=(_lrotr(t)); l^= des_SPtrans[1][(t )&0x3f]| des_SPtrans[3][(t>> 8)&0x3f]| des_SPtrans[5][(t>>16)&0x3f]| des_SPtrans[7][(t>>24)&0x3f]| des_SPtrans[0][(u )&0x3f]| des_SPtrans[2][(u>> 8)&0x3f]| des_SPtrans[4][(u>>16)&0x3f]| des_SPtrans[6][(u>>24)&0x3f]; };
			{ u=(l^ks[i+6 ]); t=l^ks[i+6+1]; t=(_lrotr(t)); r^= des_SPtrans[1][(t )&0x3f]| des_SPtrans[3][(t>> 8)&0x3f]| des_SPtrans[5][(t>>16)&0x3f]| des_SPtrans[7][(t>>24)&0x3f]| des_SPtrans[0][(u )&0x3f]| des_SPtrans[2][(u>> 8)&0x3f]| des_SPtrans[4][(u>>16)&0x3f]| des_SPtrans[6][(u>>24)&0x3f]; };
		}
	} else {
		for (i=30; i > 0; i-=8) {
			{ u=(r^ks[i-0 ]); t=r^ks[i-0+1]; t=(_lrotr(t)); l^= des_SPtrans[1][(t )&0x3f]| des_SPtrans[3][(t>> 8)&0x3f]| des_SPtrans[5][(t>>16)&0x3f]| des_SPtrans[7][(t>>24)&0x3f]| des_SPtrans[0][(u )&0x3f]| des_SPtrans[2][(u>> 8)&0x3f]| des_SPtrans[4][(u>>16)&0x3f]| des_SPtrans[6][(u>>24)&0x3f]; };
			{ u=(l^ks[i-2 ]); t=l^ks[i-2+1]; t=(_lrotr(t)); r^= des_SPtrans[1][(t )&0x3f]| des_SPtrans[3][(t>> 8)&0x3f]| des_SPtrans[5][(t>>16)&0x3f]| des_SPtrans[7][(t>>24)&0x3f]| des_SPtrans[0][(u )&0x3f]| des_SPtrans[2][(u>> 8)&0x3f]| des_SPtrans[4][(u>>16)&0x3f]| des_SPtrans[6][(u>>24)&0x3f]; };
			{ u=(r^ks[i-4 ]); t=r^ks[i-4+1]; t=(_lrotr(t)); l^= des_SPtrans[1][(t )&0x3f]| des_SPtrans[3][(t>> 8)&0x3f]| des_SPtrans[5][(t>>16)&0x3f]| des_SPtrans[7][(t>>24)&0x3f]| des_SPtrans[0][(u )&0x3f]| des_SPtrans[2][(u>> 8)&0x3f]| des_SPtrans[4][(u>>16)&0x3f]| des_SPtrans[6][(u>>24)&0x3f]; };
			{ u=(l^ks[i-6 ]); t=l^ks[i-6+1]; t=(_lrotr(t)); r^= des_SPtrans[1][(t )&0x3f]| des_SPtrans[3][(t>> 8)&0x3f]| des_SPtrans[5][(t>>16)&0x3f]| des_SPtrans[7][(t>>24)&0x3f]| des_SPtrans[0][(u )&0x3f]| des_SPtrans[2][(u>> 8)&0x3f]| des_SPtrans[4][(u>>16)&0x3f]| des_SPtrans[6][(u>>24)&0x3f]; };
		}
	}

	l=(l>>1)|(l<<31);
	r=(r>>1)|(r<<31);

	l&=0xffffffff;
	r&=0xffffffff;

	{
		uint32_t tt;

		tt=(((r>>1)^l)&0x55555555);
		l^=tt;
		r^=(tt<<1);
		tt=(((l>>8)^r)&0x00ff00ff);
		r^=tt;
		l^=(tt<<8);
		tt=(((r>>2)^l)&0x33333333);
		l^=tt;
		r^=(tt<<2);
		tt=(((l>>16)^r)&0x0000ffff);
		r^=tt;
		l^=(tt<<16);
		tt=(((r>>4)^l)&0x0f0f0f0f);
		l^=tt;
		r^=(tt<<4);
	}

	data[0]=l;
	data[1]=r;
	l=r=t=u=0;
}

void des(uint8_t* data, const uint32_t* schedule, int8_t do_encrypt)
{
	uint32_t l, ll[2];
	int32_t inIndex;
	int32_t outIndex;

	inIndex=0;
	outIndex=0;

	l = Get32bits(data, inIndex);
	ll[0]=l;

	l = Get32bits(data, inIndex+4);
	ll[1]=l;

	des_encrypt_int(ll, schedule, do_encrypt);

	l=ll[0];

	data[outIndex++] = (l&0xff);
	data[outIndex++] = ((l>>8)&0xff);
	data[outIndex++] = ((l>>16)&0xff);
	data[outIndex++] = ((l>>24)&0xff);
	l=ll[1];
	data[outIndex++] = (l&0xff);
	data[outIndex++] = ((l>>8) &0xff);
	data[outIndex++] = ((l>>16) &0xff);
	data[outIndex++] = ((l>>24) &0xff);
}

static inline void xxor(uint8_t *data, int32_t len, const uint8_t *v1, const uint8_t *v2)
{
	uint32_t i;
	switch(len)
	{
	case 16:
		for(i = 8; i < 16; ++i)
		{
			data[i] = v1[i] ^ v2[i];
		}
	case 8:
		for(i = 4; i < 8; ++i)
		{
			data[i] = v1[i] ^ v2[i];
		}
	case 4:
		for(i = 0; i < 4; ++i)
		{
			data[i] = v1[i] ^ v2[i];
		}
		break;
	default:
		while(len--) { *data++ = *v1++ ^ *v2++; }
		break;
	}
}

void des_ecb_encrypt(uint8_t* data, const uint8_t* key, int32_t len)
{
	uint32_t schedule[32];
	int32_t i; 
	
	des_set_key(key, schedule);
	
	len&=~7;
	
	for(i=0; i<len; i+=8) {
		des(&data[i], schedule, 1);
	}
}

void des_ecb_decrypt(uint8_t* data, const uint8_t* key, int32_t len)
{
	uint32_t schedule[32];
	int32_t i; 
	
	des_set_key(key, schedule);
	
	len&=~7;

	for(i=0; i<len; i+=8) {
		des(&data[i], schedule, 0);
	}
}

void des_cbc_encrypt(uint8_t* data, const uint8_t* iv, const uint8_t* key, int32_t len)
{
	const uint8_t *civ = iv; 
	uint32_t schedule[32];
	int32_t i; 

	des_set_key(key, schedule);
	
	len&=~7;

	for(i=0; i<len; i+=8) {
		xxor(&data[i],8,&data[i],civ);
		civ=&data[i];
		des(&data[i], schedule, 1);
	}
}

void des_cbc_decrypt(uint8_t* data, const uint8_t* iv, const uint8_t* key, int32_t len)
{
	uint8_t civ[2][8];
	uint32_t schedule[32];
	int32_t i, n=0;

	des_set_key(key, schedule);

	len&=~7;

	memcpy(civ[n],iv,8);
	for(i=0; i<len; i+=8,data+=8,n^=1) {
		memcpy(civ[1-n],data,8);
		des(data, schedule ,0);
		xxor(data,8,data,civ[n]);
	}
}

void des_ede2_cbc_encrypt(uint8_t* data, const uint8_t* iv, const uint8_t* key1, const uint8_t* key2, int32_t len)
{
	const uint8_t *civ = iv; 
	uint32_t schedule1[32], schedule2[32];
	int32_t i; 

	des_set_key(key1, schedule1);
	des_set_key(key2, schedule2);

	len&=~7;

	for(i=0; i<len; i+=8) {
		xxor(&data[i],8,&data[i],civ);
		civ=&data[i];
		
		des(&data[i], schedule1, 1);
		des(&data[i], schedule2, 0);
		des(&data[i], schedule1, 1);
	}
}

void des_ede2_cbc_decrypt(uint8_t* data, const uint8_t* iv, const uint8_t* key1, const uint8_t* key2, int32_t len)
{
	uint8_t civ[2][8];
	uint32_t schedule1[32], schedule2[32];
	int32_t i, n=0;

	des_set_key(key1, schedule1);
	des_set_key(key2, schedule2);
	
	len&=~7;

	memcpy(civ[n],iv,8);
	for(i=0; i<len; i+=8,data+=8,n^=1) {
		memcpy(civ[1-n],data,8);
		des(data, schedule1, 0);
		des(data, schedule2, 1);
		des(data, schedule1, 0);		
		xxor(data,8,data,civ[n]);
	}
}
