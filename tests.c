/*
 * OSCam self tests
 * This file contains tests for different config parsers and generators
 * Build this file using `make tests`
 */
#include "globals.h"

#include "oscam-array.h"
#include "oscam-string.h"
#include "oscam-conf-chk.h"
#include "oscam-conf-mk.h"

struct test_vec
{
	const char *in;  // Input data
	const char *out; // Expected output data (if out is NULL, then assume in == out)
};

typedef void  (CHK_FN)  (char *, void *);
typedef char *(MK_T_FN) (void *);
typedef void  (CLEAR_FN)(void *);
typedef void  (CLONE_FN)(void *, void *);

struct test_type
{
	char		*desc;		// Test textual description
	void		*data;		// Pointer to basic data structure
	void		*data_c;	// Pointer to data structure that will hold cloned data (for clone_ tests)
	size_t		data_sz;	// Data structure size
	CHK_FN		*chk_fn;	// chk_XXX() func for the data type
	MK_T_FN		*mk_t_fn;	// mk_t_XXX() func for the data type
	CLEAR_FN	*clear_fn;	// clear_XXX() func for the data type
	CLONE_FN	*clone_fn;	// clone_XXX() func for the data type
	const struct test_vec *test_vec; // Array of test vectors
};

static void run_parser_test(struct test_type *t)
{
	memset(t->data, 0, t->data_sz);
	memset(t->data_c, 0, t->data_sz);
	printf("%s\n", t->desc);
	const struct test_vec *vec = t->test_vec;
	while (vec->in)
	{
		bool ok;
		printf(" Testing \"%s\"", vec->in);
		char *input_setting = cs_strdup(vec->in);
		t->chk_fn(input_setting, t->data);
		t->clone_fn(t->data, t->data_c); // Check if 'clone' works
		t->clear_fn(t->data); // Check if 'clear' works
		char *generated = t->mk_t_fn(t->data_c); // Use cloned data
		if (vec->out)
			ok = strcmp(vec->out, generated) == 0;
		else
			ok = strcmp(vec->in, generated) == 0;
		if (ok)
		{
			printf(" [OK]\n");
		} else {
			printf("\n");
			printf(" === ERROR ===\n");
			printf("  Input data:   \"%s\"\n", vec->in);
			printf("  Got result:   \"%s\"\n", generated);
			printf("  Expected out: \"%s\"\n", vec->out ? vec->out : vec->in);
			printf("\n");
		}
		free_mk_t(generated);
		free(input_setting);
		fflush(stdout);
		vec++;
	}
	t->clear_fn(t->data_c);
}

void run_all_tests(void)
{
	ECM_WHITELIST ecm_whitelist, ecm_whitelist_c;
	struct test_type ecm_whitelist_test =
	{
		.desc     = "ECM whitelist setting (READER: 'ecmwhitelist')",
		.data     = &ecm_whitelist,
		.data_c   = &ecm_whitelist_c,
		.data_sz  = sizeof(ecm_whitelist),
		.chk_fn   = (CHK_FN *)&chk_ecm_whitelist,
		.mk_t_fn  = (MK_T_FN *)&mk_t_ecm_whitelist,
		.clear_fn = (CLEAR_FN *)&ecm_whitelist_clear,
		.clone_fn = (CLONE_FN *)&ecm_whitelist_clone,
		.test_vec = (const struct test_vec[])
		{
			{ .in = "0500@043800:70,6E,6C,66,7A,61,67,75,5D,6B;0600@070800:11,22,33,44,55,66;0700:AA,BB,CC,DD,EE;01,02,03,04;0123@456789:01,02,03,04" },
			{ .in = "0500@043800:70,6E,6C,66,7A,61,67,75,5D,6B" },
			{ .in = "0500@043800:70,6E,6C,66" },
			{ .in = "0500@043800:70,6E,6C" },
			{ .in = "0500@043800:70" },
			{ .in = "0500:81,82,83;0600:91" },
			{ .in = "0500:81,82" },
			{ .in = "0500:81" },
			{ .in = "@123456:81" },
			{ .in = "@123456:81;@000789:AA,BB,CC" },
			{ .in = "81" },
			{ .in = "81,82,83" },
			{ .in = "81,82,83,84" },
			{ .in = "0500@043800:70;0600@070800:11;0123@456789:01,02" },
			{ .in = "" },
			{ .in = "0500:81,32;0600:aa,bb", .out = "0500:81,32;0600:AA,BB" },
			{ .in = "500:1,2;60@77:a,b,z,,", .out = "0500:01,02;0060@000077:0A,0B" },
			{ .in = "@ff:81;@bb:11,22",      .out = "@0000FF:81;@0000BB:11,22" },
			{ .in = "@:81",                  .out = "81" },
			{ .in = "81;zzs;;;;;ab",         .out = "81,AB" },
			{ .in = ":@",                    .out = "" },
			{ .in = ",:,@,",                 .out = "" },
			{ .in = "@:",                    .out = "" },
			{ .in = "@:,,",                  .out = "" },
			{ .in = "@:;;;",                 .out = "" },
			{ .in = ",",                     .out = "" },
			{ .in = NULL },
		},
	};
	run_parser_test(&ecm_whitelist_test);

	ECM_HDR_WHITELIST ecm_hdr_whitelist, ecm_hdr_whitelist_c;
	struct test_type ecm_hdr_whitelist_test =
	{
		.desc     = "ECM header whitelist setting (READER: 'ecmhdrwhitelist')",
		.data     = &ecm_hdr_whitelist,
		.data_c   = &ecm_hdr_whitelist_c,
		.data_sz  = sizeof(ecm_hdr_whitelist),
		.chk_fn   = (CHK_FN *)&chk_ecm_hdr_whitelist,
		.mk_t_fn  = (MK_T_FN *)&mk_t_ecm_hdr_whitelist,
		.clear_fn = (CLEAR_FN *)&ecm_hdr_whitelist_clear,
		.clone_fn = (CLONE_FN *)&ecm_hdr_whitelist_clone,
		.test_vec = (const struct test_vec[])
		{
			{ .in = "1830@123456:80308F078D,81308F078D;1702@007878:807090C7000000011010008712078400,817090C7000000011010008713078400" },
			{ .in = "1830:80308F078D,81308F078D;1702:807090C7000000011010008712078400,817090C7000000011010008713078400" },
			{ .in = "813061006A00075C00,803061006A00075C00" },
			{ .in = "813061006A00075C00" },
			{ .in = "1122334455667788991011121314151617182021222324252627282930", .out = "1122334455667788991011121314151617182021" },
			{ .in = "9999@999999:1122334455667788991011121314151617182021,2233334455667788991011121314151617182021;AAAA@BBBBBB:1122334455667788991011121314151617182021" },
			{ .in = "0500:81,82,83;0600:91" },
			{ .in = "0500:81,82" },
			{ .in = "0500:81" },
			{ .in = "@123456:81" },
			{ .in = "@123456:81;@000789:AA,BB,CC" },
			{ .in = "81" },
			{ .in = "81,82,83" },
			{ .in = "81,82,83,84" },
			{ .in = "0500@043800:70;0600@070800:11;0123@456789:01,02" },
			{ .in = "" },
			{ .in = "00,82,83" },
			{ .in = "0500:81,32;0600:aa,bb", .out = "0500:81,32;0600:AA,BB" },
			{ .in = "@ff:81;@bb:11,22",      .out = "@0000FF:81;@0000BB:11,22" },
			{ .in = "0500:,,,;0060@000077:,,;0700:,;0800", .out = "0800" },
			{ .in = "@:81",                  .out = "81" },
			{ .in = "81;zzs;;;;;ab",         .out = "81,EF,AB" },
			{ .in = "1830@123456:",          .out = "" },
			{ .in = "500:1,2;60@77:a,b,z,,", .out = "" },
			{ .in = ":@",                    .out = "" },
			{ .in = ",:,@,",                 .out = "" },
			{ .in = "@:",                    .out = "" },
			{ .in = "@:,,",                  .out = "" },
			{ .in = "@:;;;",                 .out = "" },
			{ .in = ",",                     .out = "" },
			{ .in = NULL },
		},
	};
	run_parser_test(&ecm_hdr_whitelist_test);

	TUNTAB tuntab, tuntab_c;
	struct test_type tuntab_test =
	{
		.desc     = "Beta tunnel (tuntab) (ACCOUNT: 'betatunnel')",
		.data     = &tuntab,
		.data_c   = &tuntab_c,
		.data_sz  = sizeof(tuntab),
		.chk_fn   = (CHK_FN *)&chk_tuntab,
		.mk_t_fn  = (MK_T_FN *)&mk_t_tuntab,
		.clear_fn = (CLEAR_FN *)&tuntab_clear,
		.clone_fn = (CLONE_FN *)&tuntab_clone,
		.test_vec = (const struct test_vec[])
		{
			{ .in = "1833.007A:1702,1833.007B:1702,1833.007C:1702,1833.007E:1702,1833.007F:1702,1833.0080:1702,1833.0081:1702,1833.0082:1702,1833.0083:1702,1833.0084:1702" },
			{ .in = "1833.007A:1702,1833.007B:1702,1833.007C:1702,1833.007E:1702" },
			{ .in = "1833.007A:1702" },
			{ .in = "" },
			{ .in = "1833.007A" },
			{ .in = "1833:1702",      .out = "" },
			{ .in = "1833",           .out = "" },
			{ .in = "zzzz.yyyy:tttt", .out = "" },
			{ .in = "zzzz.yyyy",      .out = "" },
			{ .in = ",",              .out = "" },
			{ .in = ".:",             .out = "" },
			{ .in = ":.,",            .out = "" },
			{ .in = NULL },
		},
	};
	run_parser_test(&tuntab_test);

	FTAB ftab, ftab_c;
	struct test_type ftab_test =
	{
		.desc     = "Filters (ftab) (ACCOUNT: 'chid', 'ident'; READER: 'chid', 'ident', 'fallback_percaid', 'localcards')",
		.data     = &ftab,
		.data_c   = &ftab_c,
		.data_sz  = sizeof(ftab),
		.chk_fn   = (CHK_FN *)&chk_ftab,
		.mk_t_fn  = (MK_T_FN *)&mk_t_ftab,
		.clear_fn = (CLEAR_FN *)&ftab_clear,
		.clone_fn = (CLONE_FN *)&ftab_clone,
		.test_vec = (const struct test_vec[])
		{
			{ .in = "0100:123456,234567;0200:345678,456789" },
			{ .in = "183D:000000,005411" },
			{ .in = "183D:000000" },
			{ .in = "0100:000012" },
			{ .in = "0100:000012;0604:0000BA,000101,00010E,000141" },
			{ .in = "1234:234567;0010:345678,876543" },
			{ .in = "" },
			{ .in = "0200:eeee,tyut,1234", .out = "0200:00EEEE,001234" },
			{ .in = "0200:eeee,tyut",      .out = "0200:00EEEE" },
			{ .in = "1:0",                 .out = "0001:000000" },
			{ .in = "1:0,1,0",             .out = "0001:000000,000001,000000" },
			{ .in = "0:0",                 .out = "" },
			{ .in = "zzzz:",               .out = "" },
			{ .in = "yyyy:rrrr,qqqq",      .out = "" },
			{ .in = ",",                   .out = "" },
			{ .in = ",;,",                 .out = "" },
			{ .in = ";;;",                 .out = "" },
			{ .in = ".:",                  .out = "" },
			{ .in = ":.,",                 .out = "" },
			{ .in = ":;.,",                .out = "" },
			{ .in = ".:;,",                .out = "" },
			{ .in = NULL },
		},
	};
	run_parser_test(&ftab_test);

	CAIDVALUETAB caidvaluetab, caidvaluetab_c;
	struct test_type caidvaluetab_test =
	{
		.desc     = "caidvaluetab (ACCOUNT: 'lb_nbest_percaid'; GLOBAL: 'lb_nbest_percaid', 'fallbacktimeout_percaid', 'lb_retrylimits', 'cacheex_mode1_delay')",
		.data     = &caidvaluetab,
		.data_c   = &caidvaluetab_c,
		.data_sz  = sizeof(caidvaluetab),
		.chk_fn   = (CHK_FN *)&chk_caidvaluetab,
		.mk_t_fn  = (MK_T_FN *)&mk_t_caidvaluetab,
		.clear_fn = (CLEAR_FN *)&caidvaluetab_clear,
		.clone_fn = (CLONE_FN *)&caidvaluetab_clone,
		.test_vec = (const struct test_vec[])
		{
			{ .in = "0100:4,0200:3,0300:2,0400:1" },
			{ .in = "0100:4,02:3,03:2,04:1,0500:9999" },
			{ .in = "0100:4" },
			{ .in = "01:4" },
			{ .in = "" },
			{ .in = "0500:10000",          .out = "" },
			{ .in = "0200:eeee,tyut,1234", .out = "0200:0" },
			{ .in = "0200:eeee,tyut",      .out = "0200:0" },
			{ .in = "1:0",                 .out = "01:0" },
			{ .in = "1:0,1,0",             .out = "01:0" },
			{ .in = "0500:10000",          .out = "" },
			{ .in = "0:0",                 .out = "" },
			{ .in = "zzzz:",               .out = "" },
			{ .in = "yyyy:rrrr,qqqq",      .out = "" },
			{ .in = ",",                   .out = "" },
			{ .in = ",:,",                 .out = "" },
			{ .in = ";:;",                 .out = "" },
			{ .in = ".:",                  .out = "" },
			{ .in = ":.,",                 .out = "" },
			{ .in = ":;.,",                .out = "" },
			{ .in = ".:;,",                .out = "" },
			{ .in = NULL },
		},
	};
	run_parser_test(&caidvaluetab_test);

}
