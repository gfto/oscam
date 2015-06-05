#define MODULE_LOG_PREFIX "array"

#include "globals.h"
#include "oscam-string.h"

void array_clear(void **arr_data, int32_t *arr_num_entries)
{
	*arr_num_entries = 0;
	if (arr_data)
	{
		free(*arr_data);
		*arr_data = NULL;
	}
}

bool array_clone(void **src_arr_data, int32_t *src_arr_num_entries, uint32_t entry_size, void **dst_arr_data, int32_t *dst_arr_num_entries)
{
	array_clear(dst_arr_data, dst_arr_num_entries);
	if (!src_arr_data || !dst_arr_data || !*src_arr_data)
		return false;
	if (!cs_malloc(dst_arr_data, *src_arr_num_entries * entry_size))
		return false;
	memcpy(*dst_arr_data, *src_arr_data, *src_arr_num_entries * entry_size);
	*dst_arr_num_entries = *src_arr_num_entries;
	return true;
}

bool array_add(void **arr_data, int32_t *arr_num_entries, uint32_t entry_size, void *new_entry)
{
	if (!cs_realloc(arr_data, (*arr_num_entries + 1) * entry_size))
		return false;
	memcpy(*arr_data + (*arr_num_entries * entry_size), new_entry, entry_size);
	*arr_num_entries += 1;
	return true;
}

/* Array functions for different types */
#define DECLARE_ARRAY_FUNCS(NAME, BASE_TYPE, DATA_TYPE, DATA_FIELD, NUM_FIELD) \
	void NAME##_clear(BASE_TYPE *in) \
	{ \
		if (!in) return; \
		void *pin = in->DATA_FIELD; /* Prevent warnings about strict-aliasing rules */ \
		array_clear(&pin, &in->NUM_FIELD); \
		in->DATA_FIELD = pin; \
	} \
	\
	bool NAME##_clone(BASE_TYPE *src, BASE_TYPE *dst) \
	{ \
		if (!src || !dst) return false; \
		void *psrc = src->DATA_FIELD, *pdst = dst->DATA_FIELD; /* Prevent warnings about strict-aliasing rules */ \
		bool ret = array_clone(&psrc, &src->NUM_FIELD, sizeof(*src->DATA_FIELD), &pdst, &dst->NUM_FIELD); \
		dst->DATA_FIELD = pdst; \
		return ret; \
	} \
	\
	bool NAME##_add(BASE_TYPE *in, DATA_TYPE *td) \
	{ \
		if (!in) return false; \
		void *pin = in->DATA_FIELD; /* Prevent warnings about strict-aliasing rules */ \
		bool ret = array_add(&pin, &in->NUM_FIELD, sizeof(*in->DATA_FIELD), td); \
		in->DATA_FIELD = pin; \
		return ret; \
	}

DECLARE_ARRAY_FUNCS(ftab, FTAB, FILTER, filts, nfilts); // Declare ftab_clear(), ftab_clone(), ftab_add()
DECLARE_ARRAY_FUNCS(tuntab, TUNTAB, TUNTAB_DATA, ttdata, ttnum); // Declare tuntab_clear(), tuntab_clone(), tuntab_add()
DECLARE_ARRAY_FUNCS(ecm_whitelist, ECM_WHITELIST, ECM_WHITELIST_DATA, ewdata, ewnum); // Declare ecm_whitelist_clear(), ecm_whitelist_clone(), ecm_whitelist_add()
DECLARE_ARRAY_FUNCS(ecm_hdr_whitelist, ECM_HDR_WHITELIST, ECM_HDR_WHITELIST_DATA, ehdata, ehnum); // Declare ecm_hdr_whitelist_clear(), ecm_hdr_whitelist_clone(), ecm_hdr_whitelist_add()
DECLARE_ARRAY_FUNCS(caidvaluetab, CAIDVALUETAB, CAIDVALUETAB_DATA, cvdata, cvnum); // Declare caidvaluetab_clear(), caidvaluetab_clone(), caidvaluetab_add()
DECLARE_ARRAY_FUNCS(caidtab, CAIDTAB, CAIDTAB_DATA, ctdata, ctnum); // Declare caidtab_clear(), caidtab_clone(), caidtab_add()
DECLARE_ARRAY_FUNCS(cecspvaluetab, CECSPVALUETAB, CECSPVALUETAB_DATA, cevdata, cevnum); // Declare cecspvaluetab_clear(), cecspvaluetab_clone(), cecspvaluetab_add()
DECLARE_ARRAY_FUNCS(cwcheckvaluetab, CWCHECKTAB, CWCHECKTAB_DATA, cwcheckdata, cwchecknum); // Declare cwcheckvaluetab_clear(), cwcheckvaluetab_clone(), cwcheckvaluetab_add()

#undef DECLARE_ARRAY_FUNCS
