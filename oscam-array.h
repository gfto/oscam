#ifndef OSCAM_ARRAY_H
#define OSCAM_ARRAY_H

/* Functions for manipulating dynamic arrays */

/* Frees array data and reset array num_entries */
void array_clear(void **arr_data, int32_t *arr_num_entries);

/* Initializes dst array with src array data. dst array is cleared first */
bool array_clone(void **src_arr_data, int32_t *src_arr_num_entries, uint32_t entry_size, void **dst_arr_data, int32_t *dst_arr_num_entries);

/* Add element at the end of array */
bool array_add(void **arr_data, int32_t *arr_num_entries, uint32_t entry_size, void *new_entry);

/* Array functions for different types */
#define DECLARE_ARRAY_FUNCS(NAME, BASE_TYPE, DATA_TYPE, DATA_FIELD, NUM_FIELD) \
	void NAME##_clear(BASE_TYPE *in); \
	bool NAME##_clone(BASE_TYPE *src, BASE_TYPE *dst); \
	bool NAME##_add(BASE_TYPE *in, DATA_TYPE *td); \

DECLARE_ARRAY_FUNCS(ftab, FTAB, FILTER, filts, nfilts); // Declare ftab_clear(), ftab_clone(), ftab_add()
DECLARE_ARRAY_FUNCS(tuntab, TUNTAB, TUNTAB_DATA, ttdata, ttnum); // Declare tuntab_clear(), tuntab_clone(), tuntab_add()
DECLARE_ARRAY_FUNCS(ecm_whitelist, ECM_WHITELIST, ECM_WHITELIST_DATA, ewdata, ewnum); // Declare ecm_whitelist_clear(), ecm_whitelist_clone(), ecm_whitelist_add()
DECLARE_ARRAY_FUNCS(ecm_hdr_whitelist, ECM_HDR_WHITELIST, ECM_HDR_WHITELIST_DATA, ehdata, ehnum); // Declare ecm_hdr_whitelist_clear(), ecm_hdr_whitelist_clone(), ecm_hdr_whitelist_add()
DECLARE_ARRAY_FUNCS(caidvaluetab, CAIDVALUETAB, CAIDVALUETAB_DATA, cvdata, cvnum); // Declare caidvaluetab_clear(), caidvaluetab_clone(), caidvaluetab_add()
DECLARE_ARRAY_FUNCS(caidtab, CAIDTAB, CAIDTAB_DATA, ctdata, ctnum); // Declare caidtab_clear(), caidtab_clone(), caidtab_add()
DECLARE_ARRAY_FUNCS(cecspvaluetab, CECSPVALUETAB, CECSPVALUETAB_DATA, cevdata, cevnum); // Declare cecspvaluetab_clear(), cecspvaluetab_clone(), cecspvaluetab_add()
DECLARE_ARRAY_FUNCS(cwcheckvaluetab, CWCHECKTAB, CWCHECKTAB_DATA, cwcheckdata, cwchecknum); // Declare cwcheckvaluetab_clear(), cwcheckvaluetab_clone(), cwcheckvaluetab_add()

#undef DECLARE_ARRAY_FUNCS

#endif
