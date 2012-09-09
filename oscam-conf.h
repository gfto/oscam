#ifndef OSCAM_CONF_H
#define OSCAM_CONF_H

#include <stdio.h>
#include <inttypes.h>
#include <stdbool.h>

enum opt_types {
	OPT_UNKNOWN = 0,
	OPT_INT     = 1 << 1,
	OPT_UINT    = 1 << 2,
	OPT_STRING  = 1 << 3,
	OPT_SSTRING = 1 << 4,
	OPT_FUNC    = 1 << 5,
	OPT_SAVE_FUNC = 1 << 6,
	OPT_FIXUP_FUNC = 1 << 7,
};

struct config_list {
	enum opt_types	opt_type;
	char			*config_name;
	size_t			var_offset;
	unsigned int	str_size;
	union {
		int32_t			d_int;
		uint32_t		d_uint;
		char			*d_char;
	} def;
	union {
		void			(*process_fn)(const char *token, char *value, void *setting, FILE *config_file);
		bool			(*should_save_fn)(void);
		void			(*fixup_fn)(void);
	} ops;
};

#define DEF_OPT_INT(__name, __var_ofs, __default) \
	{ \
		.opt_type		= OPT_INT, \
		.config_name	= __name, \
		.var_offset		= __var_ofs, \
		.def.d_int		= __default \
	}

#define DEF_OPT_UINT(__name, __var_ofs, __default) \
	{ \
		.opt_type		= OPT_UINT, \
		.config_name	= __name, \
		.var_offset		= __var_ofs, \
		.def.d_uint		= __default \
	}

#define DEF_OPT_STR(__name, __var_ofs, __default) \
	{ \
		.opt_type		= OPT_STRING, \
		.config_name	= __name, \
		.var_offset		= __var_ofs, \
		.def.d_char		= __default \
	}

#define DEF_OPT_SSTR(__name, __var_ofs, __default, __str_size) \
	{ \
		.opt_type		= OPT_SSTRING, \
		.config_name	= __name, \
		.var_offset		= __var_ofs, \
		.str_size		= __str_size, \
		.def.d_char		= __default \
	}

#define DEF_OPT_FUNC(__name, __var_ofs, __process_fn) \
	{ \
		.opt_type		= OPT_FUNC, \
		.config_name	= __name, \
		.var_offset		= __var_ofs, \
		.ops.process_fn	= __process_fn \
	}

#define DEF_OPT_SAVE_FUNC(__fn) \
	{ \
		.opt_type			= OPT_SAVE_FUNC, \
		.ops.should_save_fn	= __fn \
	}

#define DEF_OPT_FIXUP_FUNC(__fn) \
	{ \
		.opt_type		= OPT_FIXUP_FUNC, \
		.ops.fixup_fn	= __fn \
	}

#define DEF_LAST_OPT \
	{ \
		.opt_type		= OPT_UNKNOWN \
	}

struct config_sections {
	const char					*section;
	const struct config_list	*config;
};

int32_t  strToIntVal(char *value, int32_t defaultvalue);
uint32_t strToUIntVal(char *value, uint32_t defaultvalue);

void fprintf_conf(FILE *f, const char *varname, const char *fmt, ...) __attribute__ ((format (printf, 3, 4)));
void fprintf_conf_n(FILE *f, const char *varname);

int  config_list_parse(const struct config_list *clist, const char *token, char *value, void *config_data);
void config_list_save(FILE *f, const struct config_list *clist, void *config_data, int save_all);
void config_list_apply_fixups(const struct config_list *clist);
bool config_list_should_be_saved(const struct config_list *clist);
void config_list_set_defaults(const struct config_list *clist, void *config_data);

int config_section_is_active(const struct config_sections *sec);
const struct config_sections *config_find_section(const struct config_sections *conf, char *section_name);
void config_sections_save(const struct config_sections *conf, FILE *f);
void config_sections_set_defaults(const struct config_sections *conf);
void config_set_value(const struct config_sections *conf, char *section, const char *token, char *value, void *var);

FILE *create_config_file(const char *conf_filename);
bool flush_config_file(FILE *f, const char *conf_filename);

#endif
