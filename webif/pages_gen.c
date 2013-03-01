/*
 * OSCam WebIf pages generator
 * Copyright (C) 2013 Unix Solutions Ltd.
 *
 * Authors: Georgi Chorbadzhiyski (gf@unixsol.org)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <ctype.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <inttypes.h>
#include <libgen.h>

#define MAX_TEMPLATES 256
static char *index_filename = "pages_index.txt";
static char *output_pages_c = "pages.c";
static char *output_pages_h = "pages.h";

struct templates {
	unsigned int num;
	struct {
		char ident[64];
		char file[128];
		char deps[256];
		uint32_t data_len;
		enum { TXT, BIN } type;
		uint8_t mime_type;
	} data[MAX_TEMPLATES];
};

static struct templates templates;
static FILE *output_file;

static void die(const char * s, ...) {
	va_list args;
	va_start(args, s);
	fprintf(stderr, "ERROR: ");
	vfprintf(stderr, s, args);
	if (s[strlen(s) - 1] != '\n')
		fprintf(stderr, "\n");
	va_end(args);
	exit(EXIT_FAILURE);
}

static FILE *xfopen(char *filename, char *mode) {
	FILE *fh = fopen(filename, mode);
	if (!fh)
		die("fopen(%s, %s): %s\n", filename, mode, strerror(errno));
	return fh;
}

static void readfile(const char *filename, uint8_t **data, size_t *data_len) {
	struct stat sb;
	if (stat(filename, &sb) != 0)
		die("stat(%s): %s\n", filename, strerror(errno));
	int fd = open(filename, O_RDONLY);
	if (fd < 0)
		die("open(%s): %s\n", filename, strerror(errno));
	*data_len = sb.st_size;
	*data = malloc(*data_len);
	if (!*data)
		die("%s(%s): can't alloc %zd bytes\n", __func__, filename, *data_len);
	if (read(fd, *data, *data_len) < 0)
		die("read(%d, %zd): %s\n", fd, *data_len, strerror(errno));
}

static bool is_text(char *filename) {
	char *ext = strchr(basename(filename), '.');
	if (ext) {
		ext++;
		if      (strcmp(ext, "html") == 0) return true;
		else if (strcmp(ext, "json") == 0) return true;
		else if (strcmp(ext, "xml")  == 0) return true;
		else if (strcmp(ext, "css")  == 0) return true;
		else if (strcmp(ext, "svg")  == 0) return true;
		else if (strcmp(ext, "js")   == 0) return true;
	}
	return false;
}

static uint8_t mime_type_from_filename(char *filename) {
	char *ext = strchr(basename(filename), '.');
	if (ext) {
		ext++;
		// See "enum template_types" bellow
		if      (strcmp(ext, "png") == 0) return 1;
		else if (strcmp(ext, "gif") == 0) return 2;
		else if (strcmp(ext, "ico") == 0) return 3;
		else if (strcmp(ext, "jpg") == 0) return 4;
	}
	return 0;
}

static void parse_index_file(char *filename) {
	FILE *f = xfopen(filename, "r");
	int max_fields = 3;
	char line[1024];
	while (fgets(line, sizeof(line) - 1, f)) {
		int field = 0, pos = 0;
		char *ident = "", *file = "", *deps = "";
		int len = strlen(line);
		if (!len || !isalnum(line[0])) // Skip comments and junk
			continue;
		// Parse text[   ]text[   ]text
		do {
			while (line[pos] == ' ' || line[pos] == '\t') // Skip white space
				pos++;
			if (line[pos] == '\n')
				break;
			int start = pos;
			while (line[pos] != ' ' && line[pos] != '\t' && line[pos] != '\n') // Data
				pos++;
			switch (++field) {
				case 1: ident = line + start; line[pos] = '\0'; break;
				case 2: file  = line + start; line[pos] = '\0'; break;
				case 3: deps  = line + start; line[pos] = '\0'; break;
			}
			if (field >= max_fields)
				break;
			pos++;
		} while (pos < len);
		if (!strlen(ident) || !strlen(file))
			continue;

#define template_set(var) \
	do { \
		len = strlen(var); \
		pos = sizeof(templates.data[0].var); \
		if (len > pos - 1) \
			die("%s=%s length exceeds maxlen (%d > %d)\n", #var, var, len, pos - 1); \
		snprintf(templates.data[templates.num].var, pos, "%s", var); \
	} while (0)
		template_set(ident);
		template_set(file);
		template_set(deps);

		templates.data[templates.num].type = is_text(file) ? TXT : BIN;
		templates.data[templates.num].mime_type = mime_type_from_filename(file);
		templates.num++;
		if (templates.num == MAX_TEMPLATES - 1) {
			die("Too many templates in %s. Maximum is %d. Increase MAX_TEMPLATES!\n",
				filename, MAX_TEMPLATES);
		}
	}
	fclose(f);
}

static void print_template(int tpl_idx) {
	static bool ifdef_open = 0;
	char *prev_deps = "";
	char *next_deps = "";
	char *ident     = templates.data[tpl_idx].ident;
	char *deps      = templates.data[tpl_idx].deps;
	if (tpl_idx > 0)
		prev_deps   = templates.data[tpl_idx - 1].deps;
	if (tpl_idx + 1 < templates.num)
		next_deps   = templates.data[tpl_idx + 1].deps;
	int deps_len    = strlen(deps);

	// Put guards
	if (deps_len && strcmp(deps, prev_deps) != 0) {
		int i, commas = 0;
		for (i = 0; i < deps_len; i++) {
			if (deps[i] == ',')
				commas++;
		}
		if (commas == 0) {
			fprintf(output_file, "#ifdef %s\n", deps);
		} else {
			char *ptr, *saveptr1 = NULL;
			char *split_deps = strdup(deps);
			for (i = 0, ptr = strtok_r(split_deps, ",", &saveptr1); ptr; ptr = strtok_r(NULL, ",", &saveptr1), i++) {
				if (i == 0)
					fprintf(output_file, "#if defined(%s)", ptr);
				else
					fprintf(output_file, " || defined(%s)", ptr);
			}
			fprintf(output_file, "\n");
			free(split_deps);
		}
		ifdef_open = 1;
	}

	fprintf(output_file, "\t{ .tpl_name=\"%s\", .tpl_data=TPL%s, .tpl_deps=\"%s\", .tpl_data_len=%u, .tpl_type=%u },\n",
		ident, ident, deps, templates.data[tpl_idx].data_len, templates.data[tpl_idx].mime_type
	);

	if (ifdef_open && strcmp(deps, next_deps) != 0) {
		fprintf(output_file, "#endif\n");
		ifdef_open = 0;
	}
}

static void dump_text(char *ident, uint8_t *buf, size_t buf_len) {
	int i;
	fprintf(output_file, "#define TPL%s \\\n\"", ident);
	for (i = 0; i < buf_len; i++) {
		switch (buf[i]) {
			case '\n':
				if (i < buf_len - 1)
					fprintf(output_file, "\\n\\\n");
				else
					fprintf(output_file, "\\n");
				break;
			case '\\': fprintf(output_file, "\\\\"); break;
			case '"' : fprintf(output_file, "\\\""); break;
			default  : fprintf(output_file, "%c", buf[i]); break;
		}
	}
	fprintf(output_file, "\"\n\n");
}

static void dump_binary(char *ident, uint8_t *buf, size_t buf_len) {
	fprintf(output_file, "#define TPL%s \\\n\"", ident);
	int i;
	for (i = 0; i < buf_len; i++) {
		fprintf(output_file, "\\x%02x", buf[i]);
	}
	fprintf(output_file, "\"\n\n");
}

int main(void) {
	int i;

	parse_index_file(index_filename);

	output_file = xfopen(output_pages_h, "w");
	fprintf(output_file, "#ifndef WEBIF_PAGES_H_\n");
	fprintf(output_file, "#define WEBIF_PAGES_H_\n");
	fprintf(output_file, "\n");
	fprintf(output_file, "enum template_types {\n");
	fprintf(output_file, "	TEMPLATE_TYPE_TEXT = 0,\n");
	fprintf(output_file, "	TEMPLATE_TYPE_PNG  = 1,\n");
	fprintf(output_file, "	TEMPLATE_TYPE_GIF  = 2,\n");
	fprintf(output_file, "	TEMPLATE_TYPE_ICO  = 3,\n");
	fprintf(output_file, "	TEMPLATE_TYPE_JPG  = 4,\n");
	fprintf(output_file, "};\n");
	fprintf(output_file, "\n");
	fprintf(output_file, "struct template {\n");
	fprintf(output_file, "	char *tpl_name;\n");
	fprintf(output_file, "	char *tpl_data;\n");
	fprintf(output_file, "	char *tpl_deps;\n");
	fprintf(output_file, "	uint32_t tpl_data_len;\n");
	fprintf(output_file, "	uint8_t tpl_type;\n");
	fprintf(output_file, "};\n");
	fprintf(output_file, "\n");
	fprintf(output_file, "int32_t templates_count(void);\n");
	fprintf(output_file, "bool template_is_image(enum template_types tpl_type);\n");
	fprintf(output_file, "const char *template_get_mimetype(enum template_types tpl_type);\n");
	fprintf(output_file, "\n");
	fprintf(output_file, "#endif\n");
	fclose(output_file);

	output_file = xfopen(output_pages_c, "w");
	fprintf(output_file, "#include \"../globals.h\"\n");
	fprintf(output_file, "\n");
	fprintf(output_file, "#ifdef WEBIF\n");
	fprintf(output_file, "\n");
	fprintf(output_file, "#include \"pages.h\"\n");
	fprintf(output_file, "\n");

	for (i = 0; i < templates.num; i++) {
		uint8_t *buf;
		size_t buf_len;
		readfile(templates.data[i].file, &buf, &buf_len);
		templates.data[i].data_len = buf_len;
		switch (templates.data[i].type) {
			case TXT: dump_text(templates.data[i].ident, buf, buf_len); break;
			case BIN: dump_binary(templates.data[i].ident, buf, buf_len); break;
		}
		free(buf);
	}

	fprintf(output_file, "const struct template templates[] = {\n");
	for (i = 0; i < templates.num; i++) {
		print_template(i);
	}
	fprintf(output_file, "};\n");
	fprintf(output_file, "\n");
	fprintf(output_file, "int32_t templates_count(void) { return sizeof(templates) / sizeof(struct template); }\n");
	fprintf(output_file, "\n");
	fprintf(output_file, "bool template_is_image(enum template_types tpl_type) {\n");
	fprintf(output_file, "	switch (tpl_type) {\n");
	fprintf(output_file, "	case TEMPLATE_TYPE_PNG:\n");
	fprintf(output_file, "	case TEMPLATE_TYPE_GIF:\n");
	fprintf(output_file, "	case TEMPLATE_TYPE_ICO:\n");
	fprintf(output_file, "	case TEMPLATE_TYPE_JPG:\n");
	fprintf(output_file, "		return true;\n");
	fprintf(output_file, "	default:\n");
	fprintf(output_file, "		return false;\n");
	fprintf(output_file, "	}\n");
	fprintf(output_file, "	return false;\n");
	fprintf(output_file, "}\n");
	fprintf(output_file, "\n");
	fprintf(output_file, "const char *template_get_mimetype(enum template_types tpl_type) {\n");
	fprintf(output_file, "	switch (tpl_type) {\n");
	fprintf(output_file, "	case TEMPLATE_TYPE_TEXT: return \"text/plain\";\n");
	fprintf(output_file, "	case TEMPLATE_TYPE_PNG : return \"image/png\";\n");
	fprintf(output_file, "	case TEMPLATE_TYPE_GIF : return \"image/gif\";\n");
	fprintf(output_file, "	case TEMPLATE_TYPE_ICO : return \"image/x-icon\";\n");
	fprintf(output_file, "	case TEMPLATE_TYPE_JPG : return \"image/jpg\";\n");
	fprintf(output_file, "	}\n");
	fprintf(output_file, "	return \"\";\n");
	fprintf(output_file, "}\n");
	fprintf(output_file, "\n");
	fprintf(output_file, "#endif\n");
	fclose(output_file);

	return 0;
}
