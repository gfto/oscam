#ifndef OSCAM_FILES_H_
#define OSCAM_FILES_H_

#include <dirent.h>

char *get_tmp_dir(void);
int32_t cs_readdir_r(DIR *dirp, struct dirent *entry, struct dirent **result);
int32_t file_exists(const char *filename);
int32_t file_copy(char *srcfile, char *destfile);
int32_t safe_overwrite_with_bak(char *destfile, char *tmpfile, char *bakfile, int32_t forceBakOverWrite);

#endif
