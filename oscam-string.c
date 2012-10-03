#include "globals.h"
#include "oscam-string.h"

/* This function encapsulates malloc. It automatically adds an error message
   to the log if it failed and calls cs_exit(quiterror) if quiterror > -1.
   result will be automatically filled with the new memory position or NULL
   on failure. */
void *cs_malloc(void *result, size_t size, int32_t quiterror)
{
	void **tmp = result;
	*tmp = malloc(size);
	if (*tmp == NULL) {
		cs_log("Couldn't allocate memory (errno=%d %s)!", errno, strerror(errno));
		if (quiterror > -1)
			cs_exit(quiterror);
	} else {
		memset(*tmp, 0, size);
	}
	return *tmp;
}

/* This function encapsulates realloc. It automatically adds an error message
   to the log if it failed and calls cs_exit(quiterror) if quiterror > -1.
   result will be automatically filled with the new memory position or NULL
   on failure. If a failure occured, the existing memory in result will
   be freed. */
void *cs_realloc(void *result, size_t size, int32_t quiterror)
{
	void **tmp = result, **tmp2 = result;
	*tmp = realloc(*tmp, size);
	if (*tmp == NULL) {
		cs_log("Couldn't allocate memory (errno=%d %s)!", errno, strerror(errno));
		free(*tmp2);
		if (quiterror > -1)
			cs_exit(quiterror);
	}
	return *tmp;
}

/* Allocates a new empty string and copies str into it. You need to free() the result. */
char *strnew(char *str)
{
	if (!str)
		return NULL;
	char *newstr = cs_malloc(&newstr, strlen(str) + 1, 1);
	cs_strncpy(newstr, str, strlen(str) + 1);
	return newstr;
}

/* Ordinary strncpy does not terminate the string if the source is exactly
   as long or longer as the specified size. This can raise security issues.
   This function is a replacement which makes sure that a \0 is always added.
   num should be the real size of char array (do not subtract -1). */
void cs_strncpy(char *destination, const char *source, size_t num)
{
	if (!source) {
		destination[0] = '\0';
		return;
	}
	uint32_t l, size = strlen(source);
	if (size > num - 1)
		l = num - 1;
	else
		l = size;
	memcpy(destination, source, l);
	destination[l] = '\0';
}

/* This function is similar to strncpy but is case insensitive when comparing. */
int32_t cs_strnicmp(const char * str1, const char * str2, size_t num) {
	uint32_t i, len1 = strlen(str1), len2 = strlen(str2);
	int32_t diff;
	for(i = 0; i < len1 && i < len2 && i < num; ++i) {
		diff = toupper(str1[i]) - toupper(str2[i]);
		if (diff != 0) return diff;
	}
	return 0;
}

/* Converts the string txt to it's lower case representation. */
char *strtolower(char *txt) {
	char *p;
	for (p = txt; *p; p++) {
		if (isupper((uchar)*p))
			*p = tolower((uchar)*p);
	}
	return txt;
}

char *trim(char *txt)
{
	int32_t l;
	char *p1, *p2;
	if (*txt == ' ') {
		for (p1=p2=txt; (*p1==' ') || (*p1=='\t') || (*p1=='\n') || (*p1=='\r'); p1++)
			;
		while (*p1)
			*p2++ = *p1++;
		*p2 = '\0';
	}
	l = strlen(txt);
	if (l > 0) {
		for (p1 = txt + l - 1; l > 0 && ((*p1==' ') || (*p1=='\t') || (*p1=='\n') || (*p1=='\r')); *p1--='\0', l--)
			;
	}
	return txt;
}

bool streq(const char *s1, const char *s2)
{
	if (!s1 && s2) return 0;
	if (s1 && !s2) return 0;
	if (!s1 && !s2) return 1;
	return strcmp(s1, s2) == 0;
}

char *cs_hexdump(int32_t m, const uchar *buf, int32_t n, char *target, int32_t len)
{
	int32_t i = 0;
	target[0] = '\0';
	m = m ? 3 : 2;
	if (m * n >= len)
		n = (len / m) - 1;
	while (i < n) {
		snprintf(target + (m * i), len - (m * i), "%02X%s", *buf++, m > 2 ? " " : "");
		i++;
	}
	return target;
}

int32_t gethexval(char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	return -1;
}

int32_t cs_atob(uchar *buf, char *asc, int32_t n)
{
	int32_t i, rc;
	for (i = 0; i < n; i++) {
		rc = (gethexval(asc[i<<1]) << 4) | gethexval(asc[(i <<1 ) + 1]);
		if (rc & 0x100)
			return -1;
		buf[i] = rc;
	}
	return n;
}

uint32_t cs_atoi(char *asc, int32_t l, int32_t val_on_err)
{
	int32_t i, n = 0;
	uint32_t rc = 0;
	for (i = ((l-1) << 1), errno = 0; i >= 0 && n < 4; i -= 2) {
		int32_t b = (gethexval(asc[i]) << 4) | gethexval(asc[i+1]);
		if (b < 0) {
			errno = EINVAL;
			rc = val_on_err ? 0xFFFFFFFF : 0;
			break;
		}
		rc |= b << (n << 3);
		n++;
	}
	return rc;
}

int32_t byte_atob(char *asc)
{
	int32_t rc;
	if (strlen(trim(asc)) != 2) {
		rc = -1;
	} else {
		rc = (gethexval(asc[0]) << 4) | gethexval(asc[1]);
		if (rc & 0x100)
			rc = -1;
	}
	return rc;
}

int32_t word_atob(char *asc)
{
	int32_t rc;
	if (strlen(trim(asc)) != 4) {
		rc = -1;
	} else {
		rc = gethexval(asc[0]) << 12 | gethexval(asc[1]) << 8 |
		     gethexval(asc[2]) << 4  | gethexval(asc[3]);
		if (rc & 0x10000)
			rc = -1;
	}
	return rc;
}

/*
 * dynamic word_atob
 * converts an 1-4 digit asc hexstring
 */
int32_t dyn_word_atob(char *asc)
{
	int32_t rc = (-1);
	int32_t i, len = strlen(trim(asc));
	if (len <= 4 && len > 0) {
		for (i = 0, rc = 0; i < len; i++) {
			rc = rc << 4 | gethexval(asc[i]);
		}
		if (rc & 0x10000)
			rc = -1;
	}
	return rc;
}

int32_t key_atob_l(char *asc, uchar *bin, int32_t l)
{
	int32_t i, n1, n2, rc;
	for (i = rc = 0; i < l; i += 2) {
		if ((n1 = gethexval(asc[i  ])) < 0) rc = -1;
		if ((n2 = gethexval(asc[i+1])) < 0) rc = -1;
		bin[i >> 1] = (n1 << 4) + (n2 & 0xff);
	}
	return rc;
}

uint32_t b2i(int32_t n, const uchar *b)
{
	switch(n) {
	case 2: return  (b[0] <<  8) |  b[1];
	case 3: return  (b[0] << 16) | (b[1] <<  8) |  b[2];
	case 4: return ((b[0] << 24) | (b[1] << 16) | (b[2] <<8 ) | b[3]) & 0xffffffffL;
	default: cs_log("Error in b2i, n=%i",n);
	}
	return 0;
}

uint64_t b2ll(int32_t n, uchar *b)
{
	int32_t i;
	uint64_t k = 0;
	for (i = 0; i < n; k += b[i++])
		k <<= 8;
	return k;
}

uchar *i2b_buf(int32_t n, uint32_t i, uchar *b)
{
	switch(n) {
	case 2:
		b[0] = (i>> 8) & 0xff;
		b[1] = (i    ) & 0xff;
		break;
	case 3:
		b[0] = (i>>16) & 0xff;
		b[1] = (i>> 8) & 0xff;
		b[2] = (i    ) & 0xff;
	case 4:
		b[0] = (i>>24) & 0xff;
		b[1] = (i>>16) & 0xff;
		b[2] = (i>> 8) & 0xff;
		b[3] = (i    ) & 0xff;
		break;
	}
	return b;
}

uint32_t a2i(char *asc, int32_t bytes)
{
	int32_t i, n;
	uint32_t rc;
	for (rc = i = 0, n = strlen(trim(asc)) - 1; i < abs(bytes) << 1; n--, i++) {
		if (n >= 0) {
			int32_t rcl;
			if ((rcl = gethexval(asc[n])) < 0) {
				errno = EINVAL;
				return 0x1f1f1f;
			}
			rc |= rcl << (i << 2);
		} else {
			if (bytes < 0)
				rc |= 0xf << (i << 2);
			errno = 0;
		}
	}
	return rc;
}

int32_t boundary(int32_t exp, int32_t n)
{
	return (((n-1) >> exp) + 1) << exp;
}
