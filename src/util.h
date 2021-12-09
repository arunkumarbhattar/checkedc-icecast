/* Icecast
 *
 * This program is distributed under the GNU General Public License, version 2.
 * A copy of this license is included with this source.
 *
 * Copyright 2000-2004, Jack Moffitt <jack@xiph.org, 
 *                      Michael Smith <msmith@xiph.org>,
 *                      oddsock <oddsock@xiph.org>,
 *                      Karl Heyes <karl@xiph.org>
 *                      and others (see AUTHORS for details).  Copyright 2012-2014, Philipp "ph3-der-loewe" Schafft <lion@lion.leolix.org>,
 */

#ifndef __UTIL_H__
#define __UTIL_H__

#define XSLT_CONTENT 1
#define HTML_CONTENT 2

#define READ_ENTIRE_HEADER 1
#define READ_LINE 0

#define MAX_LINE_LEN 512

  void xmlSafeFree(_Nt_array_ptr<char>); 

int util_timed_wait_for_fd(sock_t fd, int timeout);
int util_read_header(sock_t sock, char *buff : itype(_Array_ptr<char>) count(4095), unsigned long len, int entire);
int util_check_valid_extension(const char *uri : itype(_Nt_array_ptr<const char>));
char *util_get_extension(const char *path : itype(_Nt_array_ptr<const char>)) : itype(_Nt_array_ptr<char>);
char *util_get_path_from_uri(char *uri : itype(_Nt_array_ptr<char>)) : itype(_Ptr<char>);
char *util_get_path_from_normalised_uri(const char *uri : itype(_Nt_array_ptr<const char>)) : itype(_Nt_array_ptr<char>);
char *util_normalise_uri(const char *uri : itype(_Nt_array_ptr<const char>)) : itype(_Nt_array_ptr<char>);
char *util_base64_encode(const char *data : itype(_Nt_array_ptr<const char>)) : itype(_Nt_array_ptr<char>);
char *util_base64_decode(const char *input : itype(_Nt_array_ptr<const char>)) : itype(_Nt_array_ptr<char>);
char *util_bin_to_hex(unsigned char *data : itype(_Array_ptr<unsigned char>) count(len), int len) : itype(_Nt_array_ptr<char>);

char *util_url_unescape(const char *src : itype(_Nt_array_ptr<const char>)) : itype(_Nt_array_ptr<char>);
char *util_url_escape(const char *src : itype(_Nt_array_ptr<const char>)) : itype(_Nt_array_ptr<char>);

/* Function to build up a HTTP header.
 * out is the pointer to storage.
 * len is the total length of out.
 * offset is the offset in out we should start writing at if offset >= 0.
 * In this case the 'used' length is len-offset.
 * If offset is -1 we append at the end of out.
 * In this case the used length is len-strlen(out).
 * cache is a bool. If set allow the client to cache the content (static data).
 * if unset we will send no-caching headers.
 * status is the HTTP status code. If -1 no HTTP status header is generated.
 * statusmsg is the status header text. If NULL a default one
 * is used for the given status code. This is ignored if status is -1.
 * contenttype is the value for the Content-Type header.
 * if NULL no such header is generated.
 * charset is the charset for the object. If NULL no header is generated
 * or default is used.
 * datablock is random data added to the request.
 * If datablock is non NULL the end-of-header is appended as well as this datablock.
 * If datablock is NULL no end-of-header nor any data is appended.
 * Returns the number of bytes written or -1 on error.
 */
struct source_tag; /* use forward decleration so we do not need to
                    * include <source.h> that would cause other conflicts. */
ssize_t util_http_build_header(char *out : itype(_Nt_array_ptr<char>), size_t len, ssize_t offset, int cache, int status, const char *statusmsg : itype(_Nt_array_ptr<const char>), const char *contenttype : itype(_Nt_array_ptr<const char>), const char *charset : itype(_Nt_array_ptr<const char>) count(5), const char *datablock : itype(_Nt_array_ptr<const char>), struct source_tag *source : itype(_Ptr<struct source_tag>));

/* String dictionary type, without support for NULL keys, or multiple
 * instances of the same key */
typedef struct _util_dict {
  char *key : itype(_Nt_array_ptr<char>);
  char *val : itype(_Nt_array_ptr<char>);
  struct _util_dict *next : itype(_Ptr<struct _util_dict>);
} util_dict;

util_dict *util_dict_new(void) : itype(_Ptr<util_dict>);
void util_dict_free(util_dict *dict : itype(_Ptr<util_dict>));
/* dict, key must not be NULL. */
int util_dict_set(util_dict *dict : itype(_Ptr<util_dict>), const char *key : itype(_Nt_array_ptr<const char>) count(99), const char *val : itype(_Nt_array_ptr<const char>));
const char *util_dict_get(util_dict *dict : itype(_Ptr<util_dict>), const char *key : itype(_Nt_array_ptr<const char>)) : itype(_Ptr<const char>);
char *util_dict_urlencode(util_dict *dict : itype(_Ptr<util_dict>), char delim) : itype(_Ptr<char>);

#ifndef HAVE_LOCALTIME_R
struct tm *localtime_r (const time_t *timep, struct tm *result);
#endif
char *util_conv_string(const char *string : itype(_Nt_array_ptr<const char>), const char *in_charset : itype(_Nt_array_ptr<const char>), const char *out_charset : itype(_Nt_array_ptr<const char>)) : itype(_Nt_array_ptr<char>);

int get_line(FILE *file : itype(_Ptr<FILE>), char *buf : itype(_Nt_array_ptr<char>) count(511), size_t siz);


_Nt_array_ptr<char> stralloc(int size) : count(size);
_Nt_array_ptr<char> strrealloc(_Nt_array_ptr<char> x, unsigned int new_len) : count(new_len);

#endif  /* __UTIL_H__ */
