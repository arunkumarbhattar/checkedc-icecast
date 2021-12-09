/* Icecast
 *
 * This program is distributed under the GNU General Public License, version 2.
 * A copy of this license is included with this source.
 *
 * Copyright 2000-2004, Jack Moffitt <jack@xiph.org, 
 *                      Michael Smith <msmith@xiph.org>,
 *                      oddsock <oddsock@xiph.org>,
 *                      Karl Heyes <karl@xiph.org>
 *                      and others (see AUTHORS for details).
 */

/* format_mp3.h
**
** mp3 format plugin
**
*/
#ifndef __FORMAT_MP3_H__
#define __FORMAT_MP3_H__

typedef struct {
    /* These are for inline metadata */
    int inline_metadata_interval;
    int offset;
    int interval;
    char *url_artist : itype(_Nt_array_ptr<char>);
    char *url_title : itype(_Nt_array_ptr<char>);
    char *url : itype(_Nt_array_ptr<char>);
    char *inline_url : itype(_Nt_array_ptr<char>);
    int update_metadata;

    refbuf_t *metadata : itype(_Ptr<refbuf_t>);
    refbuf_t *read_data : itype(_Ptr<refbuf_t>);
    int read_count;
    mutex_t url_lock;

    unsigned build_metadata_len;
    unsigned build_metadata_offset;
    char build_metadata[4081];
} mp3_state;

int format_mp3_get_plugin(struct source_tag *src : itype(_Ptr<struct source_tag>));

#endif  /* __FORMAT_MP3_H__ */
