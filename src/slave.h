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

#ifndef __SLAVE_H__
#define __SLAVE_H__

#include "thread/thread.h"

typedef struct _relay_server {
    _Nt_array_ptr<char> server;
    int port;
    _Nt_array_ptr<char> mount;
    _Nt_array_ptr<char> username;
    _Nt_array_ptr<char> password;
    _Nt_array_ptr<char> localmount;
    _Nt_array_ptr<char> bind;
    struct source_tag *source;
    int mp3metadata;
    int on_demand;
    int running;
    int cleanup;
    time_t start;
    thread_type *thread;
    _Ptr<struct _relay_server> next;
} relay_server;


void slave_initialize(void);
void slave_shutdown(void);
void slave_update_all_mounts (void);
void slave_rebuild_mounts (void);
relay_server *relay_free (relay_server *relay);

#endif  /* __SLAVE_H__ */
