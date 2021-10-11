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

/** 
 * Client authentication functions
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "auth.h"
#include "source.h"
#include "client.h"
#include "cfgfile.h"
#include "httpp/httpp.h"
#include "md5.h"

#include "logging.h"
#define CATMODULE "auth_htpasswd"

#ifdef WIN32
#define snprintf _snprintf
#endif

static auth_result htpasswd_adduser (_Ptr<auth_t> auth, const char *username : itype(_Nt_array_ptr<const char>), _Nt_array_ptr<const char> password);
static auth_result htpasswd_deleteuser(_Ptr<auth_t> auth, _Nt_array_ptr<const char> username);
static auth_result htpasswd_userlist(_Ptr<auth_t> auth, xmlNodePtr srcnode);
static int _free_user (void *key);

typedef struct
{
    char *name;
    char *pass;
} htpasswd_user;

typedef struct {
    char *filename : itype(_Nt_array_ptr<char>);
    rwlock_t file_rwlock;
    avl_tree *users : itype(_Ptr<avl_tree>);
    time_t mtime;
} htpasswd_auth_state;

static void htpasswd_clear(_Ptr<auth_t> self) {
    htpasswd_auth_state *state = self->state;
    free<char>(state->filename);
    if (state->users)
        avl_tree_free (state->users, (_free_user));
    thread_rwlock_destroy(&state->file_rwlock);
    free<htpasswd_auth_state>(state);
}


/* md5 hash */
static _Nt_array_ptr<char> get_hash(const char *data : itype(_Nt_array_ptr<const char>), int len)
{
    struct MD5Context context = {};
    unsigned char digest _Checked[16];

    MD5Init(&context);

    MD5Update(&context, _Assume_bounds_cast<_Array_ptr<const unsigned char>>((const unsigned char *)data, byte_count(0)), len);

    MD5Final(digest, _Assume_bounds_cast<_Array_ptr<struct MD5Context>>(&context, byte_count(0)));

    return ((_Nt_array_ptr<char> )util_bin_to_hex(digest, 16));
}


static int compare_users (void *arg, void *a, void *b)
{
    htpasswd_user *user1 = (htpasswd_user *)a;
    htpasswd_user *user2 = (htpasswd_user *)b;

    return strcmp (user1->name, user2->name);
}


static int _free_user (void *key)
{
    htpasswd_user *user = (htpasswd_user *)key;

    free<char> (user->name); /* ->pass is part of same buffer */
    free<htpasswd_user> (user);
    return 1;
}

_Nt_array_ptr<char> strchr_safe(_Nt_array_ptr<const char> s, int c) : count(1)
_Checked {
  _Nt_array_ptr<char> r = ((_Nt_array_ptr<char> )strchr(s, c)); 
  if (r != NULL) { 
    if (r[0] != '\0') { 
      return r;
    } 
  }

  return NULL;
}

static void htpasswd_recheckfile (_Ptr<htpasswd_auth_state> htpasswd)
{
    _Ptr<FILE> passwdfile = ((void *)0);
    _Ptr<avl_tree> new_users = ((void *)0);
    int num = 0;
    struct stat file_stat;
    char line _Nt_checked[MAX_LINE_LEN];

    if (htpasswd->filename == NULL)
        return;
    if (stat (htpasswd->filename, &file_stat) < 0)
    {
        ICECAST_LOG_WARN("failed to check status of %s", htpasswd->filename);

        /* Create a dummy users tree for things to use later */
        thread_rwlock_wlock (&htpasswd->file_rwlock);
        if(!htpasswd->users)
            htpasswd->users = avl_tree_new<void>((compare_users), NULL);
        thread_rwlock_unlock (&htpasswd->file_rwlock);

        return;
    }

    if (file_stat.st_mtime == htpasswd->mtime)
    {
        /* common case, no update to file */
        return;
    }
    ICECAST_LOG_INFO("re-reading htpasswd file \"%s\"", htpasswd->filename);
    passwdfile = fopen (htpasswd->filename, "rb");
    if (passwdfile == NULL)
    {
        ICECAST_LOG_WARN("Failed to open authentication database \"%s\": %s", 
                htpasswd->filename, strerror(errno));
        return;
    }
    htpasswd->mtime = file_stat.st_mtime;

    new_users = avl_tree_new<void> ((compare_users), NULL);

    while (get_line(passwdfile, line, MAX_LINE_LEN))
    {
        int len;
        _Ptr<htpasswd_user> entry = ((void *)0);

        num++;
        if(!line[0] || line[0] == '#')
            continue;

        _Array_ptr<char> sep : count(1) = strchr_safe(line, ':');
        if (sep == NULL)
        {
            ICECAST_LOG_WARN("No separator on line %d (%s)", num, htpasswd->filename);
            continue;
        }
        entry = calloc<htpasswd_user> (1, sizeof (htpasswd_user));
        len = strlen (line) + 1;
        _Array_ptr<char> tmp : count(len) = _Dynamic_bounds_cast<_Array_ptr<char>>(line, count(len));
        entry->name = malloc<char> (len);
        *sep = 0;
        memcpy<char> (entry->name, tmp, len);
        entry->pass = entry->name + (sep-line) + 1;
        avl_insert<htpasswd_user> (new_users, entry);
    }
    fclose (passwdfile);

    thread_rwlock_wlock (&htpasswd->file_rwlock);
    if (htpasswd->users)
        avl_tree_free (htpasswd->users,((_free_user)));
    htpasswd->users = new_users;
    thread_rwlock_unlock (&htpasswd->file_rwlock);
}


static auth_result htpasswd_auth (_Ptr<auth_client> auth_user)
{
    _Ptr<auth_t> auth = auth_user->client->auth;
    htpasswd_auth_state *htpasswd = auth->state;
    _Ptr<client_t> client = auth_user->client;
    htpasswd_user entry;
    _Ptr<htpasswd_user> result = NULL;

    if (client->username == NULL || client->password == NULL)
        return AUTH_FAILED;

    if (htpasswd->filename == NULL)
    {
        ICECAST_LOG_ERROR("No filename given in options for authenticator.");
        return AUTH_FAILED;
    }
    htpasswd_recheckfile (_Assume_bounds_cast<_Ptr<htpasswd_auth_state>>(htpasswd));

    if (htpasswd->users == NULL) {
        ICECAST_LOG_ERROR("No user list.");
        return AUTH_FAILED;
    }

    thread_rwlock_rlock (&htpasswd->file_rwlock);
    entry.name = client->username;
    if (avl_get_by_key<htpasswd_user>(htpasswd->users, &entry, &result) == 0)
    {
        _Ptr<htpasswd_user> found = result;
        _Nt_array_ptr<char> hashed_pw = ((void *)0);

        thread_rwlock_unlock (&htpasswd->file_rwlock);
        hashed_pw = get_hash (client->password, strlen (client->password));
        if (strcmp (found->pass, hashed_pw) == 0)
        {
            free<char> (hashed_pw);
            return AUTH_OK;
        }
        free<char> (hashed_pw);
        ICECAST_LOG_DEBUG("incorrect password for client");
        return AUTH_FAILED;
    }
    ICECAST_LOG_DEBUG("no such username: %s", client->username);
    thread_rwlock_unlock (&htpasswd->file_rwlock);
    return AUTH_FAILED;
}


int  auth_get_htpasswd_auth (auth_t *authenticator : itype(_Ptr<auth_t>), config_options_t *options : itype(_Ptr<config_options_t>))
{
    htpasswd_auth_state *state;

    authenticator->authenticate = htpasswd_auth;
    authenticator->free = htpasswd_clear;
    authenticator->adduser = htpasswd_adduser;
    authenticator->deleteuser = htpasswd_deleteuser;
    authenticator->listuser = htpasswd_userlist;

    state = calloc<htpasswd_auth_state>(1, sizeof(htpasswd_auth_state));

    while(options) {
        if(!strcmp(options->name, "filename"))
        {
            free<char> (state->filename);
            state->filename = ((_Nt_array_ptr<char> )strdup(options->value));
        }
        options = options->next;
    }

    if (state->filename)
        ICECAST_LOG_INFO("Configured htpasswd authentication using password file \"%s\"", 
                state->filename);
    else
        ICECAST_LOG_ERROR("No filename given in options for authenticator.");

    authenticator->state = state;

    thread_rwlock_create(&state->file_rwlock);
    htpasswd_recheckfile (_Assume_bounds_cast<_Ptr<htpasswd_auth_state>>(state));

    return 0;
}


static auth_result htpasswd_adduser (_Ptr<auth_t> auth, const char *username : itype(_Nt_array_ptr<const char>), _Nt_array_ptr<const char> password)
{
    _Ptr<FILE> passwdfile = ((void *)0);
    _Nt_array_ptr<char> hashed_password = NULL;
    htpasswd_auth_state *state = auth->state;
    htpasswd_user entry;
    _Ptr<htpasswd_user> result = NULL;

    if (state->filename == NULL) {
        ICECAST_LOG_ERROR("No filename given in options for authenticator.");
        return AUTH_FAILED;
    }

    htpasswd_recheckfile (_Assume_bounds_cast<_Ptr<htpasswd_auth_state>>(state));

    if (state->filename == NULL) {
        ICECAST_LOG_ERROR("No user list.");
        return AUTH_FAILED;
    }

    thread_rwlock_wlock (&state->file_rwlock);

    entry.name = (char*)username;
    if (avl_get_by_key<htpasswd_user>(state->users, &entry, &result) == 0)
    {
        thread_rwlock_unlock (&state->file_rwlock);
        return AUTH_USEREXISTS;
    }

    passwdfile = fopen(state->filename, "ab");

    if (passwdfile == NULL)
    {
        thread_rwlock_unlock (&state->file_rwlock);
        ICECAST_LOG_WARN("Failed to open authentication database \"%s\": %s", 
                state->filename, strerror(errno));
        return AUTH_FAILED;
    }

    hashed_password = get_hash(password, strlen(password));
    if (hashed_password) {
        fprintf(passwdfile, "%s:%s\n", username, hashed_password);
        free<char>(hashed_password);
    }

    fclose(passwdfile);
    thread_rwlock_unlock (&state->file_rwlock);

    return AUTH_USERADDED;
}


static auth_result htpasswd_deleteuser(_Ptr<auth_t> auth, _Nt_array_ptr<const char> username)
{
    _Ptr<FILE> passwdfile = ((void *)0);
    _Ptr<FILE> tmp_passwdfile = ((void *)0);
    htpasswd_auth_state *state;
    char line _Nt_checked[MAX_LINE_LEN];
    _Ptr<char> sep = ((void *)0);
    char *tmpfile = NULL;
    int tmpfile_len = 0;
    struct stat file_info;

    state = auth->state;

    if (state->filename == NULL) {
        ICECAST_LOG_ERROR("No filename given in options for authenticator.");
        return AUTH_FAILED;
    }

    if (state->users == NULL) {
        ICECAST_LOG_ERROR("No user list.");
        return AUTH_FAILED;
    }

    thread_rwlock_wlock (&state->file_rwlock);
    passwdfile = fopen(state->filename, "rb");

    if(passwdfile == NULL) {
        ICECAST_LOG_WARN("Failed to open authentication database \"%s\": %s", 
                state->filename, strerror(errno));
        thread_rwlock_unlock (&state->file_rwlock);
        return AUTH_FAILED;
    }
    tmpfile_len = strlen(state->filename) + 6;
    tmpfile = calloc<char>(1, tmpfile_len);
    snprintf (tmpfile, tmpfile_len, "%s.tmp", state->filename);
    if (stat (tmpfile, &file_info) == 0)
    {
        ICECAST_LOG_WARN("temp file \"%s\" exists, rejecting operation", tmpfile);
        free<char> (tmpfile);
        fclose (passwdfile);
        thread_rwlock_unlock (&state->file_rwlock);
        return AUTH_FAILED;
    }

    tmp_passwdfile = fopen(tmpfile, "wb");

    if(tmp_passwdfile == NULL) {
        ICECAST_LOG_WARN("Failed to open temporary authentication database \"%s\": %s", 
                tmpfile, strerror(errno));
        fclose(passwdfile);
        free<char>(tmpfile);
        thread_rwlock_unlock (&state->file_rwlock);
        return AUTH_FAILED;
    }


    while(get_line(passwdfile, line, MAX_LINE_LEN)) {
        if(!line[0] || line[0] == '#')
            continue;

        sep = strchr_safe(line, ':');
        if(sep == NULL) {
            ICECAST_LOG_DEBUG("No separator in line");
            continue;
        }

        *sep = 0;
        if (strcmp(username, line)) {
            /* We did not match on the user, so copy it to the temp file */
            /* and put the : back in */
            *sep = ':';
            fprintf(tmp_passwdfile, "%s\n", line);
        }
    }

    fclose(tmp_passwdfile);
    fclose(passwdfile);

    /* Now move the contents of the tmp file to the original */
    /* Windows won't let us rename a file if the destination file
       exists...so, lets remove the original first */
    if (remove(state->filename) != 0) {
        ICECAST_LOG_ERROR("Problem moving temp authentication file to original \"%s\" - \"%s\": %s", 
                tmpfile, state->filename, strerror(errno));
    }
    else {
        if (rename(tmpfile, state->filename) != 0) {
            ICECAST_LOG_ERROR("Problem moving temp authentication file to original \"%s\" - \"%s\": %s", 
                    tmpfile, state->filename, strerror(errno));
        }
    }
    free<char>(tmpfile);
    thread_rwlock_unlock (&state->file_rwlock);
    htpasswd_recheckfile (_Assume_bounds_cast<_Ptr<htpasswd_auth_state>>(state));

    return AUTH_USERDELETED;
}


static auth_result htpasswd_userlist(_Ptr<auth_t> auth, xmlNodePtr srcnode)
{
    htpasswd_auth_state *state;
    xmlNodePtr newnode = NULL;
    _Ptr<avl_node> node = ((void *)0);

    state = auth->state;

    if (state->filename == NULL) {
        ICECAST_LOG_ERROR("No filename given in options for authenticator.");
        return AUTH_FAILED;
    }

    htpasswd_recheckfile (_Assume_bounds_cast<_Ptr<htpasswd_auth_state>>(state));

    if (state->users == NULL) {
        ICECAST_LOG_ERROR("No user list.");
        return AUTH_FAILED;
    }

    thread_rwlock_rlock (&state->file_rwlock);
    node = avl_get_first (state->users);
    while (node)
    {
        _Ptr<htpasswd_user> user = avl_get<htpasswd_user>(node);
        newnode = xmlNewChild (srcnode, NULL, XMLSTR("User"), NULL);
        xmlNewTextChild(newnode, NULL, XMLSTR("username"), (user->name));
        node = avl_get_next (node);
    }
    thread_rwlock_unlock (&state->file_rwlock);

    return AUTH_OK;
}

