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
 * Copyright 2012-2014, Philipp "ph3-der-loewe" Schafft <lion@lion.leolix.org>,
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

#include "thread/thread.h"
#include "avl/avl.h"
#include "httpp/httpp.h"
#include "net/sock.h"

#include "connection.h"

#include "source.h"
#include "global.h"
#include "refbuf.h"
#include "client.h"
#include "stats.h"
#include "xslt.h"
#include "util.h"
#define CATMODULE "stats"
#include "logging.h"

#ifdef _WIN32
#define atoll _atoi64
#define vsnprintf _vsnprintf
#define snprintf _snprintf
#endif

#define STATS_EVENT_SET     0
#define STATS_EVENT_INC     1
#define STATS_EVENT_DEC     2
#define STATS_EVENT_ADD     3
#define STATS_EVENT_SUB     4
#define STATS_EVENT_REMOVE  5
#define STATS_EVENT_HIDDEN  6

typedef struct _event_queue_tag
{
    volatile stats_event_t *head : itype(_Ptr<volatile stats_event_t>);
    volatile stats_event_t **tail : itype(_Ptr<_Ptr<volatile stats_event_t>>);
} event_queue_t;

#define event_queue_init(qp)    { (qp)->head = NULL; (qp)->tail = &(qp)->head; }

typedef struct _event_listener_tag
{
    event_queue_t queue;
    mutex_t mutex;

    _Ptr<struct _event_listener_tag> next;
} event_listener_t;

static volatile int _stats_running = 0;
static _Ptr<thread_type> _stats_thread_id = ((void *)0);
static volatile int _stats_threads = 0;

static stats_t _stats;
static mutex_t _stats_mutex;

static event_queue_t _global_event_queue;
mutex_t _global_event_mutex;

static _Ptr<volatile event_listener_t> _event_listeners = ((void *)0);


static void *_stats_thread(void *arg);
static int _compare_stats(void *a, void *b, void *arg);
static int _compare_source_stats(void *a, void *b, void *arg);
static int _free_stats(void *key);
static int _free_source_stats(void *key);
static void _add_event_to_queue(_Ptr<stats_event_t> event, _Ptr<event_queue_t> queue);
static _Ptr<stats_node_t> _find_node(_Ptr<avl_tree> tree, _Nt_array_ptr<const char> name);
static _Ptr<stats_source_t> _find_source(_Ptr<avl_tree> tree, _Nt_array_ptr<const char> source);
static void _free_event(_Ptr<stats_event_t> event);
static _Ptr<stats_event_t> _get_event_from_queue(_Ptr<event_queue_t> queue);


/* simple helper function for creating an event */
static _Ptr<stats_event_t> build_event(_Nt_array_ptr<const char> source, _Nt_array_ptr<const char> name , _Nt_array_ptr<const char> value : byte_count(0))
{
    _Ptr<stats_event_t> event = ((void *)0);

    event = (_Ptr<stats_event_t>)calloc<stats_event_t>(1, sizeof(stats_event_t));
    if (event)
    {
        if (source)
            event->source = (_Nt_array_ptr<char>)strdup(source);
        if (name)
            event->name = (_Nt_array_ptr<char>)strdup(name);
        if (value)
            event->value = (char *)strdup(value);
        else
            event->action = STATS_EVENT_REMOVE;
    }
    return event;
}

static void queue_global_event (_Ptr<stats_event_t> event)
{
    thread_mutex_lock(&_global_event_mutex);
    _add_event_to_queue (event, &_global_event_queue);
    thread_mutex_unlock(&_global_event_mutex);
}

void stats_initialize(void)
{
    _event_listeners = NULL;

    /* set up global struct */
    _stats.global_tree = avl_tree_new<void>((_compare_stats), NULL);
    _stats.source_tree = avl_tree_new<void>((_compare_source_stats), NULL);

    /* set up global mutex */
    thread_mutex_create(&_stats_mutex);

    /* set up stats queues */
    event_queue_init (&_global_event_queue);
    thread_mutex_create(&_global_event_mutex);

    /* fire off the stats thread */
    _stats_running = 1;
    _stats_thread_id = thread_create(void, void, "Stats Thread", (_stats_thread), NULL, THREAD_ATTACHED);
}

void stats_shutdown(void)
{
    int n;

    if(!_stats_running) /* We can't shutdown if we're not running. */
        return;

    /* wait for thread to exit */
    _stats_running = 0;
    thread_join(_stats_thread_id);

    /* wait for other threads to shut down */
    do {
        thread_sleep(300000);
        thread_mutex_lock(&_stats_mutex);
        n = _stats_threads;
        thread_mutex_unlock(&_stats_mutex);
    } while (n > 0);
    ICECAST_LOG_INFO("stats thread finished");

    /* free the queues */

    /* destroy the queue mutexes */
    thread_mutex_destroy(&_global_event_mutex);

    thread_mutex_destroy(&_stats_mutex);
    avl_tree_free(_stats.source_tree, (_free_source_stats));
    avl_tree_free(_stats.global_tree, (_free_stats));

    while (1)
    {
        _Ptr<stats_event_t> event = _get_event_from_queue (&_global_event_queue);
        if (event == NULL) break;
        if(event->source)
            free<char>(event->source);
        if(event->value)
            free<char>(event->value);
        if(event->name)
            free<char>(event->name);
        free<stats_event_t>(event);
    }
}

stats_t *stats_get_stats(void) : itype(_Ptr<stats_t>)
{
    /* lock global stats
    
     copy stats

     unlock global stats

     return copied stats */

    return NULL;
}

/* simple name=tag stat create/update */
void stats_event(const char *source : itype(_Nt_array_ptr<const char>), const char *name : itype(_Nt_array_ptr<const char>) , const char *value : itype(_Nt_array_ptr<const char>))
{
    _Ptr<stats_event_t> event = ((void *)0);

    if (value && xmlCheckUTF8 ((unsigned char *)value) == 0)
    {
        ICECAST_LOG_WARN("seen non-UTF8 data, probably incorrect metadata (%s, %s)", name, value);
        return;
    }
    event = build_event (source, name, _Assume_bounds_cast<_Nt_array_ptr<const char>>(value,  byte_count(0)));
    if (event)
        queue_global_event (event);
}


/* wrapper for stats_event, this takes a charset to convert from */
void stats_event_conv(const char *mount : itype(_Nt_array_ptr<const char>), const char *name : itype(_Nt_array_ptr<const char>), const char *value : itype(_Nt_array_ptr<const char>), const char *charset : itype(_Ptr<const char>))
{
    const char *metadata = value;
    xmlBufferPtr conv = xmlBufferCreate ();

    if (charset)
    {
        xmlCharEncodingHandlerPtr handle = xmlFindCharEncodingHandler (charset);

        if (handle)
        {
            xmlBufferPtr raw = xmlBufferCreate ();
            xmlBufferAdd (raw, (const xmlChar *)value, strlen (value));
            if (xmlCharEncInFunc (handle, conv, raw) > 0)
                metadata = (char *)xmlBufferContent (conv);
            xmlBufferFree (raw);
            xmlCharEncCloseFunc (handle);
        }
        else
            ICECAST_LOG_WARN("No charset found for \"%s\"", charset);
    }

    stats_event (mount, name, metadata);
    xmlBufferFree (conv);
}

/* make stat hidden (non-zero). name can be NULL if it applies to a whole
 * source stats tree. */
void stats_event_hidden (const char *source : itype(_Nt_array_ptr<const char>), const char *name : itype(_Nt_array_ptr<const char>) , int hidden)
{
    _Ptr<stats_event_t> event = ((void *)0);
    _Nt_array_ptr<const char> str : byte_count(0) = NULL;

    if (hidden)
        str = "";
    event = build_event (source, name, str);
    if (event)
    {
        event->action = STATS_EVENT_HIDDEN;
        queue_global_event (event);
    }
}

/* printf style formatting for stat create/update */
void stats_event_args(const char *source : itype(_Nt_array_ptr<const char>), char *name : itype(_Nt_array_ptr<char>), char *format : itype(_Nt_array_ptr<char>), ...)
{
    char buf _Nt_checked[1024];
    va_list val;
    int ret;

    if (name == NULL)
        return;
    va_start(val, format);
    ret = vsnprintf(_Assume_bounds_cast<_Nt_array_ptr<char>>(buf,bounds((char *)buf, (char *)buf + sizeof (buf))), sizeof(buf), format, val);
    va_end(val);

    if (ret < 0 || (unsigned int)ret >= sizeof (buf))
    {
        ICECAST_LOG_WARN("problem with formatting %s stat %s",
                source==NULL ? "global" : source, name);
        return;
    }
    stats_event(source, name, buf);
}

static _Nt_array_ptr<char> _get_stats(_Nt_array_ptr<const char> source, _Nt_array_ptr<const char> name)
{
    _Ptr<stats_node_t> stats = NULL;
    _Ptr<stats_source_t> src = NULL;
    _Nt_array_ptr<char> value = NULL;

    thread_mutex_lock(&_stats_mutex);

    if (source == NULL) {
        stats = _find_node(_stats.global_tree, name);
    } else {
        src = _find_source(_stats.source_tree, source);
        if (src) {
            stats = _find_node(src->stats_tree, name);
        }
    }

    if (stats) value = (_Nt_array_ptr<char>) strdup(stats->value);

    thread_mutex_unlock(&_stats_mutex);

    return value;
}

char *stats_get_value(const char *source : itype(_Nt_array_ptr<const char>), const char *name : itype(_Nt_array_ptr<const char>)) : itype(_Ptr<char>)
{
    return(_get_stats(source, name));
}

/* increase the value in the provided stat by 1 */
void stats_event_inc(const char *source : itype(_Nt_array_ptr<const char>), const char *name : itype(_Nt_array_ptr<const char>))
{
    _Ptr<stats_event_t> event = build_event (source, name, NULL);
    /* ICECAST_LOG_DEBUG("%s on %s", name, source==NULL?"global":source); */
    if (event)
    {
        event->action = STATS_EVENT_INC;
        queue_global_event (event);
    }
}

void stats_event_add(const char *source : itype(_Nt_array_ptr<const char>), const char *name : itype(_Nt_array_ptr<const char>), unsigned long value)
{
    _Ptr<stats_event_t> event = build_event (source, name, NULL);
    /* ICECAST_LOG_DEBUG("%s on %s", name, source==NULL?"global":source); */
    if (event)
    {
        event->value = malloc<char> (16);
        snprintf (event->value, 16, "%ld", value);
        event->action = STATS_EVENT_ADD;
        queue_global_event (event);
    }
}

void stats_event_sub(const char *source : itype(_Nt_array_ptr<const char>), const char *name : itype(_Nt_array_ptr<const char>), unsigned long value)
{
    _Ptr<stats_event_t> event = build_event (source, name, NULL);
    if (event)
    {
        event->value = malloc<char> (16);
        snprintf (event->value, 16, "%ld", value);
        event->action = STATS_EVENT_SUB;
        queue_global_event (event);
    }
}

/* decrease the value in the provided stat by 1 */
void stats_event_dec(const char *source : itype(_Nt_array_ptr<const char>), const char *name : itype(_Nt_array_ptr<const char>))
{
    /* ICECAST_LOG_DEBUG("%s on %s", name, source==NULL?"global":source); */
    _Ptr<stats_event_t> event = build_event (source, name, NULL);
    if (event)
    {
        event->action = STATS_EVENT_DEC;
        queue_global_event (event);
    }
}

/* note: you must call this function only when you have exclusive access
** to the avl_tree
*/
static _Ptr<stats_node_t> _find_node(_Ptr<avl_tree> stats_tree, _Nt_array_ptr<const char> name)
{
    _Ptr<stats_node_t> stats = ((void *)0);
    _Ptr<avl_node> node = ((void *)0);
    int cmp;

    /* get the root node */
    node = stats_tree->root->right;
    
    while (node) {
        stats = avl_get<stats_node_t>(node);
        cmp = strcmp(name, stats->name);
        if (cmp < 0) 
            node = node->left;
        else if (cmp > 0)
            node = node->right;
        else
            return stats;
    }
    
    /* didn't find it */
    return NULL;
}

/* note: you must call this function only when you have exclusive access
** to the avl_tree
*/
static _Ptr<stats_source_t> _find_source(_Ptr<avl_tree> source_tree, _Nt_array_ptr<const char> source)
{
    _Ptr<stats_source_t> stats = ((void *)0);
    _Ptr<avl_node> node = ((void *)0);
    int cmp;

    /* get the root node */
    node = source_tree->root->right;
    while (node) {
        stats = avl_get<stats_source_t>(node);
        cmp = strcmp(source, stats->source);
        if (cmp < 0)
            node = node->left;
        else if (cmp > 0)
            node = node->right;
        else
            return stats;
    }

    /* didn't find it */
    return NULL;
}

static _Ptr<stats_event_t> _copy_event(_Ptr<stats_event_t> event)
{
    _Ptr<stats_event_t> copy = (_Ptr<stats_event_t>)calloc<stats_event_t>(1, sizeof(stats_event_t));
    if (event->source) 
        copy->source = (_Nt_array_ptr<char>)strdup(event->source);
    else
        copy->source = NULL;
    if (event->name)
        copy->name = (_Nt_array_ptr<char>)strdup(event->name);
    if (event->value)
        copy->value = (char *)strdup(event->value);
    else
        copy->value = NULL;
    copy->hidden = event->hidden;
    copy->next = NULL;

    return copy;
}


/* helper to apply specialised changes to a stats node */
static void modify_node_event (_Ptr<stats_node_t> node, _Ptr<stats_event_t> event)
{
    char *str;

    if (event->action == STATS_EVENT_HIDDEN)
    {
        if (event->value)
            node->hidden = 1;
        else
            node->hidden = 0;
        return;
    }
    if (event->action != STATS_EVENT_SET)
    {
        int64_t value = 0;

        switch (event->action)
        {
            case STATS_EVENT_INC:
                value = atoi (node->value)+1;
                break;
            case STATS_EVENT_DEC:
                value = atoi (node->value)-1;
                break;
            case STATS_EVENT_ADD:
                value = atoi (node->value)+atoi (event->value);
                break;
            case STATS_EVENT_SUB:
                value = atoll (node->value) - atoll (event->value);
                break;
            default:
                ICECAST_LOG_WARN("unhandled event (%d) for %s", event->action, event->source);
                break;
        }
        str = malloc<char> (16);
        snprintf (str, 16, "%" PRId64, value);
        if (event->value == NULL)
            event->value = strdup (str);
    }
    else
        str = (char *)strdup (event->value);
    free<char> (node->value);
    node->value = str;
    if (event->source)
        ICECAST_LOG_DEBUG("update \"%s\" %s (%s)", event->source, node->name, node->value);
    else
        ICECAST_LOG_DEBUG("update global %s (%s)", node->name, node->value);
}


static void process_global_event (_Ptr<stats_event_t> event)
{
    stats_node_t *node;

    /* ICECAST_LOG_DEBUG("global event %s %s %d", event->name, event->value, event->action); */
    if (event->action == STATS_EVENT_REMOVE)
    {
        /* we're deleting */
        node = ((stats_node_t *)_find_node(_stats.global_tree, event->name));
        if (node != NULL)
            avl_delete<void>(_stats.global_tree, (void *)node, (_free_stats));
        return;
    }
    node = ((stats_node_t *)_find_node(_stats.global_tree, event->name));
    if (node)
    {
        modify_node_event (_Assume_bounds_cast<_Ptr<stats_node_t>>(node), event);
    }
    else
    {
        /* add node */
        node = (stats_node_t *)calloc<stats_node_t>(1, sizeof(stats_node_t));
        node->name = (char *)strdup(event->name);
        node->value = (char *)strdup(event->value);

        avl_insert<void>(_stats.global_tree, (void *)node);
    }
}


static void process_source_event (_Ptr<stats_event_t> event)
{
    stats_source_t *snode = ((stats_source_t *)_find_source(_stats.source_tree, event->source));
    if (snode == NULL)
    {
        if (event->action == STATS_EVENT_REMOVE)
            return;
        snode = (stats_source_t *)calloc<stats_source_t>(1,sizeof(stats_source_t));
        if (snode == NULL)
            return;
        ICECAST_LOG_DEBUG("new source stat %s", event->source);
        snode->source = (char *)strdup(event->source);
        snode->stats_tree = avl_tree_new<void>((_compare_stats), NULL);
        if (event->action == STATS_EVENT_HIDDEN)
            snode->hidden = 1;
        else
            snode->hidden = 0;

        avl_insert<void>(_stats.source_tree, (void *)snode);
    }
    if (event->name)
    {
        stats_node_t *node = ((stats_node_t *)_find_node(snode->stats_tree, event->name));
        if (node == NULL)
        {
            if (event->action == STATS_EVENT_REMOVE)
                return;
            /* adding node */
            if (event->value)
            {
                ICECAST_LOG_DEBUG("new node %s (%s)", event->name, event->value);
                node = (stats_node_t *)calloc<stats_node_t>(1,sizeof(stats_node_t));
                node->name = (char *)strdup(event->name);
                node->value = (char *)strdup(event->value);
                node->hidden = snode->hidden;

                avl_insert<void>(snode->stats_tree, (void *)node);
            }
            return;
        }
        if (event->action == STATS_EVENT_REMOVE)
        {
            ICECAST_LOG_DEBUG("delete node %s", event->name);
            avl_delete<void>(snode->stats_tree, (void *)node, (_free_stats));
            return;
        }
        modify_node_event (_Assume_bounds_cast<_Ptr<stats_node_t>>(node), event);
        return;
    }
    if (event->action == STATS_EVENT_HIDDEN)
    {
        _Ptr<avl_node> node = avl_get_first (snode->stats_tree);

        if (event->value)
            snode->hidden = 1;
        else
            snode->hidden = 0;
        while (node)
        {
            _Ptr<stats_node_t> stats = avl_get<stats_node_t>(node);
            stats->hidden = snode->hidden;
            node = avl_get_next (node);
        }
        return;
    }
    if (event->action == STATS_EVENT_REMOVE)
    {
        ICECAST_LOG_DEBUG("delete source node %s", event->source);
        avl_delete<void>(_stats.source_tree, (void *)snode, (_free_source_stats));
    }
}

/* NOTE: implicit %z is added to format string. */
static inline void __format_time(_Nt_array_ptr<char> buffer : count(len), size_t len, _Nt_array_ptr<const char> format) {
    time_t now = time(NULL);
    struct tm local;
    char tzbuffer _Nt_checked[32];
    char timebuffer _Nt_checked[128];
#ifdef _WIN32
    struct tm *thetime;
    int time_days, time_hours, time_tz;
    int tempnum1, tempnum2;
    char sign;
#endif

    localtime_r (&now, &local);
#ifndef _WIN32
    strftime (_Assume_bounds_cast<_Nt_array_ptr<char>>(tzbuffer,bounds((char *)tzbuffer, (char *)tzbuffer + sizeof (tzbuffer))), sizeof(tzbuffer), "%z", &local);
#else
    thetime = gmtime (&now);
    time_days = local.tm_yday - thetime->tm_yday;

    if (time_days < -1) {
        tempnum1 = 24;
    } else {
        tempnum1 = 1;
    }

    if (tempnum1 < time_days) {
        tempnum2 = -24;
    } else {
        tempnum2 = time_days*24;
    }

    time_hours = (tempnum2 + local.tm_hour - thetime->tm_hour);
    time_tz = time_hours * 60 + local.tm_min - thetime->tm_min;

    if (time_tz < 0) {
        sign = '-';
        time_tz = -time_tz;
    } else {
        sign = '+';
    }

    snprintf(tzbuffer, sizeof(tzbuffer), "%c%.2d%.2d", sign, time_tz / 60, time_tz % 60);
#endif
    strftime (_Assume_bounds_cast<_Nt_array_ptr<char>>(timebuffer,bounds((char *)timebuffer, (char *)timebuffer + sizeof (timebuffer))), sizeof(timebuffer), format, &local);

    snprintf(buffer, len, "%s%s", timebuffer, tzbuffer);
}

void stats_event_time (const char *mount : itype(_Nt_array_ptr<const char>), const char *name : itype(_Nt_array_ptr<const char>))
{
    char buffer _Nt_checked[100];

    __format_time(buffer, sizeof(buffer) - 1, "%a, %d %b %Y %H:%M:%S ");
    stats_event (mount, name, buffer);
}


void stats_event_time_iso8601 (const char *mount : itype(_Nt_array_ptr<const char>), const char *name : itype(_Nt_array_ptr<const char>))
{
    char buffer _Nt_checked[100];

    __format_time(buffer, sizeof(buffer) - 1, "%Y-%m-%dT%H:%M:%S");
    stats_event (mount, name, buffer);
}


void stats_global (ice_config_t *config : itype(_Ptr<ice_config_t>))
{
    stats_event (NULL, "server_id", config->server_id);
    stats_event (NULL, "host", config->hostname);
    stats_event (NULL, "location", config->location);
    stats_event (NULL, "admin", config->admin);
}


static void *_stats_thread(void *arg)
{
    _Ptr<stats_event_t> event = ((void *)0);
    _Ptr<stats_event_t> copy = ((void *)0);
    _Ptr<event_listener_t> listener = ((void *)0);

    stats_event_time (NULL, "server_start");
    stats_event_time_iso8601 (NULL, "server_start_iso8601");

    /* global currently active stats */
    stats_event (NULL, "clients", "0");
    stats_event (NULL, "connections", "0");
    stats_event (NULL, "sources", "0");
    stats_event (NULL, "stats", "0");
    stats_event (NULL, "listeners", "0");

    /* global accumulating stats */
    stats_event (NULL, "client_connections", "0");
    stats_event (NULL, "source_client_connections", "0");
    stats_event (NULL, "source_relay_connections", "0");
    stats_event (NULL, "source_total_connections", "0");
    stats_event (NULL, "stats_connections", "0");
    stats_event (NULL, "listener_connections", "0");

    ICECAST_LOG_INFO("stats thread started");
    while (_stats_running) {
        thread_mutex_lock(&_global_event_mutex);
        if (_global_event_queue.head != NULL) {
            /* grab the next event from the queue */
            event = _get_event_from_queue (&_global_event_queue);
            thread_mutex_unlock(&_global_event_mutex);

            if (event == NULL)
                continue;
            event->next = NULL;

            thread_mutex_lock(&_stats_mutex);

            /* check if we are dealing with a global or source event */
            if (event->source == NULL)
                process_global_event (event);
            else
                process_source_event (event);
            
            /* now we have an event that's been processed into the running stats */
            /* this event should get copied to event listeners' queues */
            listener = (_Ptr<event_listener_t>)_event_listeners;
            while (listener) {
                copy = _copy_event(event);
                thread_mutex_lock (&listener->mutex);
                _add_event_to_queue (copy, &listener->queue);
                thread_mutex_unlock (&listener->mutex);

                listener = listener->next;
            }

            /* now we need to destroy the event */
            _free_event(event);

            thread_mutex_unlock(&_stats_mutex);
            continue;
        }
        else
        {
            thread_mutex_unlock(&_global_event_mutex);
        }

        thread_sleep(300000);
    }

    return NULL;
}

/* you must have the _stats_mutex locked here */
static void _unregister_listener(_Ptr<event_listener_t> listener)
{
    _Ptr<_Ptr<event_listener_t>> prev = (_Ptr<_Ptr<event_listener_t>>)&_event_listeners;
    _Ptr<event_listener_t> current = *prev;

    while (current)
    {
        if (current == listener)
        {
            *prev = current->next;
            break;
        }
        prev = &current->next;
        current = *prev;
    }
}


static _Ptr<stats_event_t> _make_event_from_node(_Ptr<stats_node_t> node, _Nt_array_ptr<char> source)
{
    _Ptr<stats_event_t> event = (_Ptr<stats_event_t>)malloc<stats_event_t>(sizeof(stats_event_t));
    
    if (source != NULL)
        event->source = (_Nt_array_ptr<char>)strdup(source);
    else
        event->source = NULL;
    event->name = (_Nt_array_ptr<char>)strdup(node->name);
    event->value = (char *)strdup(node->value);
    event->hidden = node->hidden;
    event->action = STATS_EVENT_SET;
    event->next = NULL;

    return event;
}


static void _add_event_to_queue(_Ptr<stats_event_t> event, _Ptr<event_queue_t> queue)
{
    *queue->tail = event;
    queue->tail = (_Ptr<_Ptr<volatile stats_event_t>>)&event->next;
}


static _Ptr<stats_event_t> _get_event_from_queue(_Ptr<event_queue_t> queue)
{
    _Ptr<stats_event_t> event = NULL;

    if (queue && queue->head)
    {
        event = (_Ptr<stats_event_t>)queue->head;
        queue->head = event->next;
        if (queue->head == NULL)
            queue->tail = &queue->head;
    }

    return event;
}

static int _send_event_to_client(_Ptr<stats_event_t> event, _Ptr<client_t> client)
{
    int len;
    char buf _Nt_checked[200];

    /* send data to the client!!!! */
    len = snprintf (buf, sizeof (buf), "EVENT %s %s %s\n",
            (event->source != NULL) ? event->source : "global",
            event->name ? event->name : "null",
            event->value ? event->value : "null");
    if (len > 0 && len < (int)sizeof (buf))
    {
        _Nt_array_ptr<char> tmp : count(len) = _Assume_bounds_cast<_Nt_array_ptr<char>>(buf, count(len));
        client_send_bytes<char>(client, tmp, len);
        if (client->con->error)
            return -1;
    }
    return 0;
}


static xmlNodePtr _dump_stats_to_doc (xmlNodePtr root, _Nt_array_ptr<const char> show_mount, int hidden)
{
    _Ptr<avl_node> avlnode = ((void *)0);
    xmlNodePtr ret = NULL;

    thread_mutex_lock(&_stats_mutex);
    /* general stats first */
    avlnode = avl_get_first(_stats.global_tree);
    while (avlnode)
    {
        stats_node_t *stat = avlnode->key;
        if (stat->hidden <=  hidden)
            xmlNewTextChild (root, NULL,(stat->name),(stat->value));
        avlnode = avl_get_next (avlnode);
    }
    /* now per mount stats */
    avlnode = avl_get_first(_stats.source_tree);
    while (avlnode)
    {
        _Ptr<stats_source_t> source = avl_get<stats_source_t>(avlnode);
        if (source->hidden <= hidden &&
                (show_mount == NULL || strcmp (show_mount, source->source) == 0))
        {
            _Ptr<avl_node> avlnode2 = avl_get_first (source->stats_tree);
            xmlNodePtr xmlnode = xmlNewTextChild (root, NULL, XMLSTR("source"), NULL);

            xmlSetProp (xmlnode, XMLSTR("mount"),(source->source));
            if (ret == NULL)
                ret = xmlnode;
            while (avlnode2)
            {
                stats_node_t *stat = avlnode2->key;
                xmlNewTextChild (xmlnode, NULL,(stat->name),(stat->value));
                avlnode2 = avl_get_next (avlnode2);
            }
        }
        avlnode = avl_get_next (avlnode);
    }
    thread_mutex_unlock(&_stats_mutex);
    return ret;
}


/* factoring out code for stats loops
** this function copies all stats to queue, and registers 
** the queue for all new events atomically.
** note: mutex must already be created!
*/
static void _register_listener (_Ptr<event_listener_t> listener)
{
    _Ptr<avl_node> node = ((void *)0);
    _Ptr<avl_node> node2 = ((void *)0);
    _Ptr<stats_event_t> event = ((void *)0);
    _Ptr<stats_source_t> source = ((void *)0);

    thread_mutex_lock(&_stats_mutex);

    /* first we fill our queue with the current stats */
    
    /* start with the global stats */
    node = avl_get_first(_stats.global_tree);
    while (node) {
        event = _make_event_from_node(avl_get<stats_node_t>(node), NULL);
        _add_event_to_queue (event, &listener->queue);

        node = avl_get_next(node);
    }

    /* now the stats for each source */
    node = avl_get_first(_stats.source_tree);
    while (node) {
        source = avl_get<stats_source_t>(node);
        node2 = avl_get_first(source->stats_tree);
        while (node2) {
            event = _make_event_from_node(avl_get<stats_node_t>(node2), _Assume_bounds_cast<_Nt_array_ptr<char>>(source->source, byte_count(0)));
            _add_event_to_queue (event, &listener->queue);

            node2 = avl_get_next(node2);
        }
        
        node = avl_get_next(node);
    }

    /* now we register to receive future event notices */
    listener->next = (_Ptr<event_listener_t>)_event_listeners;
    _event_listeners = listener;

    thread_mutex_unlock(&_stats_mutex);
}

_Ptr<char> stats_connection(_Ptr<client_t> arg)
{
    _Ptr<client_t> client = (_Ptr<client_t>)arg;
    _Ptr<stats_event_t> event = ((void *)0);
    event_listener_t listener = {};

    ICECAST_LOG_INFO("stats client starting");

    event_queue_init (&listener.queue);
    /* increment the thread count */
    thread_mutex_lock(&_stats_mutex);
    _stats_threads++;
    stats_event_args (NULL, "stats", "%d", _stats_threads);
    thread_mutex_unlock(&_stats_mutex);

    thread_mutex_create (&(listener.mutex));

    _register_listener (&listener);

    while (_stats_running) {
        thread_mutex_lock (&listener.mutex);
        event = _get_event_from_queue (&listener.queue);
        thread_mutex_unlock (&listener.mutex);
        if (event != NULL) {
            if (_send_event_to_client(event, client) < 0) {
                _free_event(event);
                break;
            }
            _free_event(event);
            continue;
        }
        thread_sleep (500000);
    }

    thread_mutex_lock(&_stats_mutex);
    _unregister_listener (&listener);
    _stats_threads--;
    stats_event_args (NULL, "stats", "%d", _stats_threads);
    thread_mutex_unlock(&_stats_mutex);

    thread_mutex_destroy (&listener.mutex);
    client_destroy (client);
    ICECAST_LOG_INFO("stats client finished");

    return NULL;
}


_Itype_for_any(T) void stats_callback(client_t *client : itype(_Ptr<client_t>), void *notused : itype(_Ptr<T>))
{
    if (client->con->error)
    {
        client_destroy (client);
        return;
    }
    client_set_queue (client, NULL);
    thread_create(client_t, char, "Stats Connection", stats_connection, client, THREAD_DETACHED);
}


typedef struct _source_xml_tag {
    char *mount : itype(_Ptr<char>);
    xmlNodePtr node;

    struct _source_xml_tag *next : itype(_Ptr<struct _source_xml_tag>);
} source_xml_t;


void stats_transform_xslt(client_t *client : itype(_Ptr<client_t>), const char *uri : itype(_Nt_array_ptr<const char>))
{
    xmlDocPtr doc = NULL;
    _Nt_array_ptr<char> xslpath = ((_Nt_array_ptr<char> )util_get_path_from_normalised_uri (uri));
    _Nt_array_ptr<const char> mount = (_Nt_array_ptr<const char>) httpp_get_query_param (client->parser, "mount");

    doc = stats_get_xml (0, mount);

    xslt_transform(doc, xslpath, client);

    xmlFreeDoc(doc);
    free<char> (xslpath);
}

xmlDocPtr stats_get_xml(int show_hidden, const char *show_mount : itype(_Nt_array_ptr<const char>)) : itype(_Ptr<xmlDoc>)
{
    xmlDocPtr doc = NULL;
    xmlNodePtr node = NULL;

    doc = xmlNewDoc (XMLSTR("1.0"));
    node = xmlNewDocNode (doc, NULL, XMLSTR("icestats"), NULL);
    xmlDocSetRootElement(doc, node);

    node = _dump_stats_to_doc (node, show_mount, show_hidden);

    return doc;
}


static int _compare_stats(void *arg, void *a, void *b)
{
    stats_node_t *nodea = (stats_node_t *)a;
    stats_node_t *nodeb = (stats_node_t *)b;

    return strcmp(nodea->name, nodeb->name);
}

static int _compare_source_stats(void *arg, void *a, void *b)
{
    stats_source_t *nodea = (stats_source_t *)a;
    stats_source_t *nodeb = (stats_source_t *)b;

    return strcmp(nodea->source, nodeb->source);
}

static int _free_stats(void *key)
{
    stats_node_t *node = (stats_node_t *)key;
    free<char>(node->value);
    free<char>(node->name);
    free<stats_node_t>(node);
    
    return 1;
}

static int _free_source_stats(void *key)
{
    stats_source_t *node = (stats_source_t *)key;
    avl_tree_free(node->stats_tree, (_free_stats));
    free<char>(node->source);
    free<stats_source_t>(node);

    return 1;
}

static void _free_event(_Ptr<stats_event_t> event)
{
    if (event->source) free<char>(event->source);
    if (event->name) free<char>(event->name);
    if (event->value) free<char>(event->value);
    free<stats_event_t>(event);
}


refbuf_t *stats_get_streams(void) : itype(_Ptr<refbuf_t>)
{
#define STREAMLIST_BLKSIZE  4096
    _Ptr<avl_node> node = ((void *)0);
    unsigned int remaining = STREAMLIST_BLKSIZE;
    _Ptr<refbuf_t> start = refbuf_new (remaining);
_Ptr<refbuf_t> cur = start;

    _Nt_array_ptr<char> buffer = cur->data;

    /* now the stats for each source */
    thread_mutex_lock (&_stats_mutex);
    node = avl_get_first(_stats.source_tree);
    while (node)
    {
        int ret;
        _Ptr<stats_source_t> source = avl_get<stats_source_t>(node);

        if (source->hidden == 0)
        {
            if (remaining <= strlen (source->source) + 3)
            {
                int newLen = STREAMLIST_BLKSIZE - remaining;
                cur->data = _Assume_bounds_cast<_Nt_array_ptr<char>>(cur->data, count(newLen)), cur->len = newLen;
                cur->next = refbuf_new (STREAMLIST_BLKSIZE);
                remaining = STREAMLIST_BLKSIZE;
                cur = cur->next;
                buffer = cur->data;
            }
            ret = snprintf (buffer, remaining, "%s\r\n", source->source);
            if (ret > 0)
            {
                buffer += ret;
                remaining -= ret;
            }
        }
        node = avl_get_next(node);
    }
    thread_mutex_unlock (&_stats_mutex);
    int newLen = STREAMLIST_BLKSIZE - remaining;
    cur->len = newLen;
    return start;
}



/* This removes any source stats from virtual mountpoints, ie mountpoints
 * where no source_t exists. This function requires the global sources lock
 * to be held before calling.
 */
void stats_clear_virtual_mounts (void)
{
    _Ptr<avl_node> snode = ((void *)0);

    thread_mutex_lock (&_stats_mutex);
    snode = avl_get_first(_stats.source_tree);
    while (snode)
    {
        _Ptr<stats_source_t> src = avl_get<stats_source_t>(snode);
        _Ptr<source_t> source = source_find_mount_raw (_Assume_bounds_cast<_Nt_array_ptr<const char>>(src->source, byte_count(0)));

        if (source == NULL)
        {
            /* no source_t is reserved so remove them now */
            snode = avl_get_next (snode);
            ICECAST_LOG_DEBUG("releasing %s stats", src->source);
            avl_delete<stats_source_t> (_stats.source_tree, src, (_free_source_stats));
            continue;
        }

        snode = avl_get_next (snode);
    }
    thread_mutex_unlock (&_stats_mutex);
}

