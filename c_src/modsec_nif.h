#ifndef ERLANG_MODSEC_MODSEC_NIF_H
#define ERLANG_MODSEC_MODSEC_NIF_H

#include "async_queue.h"

typedef unsigned char byte;

typedef struct
{
    ErlNifResourceType *modsec_rt;
} modsec_privdata_t;

typedef struct
{
    async_queue_t *queue;
    ErlNifThreadOpts *topts;
    ErlNifTid *tids;
    ModSecurity *modsec;
    RulesSet *rules;
    int nr_of_threads;
} ctx_t;

typedef enum
{
    UNKNOWN,
    SHUTDOWN,
    MODSEC_CHECK_REQUEST,
    MODSEC_CHECK_RESPONSE
} task_type_t;

typedef struct
{
    task_type_t type;
    ErlNifEnv *env;
    ErlNifPid pid;
    ERL_NIF_TERM ref;
    ModSecurity *modsec;
    RulesSet *rules;
    ERL_NIF_TERM logs;
    union
    {
        struct
        {
            ErlNifBinary method;
            ErlNifBinary uri;
            ErlNifBinary body;
            ERL_NIF_TERM headers;
        } d;
    } data;
} task_t;

#endif // ERLANG_MODSEC_MODSEC_NIF_H