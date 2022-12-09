#ifndef ERLANG_MODSEC_MODSEC_NIF_H
#define ERLANG_MODSEC_MODSEC_NIF_H

typedef unsigned char byte;

typedef struct
{
    ErlNifResourceType *modsec_rt;
} modsec_privdata_t;

typedef struct
{
    ModSecurity *modsec;
    RulesSet *rules;
    int nr_of_threads;
} ctx_t;

typedef enum
{
    UNKNOWN,
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