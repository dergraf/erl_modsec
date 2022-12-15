#include "modsecurity/rules_set.h"
#include "modsecurity/modsecurity.h"
#include "modsecurity/transaction.h"
#include "modsecurity/intervention.h"
#include <assert.h>
#include <erl_nif.h>

typedef struct
{
    ErlNifEnv *env;
    ERL_NIF_TERM logs;
} task_t;

ModSecurity *modsec;
RulesSet *rules;

// for -Wmissing-prototypes
void msc_logdata(void *, const void *);

void msc_logdata(void *cb_data, const void *data)
{
    task_t *task = (task_t *)cb_data;
    size_t len = strlen((const char *)data); // to make sure that trailing NULL (aka \0) is also copied
    ErlNifBinary bin;
    enif_alloc_binary(len, &bin);
    memcpy(bin.data, data, len);
    ERL_NIF_TERM log_binary = enif_make_binary(task->env, &bin);
    task->logs = enif_make_list_cell(task->env, log_binary, task->logs);
}

static int process_intervention(task_t task, Transaction *transaction)
{
    ModSecurityIntervention intervention;
    intervention.status = 200;
    intervention.url = NULL;
    intervention.log = NULL;
    intervention.disruptive = 0;
    if (msc_intervention(transaction, &intervention) == 0)
    {
        return 0;
    };

    if (intervention.log)
    {
        msc_logdata(&task, intervention.log);
        // FIXME This may cause segfault or even worse memory corruptions
        // since intervention.log allocation didn't happen in this scope!
        free(intervention.log);
    }
    else
    {
        msc_logdata(&task, "(no log message was specified)");
    }

    return 1;
}

static ERL_NIF_TERM check_request(ErlNifEnv *env, ModSecurity *modsec, RulesSet *rules, ErlNifBinary method, ErlNifBinary uri, ERL_NIF_TERM headers, ErlNifBinary body)
{
    Transaction *transaction = NULL;
    ERL_NIF_TERM head;
    ERL_NIF_TERM *tuple;
    ErlNifBinary header_name, header_value;
    int tuple_arity = 2;

    // task_t *task = alloc_task();
    task_t task;
    task.env = env;
    task.logs = enif_make_list(env, 0);

    transaction = msc_new_transaction(modsec, rules, &task);
    while (enif_get_list_cell(env, headers, &head, (ERL_NIF_TERM *)&headers))
    {
        if (!enif_get_tuple(env, head, &tuple_arity, (const ERL_NIF_TERM **)&tuple) ||
            !enif_inspect_binary(env, tuple[0], &header_name) ||
            !enif_inspect_binary(env, tuple[1], &header_value))
        {
            return enif_make_tuple2(
                env,
                enif_make_atom(env, "error"),
                enif_make_string(env, "invalid request headers", ERL_NIF_LATIN1));
        }
        msc_add_n_request_header(transaction,
                                 (const unsigned char *)header_name.data, header_name.size,
                                 (const unsigned char *)header_value.data, header_value.size);
    }
    msc_append_request_body(transaction, (unsigned char *)body.data, body.size);
    msc_process_connection(transaction, "127.0.0.1", 80, "127.0.0.1", 80);
    int i1 = process_intervention(task, transaction);
    msc_process_uri(transaction, (const char *)uri.data, (const char *)method.data, "1.1");
    int i2 = process_intervention(task, transaction);
    msc_process_request_headers(transaction);
    int i3 = process_intervention(task, transaction);
    msc_process_request_body(transaction);
    int i4 = process_intervention(task, transaction);
    msc_process_logging(transaction);
    msc_transaction_cleanup(transaction);

    if (i1 | i2 | i3 | i4)
    {
        return enif_make_tuple2(
            env,
            enif_make_atom(env, "error"),
            task.logs);
    }
    else
    {
        return enif_make_tuple2(
            env,
            enif_make_atom(env, "ok"),
            task.logs);
    }
}

static ERL_NIF_TERM check_response(ErlNifEnv *env, ModSecurity *modsec, RulesSet *rules, ERL_NIF_TERM headers, ErlNifBinary body)
{
    Transaction *transaction = NULL;
    ERL_NIF_TERM head;
    ERL_NIF_TERM *tuple;
    ErlNifBinary header_name, header_value;
    int tuple_arity = 2;

    // task_t *task = alloc_task();
    task_t task;
    task.env = env;
    task.logs = enif_make_list(env, 0);

    transaction = msc_new_transaction(modsec, rules, &task);
    while (enif_get_list_cell(env, headers, &head, (ERL_NIF_TERM *)&headers))
    {
        if (!enif_get_tuple(env, head, &tuple_arity, (const ERL_NIF_TERM **)&tuple) ||
            !enif_inspect_binary(env, tuple[0], &header_name) ||
            !enif_inspect_binary(env, tuple[1], &header_value))
        {
            return enif_make_tuple2(
                env,
                enif_make_atom(env, "error"),
                enif_make_string(env, "invalid response headers", ERL_NIF_LATIN1));
        }

        msc_add_n_response_header(transaction,
                                  (const unsigned char *)header_name.data, header_name.size,
                                  (const unsigned char *)header_value.data, header_value.size);
    }
    msc_append_response_body(transaction, (unsigned char *)body.data, body.size);
    msc_process_response_headers(transaction, 200, "HTTP 2.0");
    int i1 = process_intervention(task, transaction);
    msc_process_response_body(transaction);
    int i2 = process_intervention(task, transaction);
    msc_process_logging(transaction);
    msc_transaction_cleanup(transaction);

    if (i1 | i2)
    {
        return enif_make_tuple2(
            env,
            enif_make_atom(env, "error"),
            task.logs);
    }
    else
    {
        return enif_make_tuple2(
            env,
            enif_make_atom(env, "ok"),
            task.logs);
    }
}

static ERL_NIF_TERM modsec_check_request(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 4)
        return enif_make_badarg(env);

    ErlNifBinary method, uri, body;
    enif_inspect_binary(env, argv[0], &method);
    enif_inspect_binary(env, argv[1], &uri);
    enif_inspect_binary(env, argv[3], &body);

    return check_request(env, modsec, rules, method, uri, argv[2], body);
}

static ERL_NIF_TERM modsec_check_response(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 2)
        return enif_make_badarg(env);

    ErlNifBinary body;
    enif_inspect_binary(env, argv[1], &body);

    return check_response(env, modsec, rules, argv[0], body);
}

static ERL_NIF_TERM modsec_load_conf_files(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{

    const char *modsec_error = NULL;
    ERL_NIF_TERM head;

    if (argc != 1)
        return enif_make_badarg(env);


    ERL_NIF_TERM list = argv[0];
    while (enif_get_list_cell(env, list, &head, (ERL_NIF_TERM *)&list))
    {
        ErlNifBinary conf_file;
        if (!enif_inspect_binary(env, head, &conf_file))
        {
            return enif_make_badarg(env);
        }
        msc_rules_add_file(rules, (const char *)conf_file.data, &modsec_error);
        fprintf(stdout, "loading file %s\n", conf_file.data);
    }
    if (modsec_error != NULL)
    {
        fprintf(stderr, "init error %s\n", modsec_error);
    }

    return enif_make_atom(env, "ok");
}

static ErlNifFunc modsec_nif_funcs[] = {
        {"check_request", 4, modsec_check_request, ERL_NIF_DIRTY_JOB_CPU_BOUND},
        {"check_response", 2, modsec_check_response, ERL_NIF_DIRTY_JOB_CPU_BOUND},
        {"load_conf_files", 1, modsec_load_conf_files},
};

static void on_unload(ErlNifEnv *env, void *priv_data)
{
    msc_rules_cleanup(rules);
    msc_cleanup(modsec);
    return;
}

static int on_load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info)
{
    modsec = msc_init();
    rules = msc_create_rules_set();
    msc_set_log_cb(modsec, msc_logdata);

    return 0;
}

ERL_NIF_INIT(modsec_nif, modsec_nif_funcs, &on_load, NULL, NULL, &on_unload);