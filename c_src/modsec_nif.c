#include "modsecurity/rules_set.h"
#include "modsecurity/modsecurity.h"
#include "modsecurity/transaction.h"
#include "modsecurity/intervention.h"
#include <assert.h>
#include <erl_nif.h>
#include "modsec_nif.h"

// to supress no previous prototype warnings
void free_task(task_t *);
task_t *alloc_task(task_type_t);
task_t *alloc_init_task(task_type_t, ModSecurity *, RulesSet *, int, const ERL_NIF_TERM[]);
void msc_logdata(void *, const void *);
ERL_NIF_TERM run_task(task_t *task);

void free_task(task_t *task)
{
    if (task->env != NULL)
        enif_free_env(task->env);
    enif_free(task);
}

task_t *alloc_task(task_type_t type)
{
    task_t *task = (task_t *)enif_alloc(sizeof(task_t));
    if (task == NULL)
        return NULL;
    (void)memset(task, 0, sizeof(task_t));
    task->type = type;
    return task;
}

task_t *alloc_init_task(task_type_t type, ModSecurity *modsec, RulesSet *rules, int num_orig_terms, const ERL_NIF_TERM orig_terms[])
{
    task_t *task = alloc_task(type);
    task->env = enif_alloc_env();
    task->modsec = modsec;
    task->rules = rules;
    task->logs = enif_make_list(task->env, 0);
    if (task->env == NULL)
    {
        free_task(task);
        return NULL;
    }

    if (type == MODSEC_CHECK_REQUEST)
    {
        assert(num_orig_terms == 4);
        task->data.d.headers = enif_make_copy(task->env, orig_terms[2]);
        if (
            !enif_inspect_binary(task->env, enif_make_copy(task->env, orig_terms[0]), &task->data.d.method) ||
            !enif_inspect_binary(task->env, enif_make_copy(task->env, orig_terms[1]), &task->data.d.uri) ||
            !enif_inspect_binary(task->env, enif_make_copy(task->env, orig_terms[3]), &task->data.d.body))
        {
            free_task(task);
            return NULL;
        }
    }
    else if (type == MODSEC_CHECK_RESPONSE)
    {

        assert(num_orig_terms == 2);
        task->data.d.headers = enif_make_copy(task->env, orig_terms[0]);
        if (
            !enif_inspect_binary(task->env, enif_make_copy(task->env, orig_terms[1]), &task->data.d.body))
        {
            free_task(task);
            return NULL;
        }
    }

    return task;
}

void msc_logdata(void *cb_data, const void *data)
{
    task_t *task = (task_t *)cb_data;
    size_t len = strlen((const char *)data); // to make sure that trailing NULL (aka \0) is also copied
    ErlNifBinary bin;
    enif_alloc_binary(len, &bin);
    memcpy(bin.data, data, len);
    ERL_NIF_TERM log_binary = enif_make_binary(task->env, &bin);
    task->logs = enif_make_list_cell(task->env, log_binary, task->logs);
    return;
}

static int process_intervention(task_t *task, Transaction *transaction, char *log_str)
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

    if (intervention.log == NULL)
    {
        msc_logdata((void *)task, "(no log message was specified)");
    }
    else
    {
        msc_logdata((void *)task, intervention.log);
        // FIXME This may cause segfault or even worse memory corruptions
        // since intervention.log allocation didn't happen in this scope!
        free(intervention.log);
    }

    return 1;
}

static ERL_NIF_TERM check_request(task_t *task)
{
    Transaction *transaction = NULL;
    ERL_NIF_TERM head;
    ERL_NIF_TERM *tuple;
    ErlNifBinary header_name, header_value;
    int tuple_arity = 2;

    transaction = msc_new_transaction(task->modsec, task->rules, (void *)task);
    ERL_NIF_TERM list = task->data.d.headers;
    while (enif_get_list_cell(task->env, list, &head, (ERL_NIF_TERM *)&list))
    {
        if (!enif_get_tuple(task->env, head, &tuple_arity, (const ERL_NIF_TERM **)&tuple) ||
            !enif_inspect_binary(task->env, tuple[0], &header_name) ||
            !enif_inspect_binary(task->env, tuple[1], &header_value))
        {
            return enif_make_tuple3(
                task->env,
                enif_make_atom(task->env, "error"),
                task->ref,
                enif_make_string(task->env, "invalid request headers", ERL_NIF_LATIN1));
        }
        msc_add_n_request_header(transaction,
                                 (const unsigned char *)header_name.data, header_name.size,
                                 (const unsigned char *)header_value.data, header_value.size);
    }
    msc_append_request_body(transaction, (unsigned char *)task->data.d.body.data, task->data.d.body.size);
    msc_process_connection(transaction, "127.0.0.1", 80, "127.0.0.1", 80);
    int i1 = process_intervention(task, transaction, "process connection %i\n");
    msc_process_uri(transaction, (const char *)task->data.d.uri.data, (const char *)task->data.d.method.data, "1.1");
    int i2 = process_intervention(task, transaction, "process uri %i\n");
    msc_process_request_headers(transaction);
    int i3 = process_intervention(task, transaction, "process request headers %i\n");
    msc_process_request_body(transaction);
    int i4 = process_intervention(task, transaction, "process request body %i\n");
    msc_process_logging(transaction);
    msc_transaction_cleanup(transaction);

    if (i1 | i2 | i3 | i4)
    {
        return enif_make_tuple2(
            task->env,
            enif_make_atom(task->env, "error"),
            task->logs);
    }
    else
    {
        return enif_make_tuple2(
            task->env,
            enif_make_atom(task->env, "ok"),
            task->logs);
    }
}

static ERL_NIF_TERM check_response(task_t *task)
{
    Transaction *transaction = NULL;
    ERL_NIF_TERM head;
    ERL_NIF_TERM *tuple;
    ErlNifBinary header_name, header_value;
    int tuple_arity = 2;

    transaction = msc_new_transaction(task->modsec, task->rules, (void *)task);
    ERL_NIF_TERM list = task->data.d.headers;
    while (enif_get_list_cell(task->env, list, &head, (ERL_NIF_TERM *)&list))
    {
        if (!enif_get_tuple(task->env, head, &tuple_arity, (const ERL_NIF_TERM **)&tuple) ||
            !enif_inspect_binary(task->env, tuple[0], &header_name) ||
            !enif_inspect_binary(task->env, tuple[1], &header_value))
        {
            return enif_make_tuple3(
                task->env,
                enif_make_atom(task->env, "error"),
                task->ref,
                enif_make_string(task->env, "invalid response headers", ERL_NIF_LATIN1));
        }

        msc_add_n_response_header(transaction,
                                  (const unsigned char *)header_name.data, header_name.size,
                                  (const unsigned char *)header_value.data, header_value.size);
    }
    msc_append_response_body(transaction, (unsigned char *)task->data.d.body.data, task->data.d.body.size);
    msc_process_response_headers(transaction, 200, "HTTP 2.0");
    int i1 = process_intervention(task, transaction, "response headers %i\n");
    msc_process_response_body(transaction);
    int i2 = process_intervention(task, transaction, "response body %i\n");
    msc_process_logging(transaction);
    msc_transaction_cleanup(transaction);

    if (i1 | i2)
    {
        return enif_make_tuple2(
            task->env,
            enif_make_atom(task->env, "error"),
            task->logs);
    }
    else
    {
        return enif_make_tuple2(
            task->env,
            enif_make_atom(task->env, "ok"),
            task->logs);
    }
}

ERL_NIF_TERM run_task(task_t *task)
{
    if (task->type == MODSEC_CHECK_REQUEST)
    {

        return check_request(task);
    }
    else if (task->type == MODSEC_CHECK_RESPONSE)
    {
        return check_response(task);
    }
    return enif_make_atom(task->env, "unexpected_task_error");
}

static ERL_NIF_TERM modsec_check_request(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    ctx_t *ctx;
    task_t *task;

    if (argc != 5)
        return enif_make_badarg(env);

    modsec_privdata_t *priv = (modsec_privdata_t *)enif_priv_data(env);

    if (!enif_get_resource(env, argv[0], priv->modsec_rt, (void **)(&ctx)))
        return enif_make_badarg(env);

    ERL_NIF_TERM orig_terms[] = {argv[1], argv[2], argv[3], argv[4]};
    task = alloc_init_task(MODSEC_CHECK_REQUEST, ctx->modsec, ctx->rules, 4, orig_terms);

    if (!task)
        return enif_make_badarg(env);

    return run_task(task);
}

static ERL_NIF_TERM modsec_check_response(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    ctx_t *ctx;
    task_t *task;

    if (argc != 3)
        return enif_make_badarg(env);

    modsec_privdata_t *priv = (modsec_privdata_t *)enif_priv_data(env);

    if (!enif_get_resource(env, argv[0], priv->modsec_rt, (void **)(&ctx)))
        return enif_make_badarg(env);

    ERL_NIF_TERM orig_terms[] = {argv[1], argv[2]};
    task = alloc_init_task(MODSEC_CHECK_RESPONSE, ctx->modsec, ctx->rules, 2, orig_terms);

    if (!task)
        return enif_make_badarg(env);

    return run_task(task);
}

static ERL_NIF_TERM modsec_create_ctx(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{

    const char *modsec_error = NULL;
    ERL_NIF_TERM ret, head;

    if (argc != 1)
        return enif_make_badarg(env);

    modsec_privdata_t *priv = (modsec_privdata_t *)enif_priv_data(env);
    ctx_t *ctx = (ctx_t *)enif_alloc_resource(priv->modsec_rt, sizeof(ctx_t));
    if (ctx == NULL)
        return enif_make_badarg(env);

    enif_get_int(env, argv[1], &ctx->nr_of_threads);
    ctx->modsec = msc_init();
    ctx->rules = msc_create_rules_set();
    msc_set_log_cb(ctx->modsec, msc_logdata);
    ERL_NIF_TERM list = argv[0];
    while (enif_get_list_cell(env, list, &head, (ERL_NIF_TERM *)&list))
    {
        ErlNifBinary conf_file;
        if (!enif_inspect_binary(env, head, &conf_file))
        {
            return enif_make_badarg(env);
        }
        msc_rules_add_file(ctx->rules, (const char *)conf_file.data, &modsec_error);
        fprintf(stdout, "loading file %s\n", conf_file.data);
    }
    if (modsec_error != NULL)
    {
        fprintf(stderr, "init error %s\n", modsec_error);
    }

    ret = enif_make_resource(env, ctx);
    enif_release_resource(ctx);
    return ret;
}

static ErlNifFunc modsec_nif_funcs[] =
    {
        {"check_request", 5, modsec_check_request, ERL_NIF_DIRTY_JOB_CPU_BOUND},
        {"check_response", 3, modsec_check_response, ERL_NIF_DIRTY_JOB_CPU_BOUND},
        {"create_ctx", 1, modsec_create_ctx},
};

static void modsec_rt_dtor(ErlNifEnv *env, void *obj)
{
    return;
}

static int on_load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info)
{
    const char *mod = "modsec_nif";
    const char *name = "nif_resource";

    ErlNifResourceFlags flags = (ErlNifResourceFlags)(ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER);

    modsec_privdata_t *priv = (modsec_privdata_t *)enif_alloc(sizeof(modsec_privdata_t));
    priv->modsec_rt = enif_open_resource_type(env, mod, name, modsec_rt_dtor, flags, NULL);
    if (priv->modsec_rt == NULL)
        return -1;
    *priv_data = priv;
    return 0;
}

ERL_NIF_INIT(modsec_nif, modsec_nif_funcs, &on_load, NULL, NULL, NULL);