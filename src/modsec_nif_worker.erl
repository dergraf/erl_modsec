-module(modsec_nif_worker).
-behaviour(gen_server).

-export([start_link/0]).
-export([check/3]).

%% gen_server
-export([
    init/1,
    code_change/3,
    terminate/2,
    handle_call/3,
    handle_cast/2,
    handle_info/2
]).

-record(state, {
    context
}).

start_link() -> gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

check(RequestUri, RequestHeaders, RequestBody) ->
    gen_server:call(?MODULE, {check, RequestUri, RequestHeaders, RequestBody}, infinity).

init([]) ->
    ConfDirectoryPattern = "priv/modsec_conf/**",
    ConfFiles = lists:filtermap(
        fun(F) ->
            case filelib:is_regular(F) of
                true ->
                    {true, erlang:list_to_binary(F)};
                false ->
                    false
            end
        end,
        filelib:wildcard(ConfDirectoryPattern)
    ),
    Ctx = modsec_nif:create_ctx(ConfFiles),
    {ok, #state{context = Ctx}}.

terminate(shutdown, _) -> ok.

handle_call({check, RequestUri, RequestHeaders, RequestBody}, _From, #state{context = Ctx} = State) ->
    Ref = make_ref(),
    ok = modsec_nif:check(Ctx, Ref, self(), RequestUri, RequestHeaders, RequestBody),
    receive
        {ok, Ref} ->
            {reply, ok, State};
        {error, Ref} ->
            {reply, error, State}
    end;
handle_call(Msg, _, _) ->
    exit({unknown_call, Msg}).
handle_cast(Msg, _) -> exit({unknown_cast, Msg}).
handle_info(Msg, _) -> exit({unknown_info, Msg}).
code_change(_OldVsn, State, _Extra) -> {ok, State}.
