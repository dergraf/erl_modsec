-module(modsec_nif_worker).
-behaviour(gen_server).

-export([start_link/1]).
-export([check_request/4, check_request/5, check_response/2, check_response/3]).

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

start_link(ConfDirectoryPattern) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [ConfDirectoryPattern], []).

check_request(RequestMethod, RequestUri, RequestHeaders, RequestBody) ->
    check_request(?MODULE, RequestMethod, RequestUri, RequestHeaders, RequestBody).

check_request(NameOrPid, RequestMethod, RequestUri, RequestHeaders, RequestBody) ->
    %% RequestMethod and RequestUri must be 0 terminated
    gen_server:call(
        NameOrPid,
        {check_request, <<RequestMethod/binary, 0>>, <<RequestUri/binary, 0>>, RequestHeaders,
            RequestBody},
        infinity
    ).

check_response(ResponseHeaders, ResponseBody) ->
    check_response(?MODULE, ResponseHeaders, ResponseBody).

check_response(NameOrPid, ResponseHeaders, ResponseBody) ->
    gen_server:call(
        NameOrPid, {check_response, ResponseHeaders, ResponseBody}, infinity
    ).

init([ConfDirectoryPattern]) ->
    ConfFiles = lists:filtermap(
        fun(F) ->
            case filelib:is_regular(F) of
                true ->
                    Filename = erlang:list_to_binary(F),
                    {true, <<Filename/binary, 0>>};
                false ->
                    false
            end
        end,
        filelib:wildcard(binary_to_list(ConfDirectoryPattern))
    ),
    Ctx = modsec_nif:create_ctx(ConfFiles),
    {ok, #state{context = Ctx}}.

terminate(shutdown, _) -> ok.

handle_call(
    {check_request, RequestMethod, RequestUri, RequestHeaders, RequestBody},
    _From,
    #state{context = Ctx} = State
) ->
    Ref = make_ref(),
    ok = modsec_nif:check_request(
        Ctx, Ref, self(), RequestMethod, RequestUri, RequestHeaders, RequestBody
    ),
    receive
        {ok, Ref, Logs} ->
            {reply, {ok, Logs}, State};
        {error, Ref, Logs} ->
            {reply, {error, Logs}, State}
    end;
handle_call({check_response, ResponseHeaders, ResponseBody}, _From, #state{context = Ctx} = State) ->
    Ref = make_ref(),
    ok = modsec_nif:check_response(Ctx, Ref, self(), ResponseHeaders, ResponseBody),
    receive
        {ok, Ref, Logs} ->
            {reply, {ok, Logs}, State};
        {error, Ref, Logs} ->
            {reply, {error, Logs}, State}
    end;
handle_call(Msg, _, _) ->
    exit({unknown_call, Msg}).
handle_cast(Msg, _) -> exit({unknown_cast, Msg}).
handle_info(Msg, _) -> exit({unknown_info, Msg}).
code_change(_OldVsn, State, _Extra) -> {ok, State}.
