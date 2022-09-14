-module(modsec_nif_worker).
-behaviour(gen_server).

-export([start_link/0]).
-export([check_request/3, check_response/2]).

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

check_request(RequestUri, RequestHeaders, RequestBody) ->
    gen_server:call(?MODULE, {check_request, RequestUri, RequestHeaders, RequestBody}, infinity).

check_response(RequestHeaders, RequestBody) ->
    gen_server:call(?MODULE, {check_response, RequestHeaders, RequestBody}, infinity).

init([]) ->
    ConfDirectoryPattern = "priv/modsec_conf/**/*.conf",
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

handle_call(
    {check_request, RequestUri, RequestHeaders, RequestBody}, _From, #state{context = Ctx} = State
) ->
    Ref = make_ref(),
    ok = modsec_nif:check_request(Ctx, Ref, self(), RequestUri, RequestHeaders, RequestBody),
    receive
        {ok, Ref} ->
            {reply, ok, State};
        {error, Ref} ->
            {reply, error, State}
    end;
handle_call({check_response, ResponseHeaders, ResponseBody}, _From, #state{context = Ctx} = State) ->
    Ref = make_ref(),
    ok = modsec_nif:check_response(Ctx, Ref, self(), ResponseHeaders, ResponseBody),
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

-ifdef(TEST).

-include_lib("eunit/include/eunit.hrl").

check_request_test() ->
    modsec_nif_worker:start_link(),
    ?assert(
        ok ==
            modsec_nif_worker:check_request(<<"/foo/bar">>, [{<<"foo">>, <<"bar">>}], <<"foobar">>)
    ),
    ?assert(
        ok ==
            modsec_nif_worker:check_request(
                <<"/test/artists.php?artist=0+div+1+union%23foo*%2F*bar%0D%0Aselect%23foo%0D%0A1%2C2%2Ccurrent_user">>,
                [],
                <<"hello">>
            )
    ),
    ?assert(
        ok ==
            modsec_nif_worker:check_request(
                <<"/foo/bar">>,
                [{<<"Content-Type">>, <<"application/json">>}],
                <<"{\"hello\":\"artist=0+div+1+union%23foo*%2F*bar%0D%0Aselect%23foo%0D%0A1%2C2%2Ccurrent_user\"}">>
            )
    ).

check_response_test() ->
    modsec_nif_worker:start_link(),
    ?assert(
        ok ==
            modsec_nif_worker:check_response([{<<"foo">>, <<"bar">>}], <<"foobar">>)
    ).

%% Insert tests here.

-endif.
