-module(modsec_nif_worker).
-behaviour(gen_server).

-export([start_link/0]).
-export([check_request/4, check_response/2]).

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

check_request(RequestMethod, RequestUri, RequestHeaders, RequestBody) ->
    gen_server:call(
        ?MODULE, {check_request, RequestMethod, RequestUri, RequestHeaders, RequestBody}, infinity
    ).

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

-ifdef(TEST).

-include_lib("eunit/include/eunit.hrl").

check_request_test() ->
    modsec_nif_worker:start_link(),
    ?assertMatch(
        {ok, []},
        modsec_nif_worker:check_request(
            <<"POST">>,
            <<"/foo/bar">>,
            [
                {<<"Content-Type">>, <<"text/plain">>},
                {<<"Content-Length">>, <<"6">>},
                {<<"Host">>, <<"localhost">>},
                {<<"foo">>, <<"bar">>}
            ],
            <<"foobar">>
        )
    ),
    ?assertMatch(
        {error, [_ | _]},
        modsec_nif_worker:check_request(
            <<"POST">>,
            <<"/test/artists.php?artist=0+div+1+union%23foo*%2F*bar%0D%0Aselect%23foo%0D%0A1%2C2%2Ccurrent_user">>,
            [
                {<<"Content-Type">>, <<"text/plain">>},
                {<<"Content-Length">>, <<"5">>},
                {<<"Host">>, <<"localhost">>}
            ],
            <<"hello">>
        )
    ),
    Json =
        <<"{\"hello\":\"artist=0+div+1+union%23foo*%2F*bar%0D%0Aselect%23foo%0D%0A1%2C2%2Ccurrent_user\"}">>,
    ?assertMatch(
        {error, [_ | _]},
        modsec_nif_worker:check_request(
            <<"POST">>,
            <<"/foo/bar">>,
            [
                {
                    <<"Content-Type">>, <<"application/json">>
                },
                {<<"Content-Length">>, integer_to_binary(byte_size(Json))},
                {<<"Host">>, <<"localhost">>}
            ],
            Json
        )
    ).

check_response_test() ->
    modsec_nif_worker:start_link(),
    ?assertMatch(
        {ok, []},
        modsec_nif_worker:check_response([{<<"foo">>, <<"bar">>}], <<"foobar">>)
    ),
    ?assertMatch(
        {ok, []},
        modsec_nif_worker:check_response(
            [{<<"Content-Type">>, <<"application/json">>}],
            <<"{\"foo\":\"artist=0+div+1+union%23foo*%2F*bar%0D%0Aselect%23foo%0D%0A1%2C2%2Ccurrent_user\"}">>
        )
    ).

-endif.
