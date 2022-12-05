-module(modsec_nif_worker_tests).

-include_lib("eunit/include/eunit.hrl").

check_test_() ->
    [
        fun check_request/0,
        fun check_response/0,
        {timeout, 600, [
            fun check_parallel/0
        ]}
    ].

check_request() ->
    modsec_nif_worker:start_link(<<"./test/**/*.conf">>),
    ?assertMatch(
        {ok, []},
        modsec_nif_worker:check_request(
            <<"POST">>,
            <<"/foo/bar">>,
            [
                {<<"Content-Type">>, <<"application/json">>},
                {<<"Content-Length">>, <<"10">>},
                {<<"Host">>, <<"localhost">>},
                {<<"foo">>, <<"bar">>}
            ],
            <<"\"foobar\"">>
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

check_response() ->
    modsec_nif_worker:start_link(<<"./test/**/*.conf">>),
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

check_parallel() ->
    modsec_nif_worker:start_link(<<"./test/**/*.conf">>),
    Json =
        <<"{\"hello\":\"artist=0+div+1+union%23foo*%2F*bar%0D%0Aselect%23foo%0D%0A1%2C2%2Ccurrent_user\"}">>,
    fprof:start(),
    fprof:apply(
        fun() ->
            times(
                fun() ->
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
                end,
                1000
            )
        end,
        []
    ),
    fprof:profile(),
    fprof:analyse(),
    true.

times(Function, N) ->
    Self = self(),
    Procs = lists:foldl(
        fun(I, Acc) ->
            Pid = spawn(fun() ->
                Self ! {I, apply(Function, [])}
            end),
            maps:put(I, Pid, Acc)
        end,
        maps:new(),
        lists:seq(1, N)
    ),
    receive_results(Procs).

receive_results(Procs) when map_size(Procs) > 0 ->
    receive
        {I, _} ->
            receive_results(maps:remove(I, Procs))
    end;
receive_results(_) ->
    ok.
