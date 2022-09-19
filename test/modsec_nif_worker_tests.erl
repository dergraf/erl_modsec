-module(modsec_nif_worker_tests).

-include_lib("eunit/include/eunit.hrl").

check_request_test() ->
    modsec_nif_worker:start_link(<<"./test/*.conf">>),
    ?assertMatch(
        {error, [_ | _]},
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
    modsec_nif_worker:start_link(<<"./test/*.conf">>),
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
