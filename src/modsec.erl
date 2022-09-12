-module(modsec).

-export([process/0, process_bad/0, process_bad_2/0, process/3]).

process() ->
    process(
        <<"/test/uri">>, [{<<"Content-Type">>, <<"application/json">>}], <<"{\"hello\":\"world\"}">>
    ).

process_bad() ->
    process(
        <<"/test/uri">>,
        [{<<"Content-Type">>, <<"application/json">>}],
        <<"{\"hello\":\"artist=0+div+1+union%23foo*%2F*bar%0D%0Aselect%23foo%0D%0A1%2C2%2Ccurrent_user\"}">>
    ).
process_bad_2() ->
    process(
        <<"/test/uri">>,
        [
            {<<"Content-Type">>, <<"application/json">>},
            {<<"Some-Header">>,
                <<"{\"hello\":\"artist=0+div+1+union%23foo*%2F*bar%0D%0Aselect%23foo%0D%0A1%2C2%2Ccurrent_user\"}">>}
        ],
        <<"{\"hello\":\"world\"}">>
    ).

process(Uri, Headers, Body) ->
    modsec_nif_worker:start_link(),
    modsec_nif_worker:check(Uri, Headers, Body).
