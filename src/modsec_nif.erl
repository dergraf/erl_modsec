-module(modsec_nif).
-export([init/0, check/6, create_ctx/1]).

-on_load(init/0).

init() ->
    Dir =
        case code:priv_dir(bcrypt) of
            {error, bad_name} ->
                case code:which(modsec) of
                    Filename when is_list(Filename) ->
                        filename:join(
                            [filename:dirname(Filename), "../priv"]
                        );
                    _ ->
                        "../priv"
                end;
            Priv ->
                Priv
        end,
    erlang:load_nif(filename:join(Dir, "erl_modsec"), 0).

create_ctx(_ConfFiles) ->
    erlang:nif_error({nif_not_loaded, module, ?MODULE, line, ?LINE}).

check(_Ctx, _Ref, _Pid, _RequestUri, _RequestHeaders, _RequestBody) ->
    erlang:nif_error({nif_not_loaded, module, ?MODULE, line, ?LINE}).
