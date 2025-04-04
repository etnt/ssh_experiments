-module(ssh_tcpip_tunnel).

-export([local/6, stop/1]).


%%-define(dbg(FmtStr,Args), ok).
-define(dbg(FmtStr,Args), io:format("~p(~p): "++FmtStr,[?MODULE,?LINE|Args])).

%% Start local port forwarding tunnel (e.g. local:8080 -> remote:80)
local(LocalIp, LocalPort, RemoteIp, RemotePort, SshHost, Options) when
    is_list(LocalIp),
    is_integer(LocalPort),
    is_list(RemoteIp),
    is_integer(RemotePort),
    is_list(SshHost),
    is_list(Options)
->
    assert_ip_address(local_ip, LocalIp),
    assert_ip_address(remote_ip, RemoteIp),

    ssh_exec:start_deps(),

    SshOptions = prepare_ssh_options(Options),

    % Start tunnel in a separate process
    {ok,
        spawn(fun() ->
            start_local_tunnel(
                LocalIp, LocalPort, RemoteIp, RemotePort, SshHost, SshOptions
            )
        end)}.

assert_ip_address(What, IpStr) when is_list(IpStr) ->
    case inet:parse_address(IpStr) of
        {ok, _Ip} -> ok;
        _ -> throw({error, {What, IpStr}})
    end.



%% Stop a running tunnel
stop(Tunnel) when is_pid(Tunnel) ->
    Tunnel ! {self(), stop},
    receive
        Msg ->
            Msg
    after 5000 ->
        error
    end.

%% Internal functions

prepare_ssh_options(Options) ->
    User = proplists:get_value(user, Options),

    BaseOptions =
        [
         {silently_accept_hosts, true},
         {user, User},
         %%{connectfun, fun on_connect/3},
         {ssh_msg_debug_fun, fun debug_fun/4},
         {disconnectfun, fun on_disconnect/1}
        ],

    case proplists:get_value(user_dir, Options) of
        undefined ->
            BaseOptions;
        Path ->
            [{user_dir, filename:dirname(Path)} | BaseOptions]
    end.


debug_fun(_ConnRef, _AlwaysDisplay, _Msg, _LanguageTag) ->
    ?dbg("INFO debug_fun Msg=~p~n",[_Msg]),
    ok.


%%on_connect(Username, B, C) ->
%%  ?dbg("~p on_connect: ~p ~p ~p\n",[self(), Username,B,C]),
%%  ok.

on_disconnect(_A) ->
  ?dbg("INFO ~p on_disconnect: ~p\n",[self(), _A]),
  ok.

start_local_tunnel(LocalIp, LocalPort, RemoteIp, RemotePort, SshHost, SshOptions) ->
    ?dbg("INFO SshOptions = ~p~n",[SshOptions]),

    {Host, Port} = parse_ssh_host(SshHost),
    ?dbg("INFO Host=~p , Port=~p~n",[Host,Port]),

    try ssh:connect(Host, Port, SshOptions) of
        {ok, Connection} ->
            ?dbg("INFO Connection = ~p~n",[Connection]),
            case ssh:tcpip_tunnel_to_server(Connection,
                                            LocalIp, LocalPort,
                                            RemoteIp, RemotePort,
                                            _Timeout = infinity)
            of
                {ok, _ListenPort} ->
                    wait_loop(Connection);
                Else ->
                    ?dbg("ERROR ~p~n",[Else]),
                    {error, Else}
            end;
        Error ->
            ?dbg("ERROR ~p~n",[Error]),
            {error, {ssh_connect_failed, Error}}
    catch
        _:Error ->
            ?dbg("CRASH ~p~n",[Error]),
            {error, {ssh_connect_failed, Error}}
    end.


wait_loop(Connection) ->
    receive
        {From, stop} ->
            ssh:close(Connection),
            From ! ok;
        _Msg ->
            ?dbg("INFO Unexpected TCP msg = ~p~n",[_Msg]),
            wait_loop(Connection)
    end.



parse_ssh_host(SshHost) ->
    case string:tokens(SshHost, ":") of
        [Host, PortStr] ->
            {Host, list_to_integer(PortStr)};
        [Host] ->
            {Host, 22}
    end.
