-module(ssh_nc_tunnel).

-export([local/6, stop/1]).

-record(tunnel, {connection, ref, type, channels = [], parent}).

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
            LocalAddress =
                case inet:parse_address(LocalIp) of
                    {ok, Addr} -> Addr;
                    _ -> {127, 0, 0, 1}
                end,

            {ok, Listener} = gen_tcp:listen(LocalPort, [
                {ip, LocalAddress},
                binary,
                {active, false},
                {reuseaddr, true}
            ]),

            Tunnel = #tunnel{
                connection = Connection,
                ref = Listener,
                type = local,
                parent = self()
            },
            accept_loop(Tunnel, RemoteIp, RemotePort);
        Error ->
            ?dbg("ERROR ~p~n",[Error]),
            {error, {ssh_connect_failed, Error}}
    catch
        _:Error ->
            ?dbg("CRASH ~p~n",[Error]),
            {error, {ssh_connect_failed, Error}}
    end.


parse_ssh_host(SshHost) ->
    case string:tokens(SshHost, ":") of
        [Host, PortStr] ->
            {Host, list_to_integer(PortStr)};
        [Host] ->
            {Host, 22}
    end.

accept_loop(
    Tunnel = #tunnel{connection = Connection, ref = Listener},
    RemoteIp,
    RemotePort
) ->
    AcceptLoop = self(),
    AcceptPid =
        spawn(fun() ->
                      case gen_tcp:accept(Listener) of
                          {ok, Client} ->
                              AcceptLoop ! {self(), {accepted,Client}},
                              ?dbg("INFO ~p Got Client~n",[self()]),
                              handle_client_connection(
                                Connection,
                                Client,
                                RemoteIp,
                                RemotePort,
                                Tunnel#tunnel.parent);
                          Error ->
                              AcceptLoop ! {self(), {accept_failed, Error}}
                      end
              end),
    receive
        {AcceptPid, _Msg} ->
            ?dbg("INFO AcceptLoop got: ~p~n",[_Msg]),
            accept_loop(Tunnel, RemoteIp, RemotePort)
    end.




handle_client_connection(Connection, Client, RemoteIp, RemotePort, Parent) ->
    % Open a session channel to the SSH server
    case ssh_connection:session_channel(Connection, infinity) of
        {ok, ChannelId} ->
            ?dbg("INFO New ChannelId = ~p~n",[ChannelId]),
            % Execute a command to connect to the desired service
            % Using netcat (nc) to connect to the target host:port
            ConnectCmd = io_lib:format(
                "nc ~s ~b",
                [RemoteIp, RemotePort]
            ),

            %%spawn(fun() -> do_forward_local_data(Connection, ChannelId, Client) end),

            case
                ssh_connection:exec(Connection, ChannelId, ConnectCmd, infinity)
            of
                success ->
                    ?dbg("INFO Executed Netcat~n",[]),
                    % Register this channel with parent for cleanup
                    Parent ! {register_channel, self(), ChannelId},
                    forward_local_data(Connection, ChannelId, Client);
                Error ->
                    ?dbg("INFO exec failed, Error=~p~n",[Error]),
                    gen_tcp:close(Client),
                    {error, {exec_failed, Error}}
            end;
        Error ->
            gen_tcp:close(Client),
            {error, {channel_open_failed, Error}}
    end.

%do_forward_local_data(Connection, ChannelId, Socket) ->
%    timer:sleep(2000),
%    forward_local_data(Connection, ChannelId, Socket).

forward_local_data(Connection, ChannelId, Socket) ->
    inet:setopts(Socket, [{active, once}]),
    receive
        {tcp, Socket, Data} ->
            %%?dbg("INFO Got TCP Data = ~p~n",[Data]),
            ssh_connection:send(Connection, ChannelId, Data),
            forward_local_data(Connection, ChannelId, Socket);
        {tcp_closed, Socket} ->
            ssh_connection:close(Connection, ChannelId);
        {tcp_error, Socket, _} ->
            ssh_connection:close(Connection, ChannelId);
        {ssh_cm, Connection, {data, ChannelId, 0, Data}} ->
            gen_tcp:send(Socket, Data),
            forward_local_data(Connection, ChannelId, Socket);
        {ssh_cm, Connection, {data, ChannelId, 1, Data}} ->
            % Handle stderr data if needed
            error_logger:info_msg("SSH stderr: ~p", [Data]),
            forward_local_data(Connection, ChannelId, Socket);
        {ssh_cm, Connection, {eof, ChannelId}} ->
            % SSH channel received EOF
            forward_local_data(Connection, ChannelId, Socket);
        {ssh_cm, Connection, {exit_status, ChannelId, _Status}} ->
            % Remote process exited
            gen_tcp:close(Socket);
        {ssh_cm, Connection, {closed, ChannelId}} ->
            gen_tcp:close(Socket);
        {From, stop} ->
            ssh_connection:close(Connection, ChannelId),
            gen_tcp:close(Socket),
            From ! ok;
        _Msg ->
            ?dbg("INFO Unexpected TCP msg = ~p~n",[_Msg]),
            forward_local_data(Connection, ChannelId, Socket)
    end.
