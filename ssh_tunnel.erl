-module(ssh_tunnel).

-export([local/6, remote/6, stop/1, socks/3]).

-record(tunnel, {connection, ref, type, channels = [], parent}).

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

%% Start remote port forwarding tunnel (e.g. remote:8080 -> local:80)
remote(LocalIp, LocalPort, RemoteIp, RemotePort, SshHost, Options) when
    is_list(LocalIp),
    is_integer(LocalPort),
    is_list(RemoteIp),
    is_integer(RemotePort),
    is_list(SshHost),
    is_list(Options)
->
    assert_ip_address(local_ip, LocalIp),
    assert_ip_address(remote_ip, RemoteIp),

    SshOptions = prepare_ssh_options(Options),

    % Start tunnel in a separate process
    {ok,
        spawn(fun() ->
            start_remote_tunnel(
                LocalIp, LocalPort, RemoteIp, RemotePort, SshHost, SshOptions
            )
        end)}.

%% Start a SOCKS proxy server
socks(LocalPort, SshHost, Options) when
    is_integer(LocalPort),
    is_list(SshHost),
    is_list(Options)
->
    SshOptions = prepare_ssh_options(Options),

    % Start SOCKS proxy in a separate process
    {ok,
        spawn(fun() ->
            start_socks_proxy(LocalPort, SshHost, SshOptions)
        end)}.

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

    BaseOptions = [
        {silently_accept_hosts, true},
        {user, User}
    ],

    case proplists:get_value(user_dir, Options) of
        undefined ->
            BaseOptions;
        Path ->
            [{user_dir, filename:dirname(Path)} | BaseOptions]
    end.

start_local_tunnel(
    LocalIp, LocalPort, RemoteIp, RemotePort, SshHost, SshOptions
) ->
    {Host, Port} = parse_ssh_host(SshHost),

    case ssh:connect(Host, Port, SshOptions) of
        {ok, Connection} ->
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
            {error, {ssh_connect_failed, Error}}
    end.

start_remote_tunnel(
    LocalIp, LocalPort, RemoteIp, RemotePort, SshHost, SshOptions
) ->
    {Host, Port} = parse_ssh_host(SshHost),

    case ssh:connect(Host, Port, SshOptions) of
        {ok, Connection} ->
            % Use a session channel and execute a netcat command to listen on remote port
            {ok, ChannelId} = ssh_connection:session_channel(
                Connection, infinity
            ),
            RemoteCmd = io_lib:format(
                "nc -l ~s ~b",
                [RemoteIp, RemotePort]
            ),

            ok = ssh_connection:exec(
                Connection, ChannelId, RemoteCmd, infinity
            ),

            Tunnel = #tunnel{
                connection = Connection,
                ref = {socket, ChannelId},
                type = remote,
                parent = self()
            },

            % Connect to local service that we want to forward
            case
                gen_tcp:connect(LocalIp, LocalPort, [binary, {active, once}])
            of
                {ok, Socket} ->
                    forward_remote_data(Tunnel, Socket);
                Error ->
                    ssh_connection:close(Connection, ChannelId),
                    ssh:close(Connection),
                    {error, {local_connect_failed, Error}}
            end;
        Error ->
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
    case gen_tcp:accept(Listener) of
        {ok, Client} ->
            ChannelPid = spawn(fun() ->
                handle_client_connection(
                    Connection,
                    Client,
                    RemoteIp,
                    RemotePort,
                    Tunnel#tunnel.parent
                )
            end),
            NewTunnel = Tunnel#tunnel{
                channels = [ChannelPid | Tunnel#tunnel.channels]
            },
            accept_loop(NewTunnel, RemoteIp, RemotePort);
        Error ->
            {error, {accept_failed, Error}}
    end.

handle_client_connection(Connection, Client, RemoteIp, RemotePort, Parent) ->
    % Open a session channel to the SSH server
    case ssh_connection:session_channel(Connection, infinity) of
        {ok, ChannelId} ->
            % Execute a command to connect to the desired service
            % Using netcat (nc) to connect to the target host:port
            ConnectCmd = io_lib:format(
                "nc ~s ~b",
                [RemoteIp, RemotePort]
            ),

            case
                ssh_connection:exec(Connection, ChannelId, ConnectCmd, infinity)
            of
                ok ->
                    % Register this channel with parent for cleanup
                    Parent ! {register_channel, self(), ChannelId},
                    forward_local_data(Connection, ChannelId, Client);
                Error ->
                    gen_tcp:close(Client),
                    {error, {exec_failed, Error}}
            end;
        Error ->
            gen_tcp:close(Client),
            {error, {channel_open_failed, Error}}
    end.

forward_local_data(Connection, ChannelId, Socket) ->
    inet:setopts(Socket, [{active, once}]),
    receive
        {tcp, Socket, Data} ->
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
            From ! ok
    end.

forward_remote_data(Tunnel = #tunnel{connection = Connection}, Socket) ->
    ChannelId = element(2, Tunnel#tunnel.ref),
    receive
        {tcp, Socket, Data} ->
            inet:setopts(Socket, [{active, once}]),
            ssh_connection:send(Connection, ChannelId, Data),
            forward_remote_data(Tunnel, Socket);
        {tcp_closed, Socket} ->
            ssh_connection:close(Connection, ChannelId);
        {tcp_error, Socket, _} ->
            ssh_connection:close(Connection, ChannelId);
        {ssh_cm, Connection, {data, ChannelId, 0, Data}} ->
            gen_tcp:send(Socket, Data),
            forward_remote_data(Tunnel, Socket);
        {ssh_cm, Connection, {data, ChannelId, 1, Data}} ->
            % Handle stderr data if needed
            error_logger:info_msg("SSH stderr: ~p", [Data]),
            forward_remote_data(Tunnel, Socket);
        {ssh_cm, Connection, {eof, ChannelId}} ->
            % SSH channel received EOF
            forward_remote_data(Tunnel, Socket);
        {ssh_cm, Connection, {exit_status, ChannelId, _Status}} ->
            % Remote process exited
            gen_tcp:close(Socket);
        {ssh_cm, Connection, {closed, ChannelId}} ->
            gen_tcp:close(Socket);
        {From, stop} ->
            ssh_connection:close(Connection, ChannelId),
            gen_tcp:close(Socket),
            From ! ok;
        {register_channel, Pid, ChanId} ->
            NewTunnel = Tunnel#tunnel{
                channels = [{Pid, ChanId} | Tunnel#tunnel.channels]
            },
            forward_remote_data(NewTunnel, Socket)
    end.

start_socks_proxy(LocalPort, SshHost, SshOptions) ->
    {Host, Port} = parse_ssh_host(SshHost),

    case ssh:connect(Host, Port, SshOptions) of
        {ok, Connection} ->
            {ok, Listener} = gen_tcp:listen(LocalPort, [
                binary,
                {active, false},
                {reuseaddr, true}
            ]),

            Tunnel = #tunnel{
                connection = Connection,
                ref = Listener,
                type = socks,
                parent = self()
            },
            accept_socks_connections(Tunnel);
        Error ->
            {error, {ssh_connect_failed, Error}}
    end.

accept_socks_connections(
    Tunnel = #tunnel{connection = Connection, ref = Listener}
) ->
    case gen_tcp:accept(Listener) of
        {ok, Client} ->
            spawn(fun() -> handle_socks_connection(Connection, Client) end),
            accept_socks_connections(Tunnel);
        Error ->
            {error, {accept_failed, Error}}
    end.

handle_socks_connection(Connection, Socket) ->
    % SOCKS protocol implementation would go here
    % This is a simplified skeleton

    inet:setopts(Socket, [{active, once}]),
    receive
        {tcp, Socket, <<5, _NumMethods, Methods/binary>>} ->
            % SOCKS5 initial handshake
            case binary:match(Methods, <<0>>) of
                {_, _} ->
                    gen_tcp:send(Socket, <<5, 0>>),
                    handle_socks5_request(Connection, Socket);
                nomatch ->
                    gen_tcp:send(Socket, <<5, 255>>),
                    gen_tcp:close(Socket)
            end;
        {tcp_closed, Socket} ->
            ok
    end.

handle_socks5_request(Connection, Socket) ->
    % This would implement the full SOCKS5 protocol
    % Simplified skeleton for demonstration
    inet:setopts(Socket, [{active, once}]),
    receive
        {tcp, Socket, <<5, 1, 0, AType, Rest/binary>>} ->
            % Process connection request
            {TargetHost, TargetPort, _} = parse_socks_address(AType, Rest),

            % Use a session channel and execute a netcat command to connect
            case ssh_connection:session_channel(Connection, infinity) of
                {ok, ChannelId} ->
                    ConnectCmd = io_lib:format("nc ~s ~b", [
                        TargetHost, TargetPort
                    ]),
                    case
                        ssh_connection:exec(
                            Connection, ChannelId, ConnectCmd, infinity
                        )
                    of
                        ok ->
                            gen_tcp:send(
                                Socket, <<5, 0, 0, 1, 0, 0, 0, 0, 0, 0>>
                            ),
                            forward_local_data(Connection, ChannelId, Socket);
                        _ ->
                            gen_tcp:send(
                                Socket, <<5, 1, 0, 1, 0, 0, 0, 0, 0, 0>>
                            ),
                            gen_tcp:close(Socket)
                    end;
                _ ->
                    gen_tcp:send(Socket, <<5, 1, 0, 1, 0, 0, 0, 0, 0, 0>>),
                    gen_tcp:close(Socket)
            end;
        {tcp_closed, Socket} ->
            ok
    end.

parse_socks_address(1, <<A, B, C, D, PortHi, PortLo, _/binary>>) ->
    % IPv4
    {
        lists:flatten(io_lib:format("~p.~p.~p.~p", [A, B, C, D])),
        (PortHi bsl 8) bor PortLo,
        6
    };
parse_socks_address(3, <<Len, HostName:Len/binary, PortHi, PortLo, _/binary>>) ->
    % Domain name
    {binary_to_list(HostName), (PortHi bsl 8) bor PortLo, 3 + Len + 2};
parse_socks_address(4, _) ->
    % IPv6 - simplified, would need proper implementation
    {"::1", 0, 18}.


