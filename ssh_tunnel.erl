-module(ssh_tunnel).

-export([local/6, remote/6, stop/1]).

-record(tunnel, {port, type}).

%% Start local port forwarding tunnel (e.g. local:8080 -> remote:80)
local(LocalIp, LocalPort, RemoteIp, RemotePort, SshHost, Options)
  when is_list(LocalIp),
       is_integer(LocalPort),
       is_list(RemoteIp),
       is_integer(RemotePort),
       is_list(SshHost),
       is_list(Options) ->
    assert_ip_address(local_ip, LocalIp),
    assert_ip_address(remote_ip, RemoteIp),
    User = proplists:get_value(user, Options),
    Identity =
        case proplists:get_value(identity, Options) of
            undefined ->
                "";
            Path ->
                " -i " ++ Path
        end,
    % Build SSH command for local forwarding
    Cmd = lists:flatten(
              io_lib:format("ssh ~s -nNT -L ~s:~b:~s:~b ~s@~s",
                            [Identity, LocalIp, LocalPort, RemoteIp, RemotePort, User, SshHost])),
    start_tunnel(Cmd, local).

assert_ip_address(What, IpStr) when is_list(IpStr) ->
    case inet:parse_address(IpStr) of
        {ok, _Ip} -> ok;
        _ -> throw({error, {What,IpStr}})
    end.


%% Start remote port forwarding tunnel (e.g. remote:8080 -> local:80)
remote(LocalIp, LocalPort, RemoteIp, RemotePort, SshHost, Options)
    when is_list(LocalIp),
         is_integer(LocalPort),
         is_list(RemoteIp),
         is_integer(RemotePort),
         is_list(SshHost),
         is_list(Options) ->
    assert_ip_address(local_ip, LocalIp),
    assert_ip_address(remote_ip, RemoteIp),
    User = proplists:get_value(user, Options),
    Identity =
        case proplists:get_value(identity, Options) of
            undefined ->
                "";
            Path ->
                " -i " ++ Path
        end,
    % Build SSH command for remote forwarding
    Cmd = lists:flatten(
              io_lib:format("ssh ~s -nNT -R ~s:~b:~s:~b ~s@~s",
                            [Identity, RemoteIp, RemotePort, LocalIp, LocalPort, User, SshHost])),
    start_tunnel(Cmd, remote).

%% Stop a running tunnel
stop(#tunnel{port = Port} = _Tunnel) ->
    Port ! {self(), close},
    receive
        {Port, closed} ->
            ok
    after 5000 ->
        catch port_close(Port),
        {error, timeout}
    end.

%% Internal functions

start_tunnel(Cmd, Type) ->
    io:format(">>> Cmd: ~p~n",[Cmd]),
    Port = open_port({spawn, Cmd}, [exit_status, {line, 16384}]),
    monitor_tunnel(Port, Type, []).

monitor_tunnel(Port, Type, Log) ->
    receive
        {Port, {data, {eol, Line}}} ->
            monitor_tunnel(Port, Type, [Line | Log]);
        {Port, {exit_status, 0}} ->
            {ok, #tunnel{port = Port, type = Type}};
        {Port, {exit_status, Status}} ->
            {error, {exit_status, Status, lists:reverse(Log)}};
        {'EXIT', Port, Reason} ->
            {error, {tunnel_crashed, Reason, lists:reverse(Log)}}
    end.
