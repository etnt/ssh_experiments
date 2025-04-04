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
    {ok, spawn(fun() -> start_tunnel(Cmd, local) end)}.

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
    {ok, spawn(fun() -> start_tunnel(Cmd, remote) end)}.

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

start_tunnel(Cmd0, Type) ->
    %%io:format(">>> Cmd: ~p~n",[Cmd]),
    Cmd = "sh -c 'echo $$; exec " ++ Cmd0 ++ "'",
    Port = open_port({spawn, Cmd}, [exit_status, {line, 16384}]),
    Line = receive_line(Port),
    monitor_tunnel(Port, Type, Line, []).

receive_line(Port) ->
    receive
        {Port, {data, {eol, Data}}} ->
            Data
    end.



monitor_tunnel(Port, Type, PidLine, Log) ->
    receive
        {Port, {data, {eol, Line}}} ->
            monitor_tunnel(Port, Type, PidLine, [Line | Log]);
        {Port, {exit_status, 0}} ->
            {ok, #tunnel{port = Port, type = Type}};
        {Port, {exit_status, Status}} ->
            {error, {exit_status, Status, lists:reverse(Log)}};
        {'EXIT', Port, Reason} ->
            {error, {tunnel_crashed, Reason, lists:reverse(Log)}};
        {From, stop} ->
            force_kill(PidLine),
            From ! close_port(Port)
    end.

close_port(Port) ->
    Port ! {self(), close},
     receive
         {Port, closed} ->
             ok
     after 5000 ->
         catch port_close(Port),
         {error, timeout}
     end.

force_kill(PidLine) ->
    io:format("Killing OS pid: ~p~n", [PidLine]),
    os:cmd(["kill -9 ", PidLine]),
    killed.
