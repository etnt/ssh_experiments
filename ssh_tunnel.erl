-module(ssh_tunnel).
-export([local/5, remote/4, stop/1]).

-record(tunnel, {port, type}).

%% Start local port forwarding tunnel (e.g. local:8080 -> remote:80)
local(LocalPort, RemoteHost, RemotePort, SshHost, Options) when is_integer(LocalPort),
                                                               is_list(RemoteHost),
                                                               is_integer(RemotePort),
                                                               is_list(SshHost),
                                                               is_list(Options) ->
    User = proplists:get_value(user, Options),
    Identity = case proplists:get_value(identity, Options) of
        undefined -> "";
        Path -> [" -i ", Path]
    end,
    % Build SSH command for local forwarding
    Cmd = lists:flatten(io_lib:format(
        "ssh ~s-nNT -L ~b:~s:~b ~s@~s",
        [Identity, LocalPort, RemoteHost, RemotePort, User, SshHost]
    )),
    start_tunnel(Cmd, local).

%% Start remote port forwarding tunnel (e.g. remote:8080 -> local:80)
remote(RemotePort, LocalPort, SshHost, Options) when is_integer(RemotePort),
                                                    is_integer(LocalPort),
                                                    is_list(SshHost),
                                                    is_list(Options) ->
    User = proplists:get_value(user, Options),
    Identity = case proplists:get_value(identity, Options) of
        undefined -> "";
        Path -> [" -i ", Path]
    end,
    % Build SSH command for remote forwarding
    Cmd = lists:flatten(io_lib:format(
        "ssh ~s-nNT -R ~b:localhost:~b ~s@~s",
        [Identity, RemotePort, LocalPort, User, SshHost]
    )),
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
    Port = open_port({spawn, Cmd}, [exit_status, {line, 16384}]),
    monitor_tunnel(Port, Type, []).

monitor_tunnel(Port, Type, Log) ->
    receive
        {Port, {data, {eol, Line}}} ->
            % Log any output from the SSH process
            monitor_tunnel(Port, Type, [Line|Log]);
        {Port, {exit_status, 0}} ->
            {ok, #tunnel{port = Port, type = Type}};
        {Port, {exit_status, Status}} ->
            {error, {exit_status, Status, lists:reverse(Log)}};
        {'EXIT', Port, Reason} ->
            {error, {tunnel_crashed, Reason, lists:reverse(Log)}}
    end.
