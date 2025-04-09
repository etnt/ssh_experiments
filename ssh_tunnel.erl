-module(ssh_tunnel).

-export([local/6, remote/6, stop/1]).
-export([netconf_jump_test/6, stop_jump_session/1]).

-record(tunnel, {port, type}).



%% @doc Connect to NETCONF using SSH ProxyJump (-J) feature for authentication prompt passthrough
netconf_jump_test(JumpHost, Options, RemoteIp, RemotePort, RemoteUser, RemotePassword) ->
    assert_ip_address(remote_ip, RemoteIp),
    
    JumpUser = proplists:get_value(user, Options),
    JumpPassword = proplists:get_value(user_password, Options),
    JumpUserHost = lists:flatten(io_lib:format("~s@~s", [JumpUser, JumpHost])),

    RemoteUserHost = lists:flatten(io_lib:format("~s@~s", [RemoteUser, RemoteIp])),

    %%Identity =
    %%    case proplists:get_value(identity, Options) of
    %%        undefined ->
    %%            throw({error,no_identity});
    %%        Path ->
    %%            Path
    %%    end,

    %% Build SSH command with ProxyJump
    %%NoHostKeyCheck = "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null",
    %%_Cmd = io_lib:format(
    %%    "./ssh_pty_wrapper ~s ~s -J ~s ~s@~s -p ~w -s netconf",
    %%    [Identity, NoHostKeyCheck, JumpUserHost, RemoteUser, RemoteIp, RemotePort]
    %%),



    %% Spawn interactive port to handle the SSH session
    %%Port = open_port({spawn, Cmd}, [binary, use_stdio, exit_status, stderr_to_stdout]),
    Port = open_port({spawn_executable, "./ssh_pty_wrapper"},
                                    [{args,
                                      [%"-i", Identity,
                                       "-J", JumpUserHost,
                                       RemoteUserHost,
                                       "-p", integer_to_list(RemotePort),
                                       "-s", "netconf"]},
                                     binary, use_stdio, stream]),
                                 %%binary, stderr_to_stdout, use_stdio, stream, exit_status, {env,[{"TERM","vt100"},{"DISPLAY", ""}]} ]),                                 
    
    
    jumphost_session(pw1, Port, 5000, JumpPassword, RemotePassword).


send_hello(Port) ->
    %% Send Hello message over stdin to the SSH process
    HelloMsg =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<hello xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
        "  <capabilities>\n"
        "    <capability>urn:ietf:params:netconf:base:1.0</capability>\n"
        "  </capabilities>\n"
        "</hello>\n]]>]]>",
    
    port_command(Port, list_to_binary(HelloMsg)),
    
    ok.

%% Interactive port handler that relays I/O between Erlang and SSH process
jumphost_session(State, Port, Timeout, JumpPassword, RemotePassword) ->
    receive
        {Port, {data, Data}}  ->

            if (State == pw1) orelse (State == pw2) ->
                    case binary:match(Data, <<"password:">>) of
                        nomatch ->
                            io:format("<~p>: ~p~n",[State, Data]),
                            jumphost_session(State, Port, Timeout, JumpPassword, RemotePassword);
                        _ when State == pw1 ->
                            io:format("<~p>: sending JumpPassword: ~s~n",[State,JumpPassword]),
                            port_command(Port, list_to_binary(JumpPassword++"\n")),
                            jumphost_session(pw2, Port, Timeout, JumpPassword, RemotePassword);
                        _ when State == pw2 ->
                            io:format("<~p>: sending RemotePassword: ~s~n",[State,RemotePassword]),
                            port_command(Port, list_to_binary(RemotePassword++"\n")),
                            jumphost_session(run, Port, Timeout, JumpPassword, RemotePassword)
                    end;
               true ->
                    io:format("<~p>: ~p~n",[State, Data]),
                    jumphost_session(State, Port, Timeout, JumpPassword, RemotePassword)
            end;

        {Port, {exit_status, Status}} ->
            io:format("SSH process exited with status ~p~n", [Status]);
            
        {'EXIT', Port, Reason} ->
            io:format("SSH port closed with reason: ~p~n", [Reason]);
            
        {input, Data} ->
            %% Forward input to SSH process
            port_command(Port, list_to_binary(Data)),
            jumphost_session(State, Port, Timeout, JumpPassword, RemotePassword)

    after Timeout ->
            if (State == pw1) orelse (State == pw2) ->
                    jumphost_session(State, Port, Timeout, JumpPassword, RemotePassword);
               true ->
                    %% Send HELLO once!
                    io:format("<~p>: sending Hello~n",[State]),
                    send_hello(Port),
                    jumphost_session(State, Port, infinity, JumpPassword, RemotePassword)
            end

    end.

%% To stop the session
stop_jump_session(Port) ->
    port_close(Port).



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
