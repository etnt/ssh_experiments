-module(ssh_exec).
-export([main/1, exec/4, shell/3, start_deps/0]).

-record(address, {address,
                  port,
                  profile
                 }).

shell(Host, Port, Options) ->
    start_deps(),
    ssh:shell(Host, Port, Options).

start_deps() ->
    ok = application:ensure_started(crypto),
    ok = application:ensure_started(asn1),
    ok = application:ensure_started(public_key),
    ok = application:ensure_started(inets),
    ok = application:ensure_started(ssh).
    

get_user_ssh_dir() ->
    {ok, [[Home]]} = init:get_argument(home),
    filename:join(Home, ".ssh").

exec(Host, Port, User, Command) when is_list(Host) ->
    start_deps(),
    _SshDir = get_user_ssh_dir(),
    SshOpts = [
        {user, User}
        %{silently_accept_hosts, true},
        %{user_interaction, false},
        %{user_dir, SshDir},
        %{ssh_msg_debug_fun, fun(_, true, M, _) ->
        %    io:format("DEBUG: ~p~n", [M])
        %end},
        %{auth_methods, "publickey,password"}
    ],
    do_exec(Host, Port, Command, SshOpts).

do_exec(Host, Port, Command, Options) ->
    case connect(Host, Port, Options) of
        {ok,ConnectionRef} ->
            Reply = execute(ConnectionRef, Command),
            io:format("~s~n",[binary_to_list(list_to_binary(Reply))]),
            close(ConnectionRef);
        Error ->
            Error
    end.

close(ConnectionRef) ->
    ssh_connection_handler:stop(ConnectionRef).

execute(ConnectionRef, Command) ->
    case ssh_connection:session_channel(ConnectionRef, infinity) of
        {ok, ChannelId} ->
            case
                ssh_connection:exec(ConnectionRef, ChannelId, Command, infinity)
            of
                success ->
                    collect_output(ConnectionRef, ChannelId, []);
                Error ->
                    ssh:close(ConnectionRef),
                    {error, {exec_failed, Error}}
            end;
        Error ->
            ssh:close(ConnectionRef),
            {error, {channel_failed, Error}}
    end.


connect(Host, Port, Options) ->
    case ssh_options:handle_options(client, Options) of
        {error, Reason} ->
            {error, Reason};

        SshOptions ->
            SocketOpts =
                ssh_options:get_value(user_options,socket_options,SshOptions,?MODULE,?LINE)
                ++ [{active,false}],
            try
                transport_connect(Host, Port, SocketOpts, SshOptions)
            of
                {ok, Socket} ->
                    continue_connect(Socket, SshOptions, infinity);
                {error, Reason} ->
                    {error, Reason}
            catch
                _:badarg -> {error, {options,SocketOpts}};
                _:{error,Reason} -> {error,Reason};
                error:Error -> {error,Error};
                Class:Error -> {error, {Class,Error}}
            end
    end.

continue_connect(Socket, Options0, NegTimeout) ->
    {ok, {SockHost,SockPort}} = inet:sockname(Socket),
    Options = ssh_options:put_value(internal_options,{negotiation_timeout,NegTimeout},Options0, ?MODULE,?LINE),
    Profile = ssh_options:get_value(user_options,profile,Options,?MODULE,?LINE),
    Address = #address{address = SockHost,
                       port    = SockPort,
                       profile = Profile
                      },
    ssh_system_sup:start_connection(client, Address, Socket, Options).


transport_connect(Host, Port, SocketOpts, Options) ->
    {_, Callback, _} =
        ssh_options:get_value(user_options,transport,Options,?MODULE,?LINE),
    ConnectTimeout =
        ssh_options:get_value(user_options,connect_timeout,Options,?MODULE,?LINE),
    Callback:connect(Host, Port, SocketOpts, ConnectTimeout).

collect_output(ConnectionRef, ChannelId, Acc) ->
    receive
        {ssh_cm, ConnectionRef, {data, ChannelId, _, Data}} ->
            collect_output(ConnectionRef, ChannelId, [Data | Acc]);
        {ssh_cm, ConnectionRef, {eof, ChannelId}} ->
            collect_output(ConnectionRef, ChannelId, Acc);
        {ssh_cm, ConnectionRef, {exit_status, ChannelId, _Status}} ->
            collect_output(ConnectionRef, ChannelId, Acc);
        {ssh_cm, ConnectionRef, {closed, ChannelId}} ->
            ssh:close(ConnectionRef),
            lists:reverse(Acc)
    after 10000 ->
        ssh:close(ConnectionRef),
        {error, timeout}
    end.

main([Host, Port, User, Command]) ->
    try
        PortNum = list_to_integer(Port),
        Result = exec(Host, PortNum, User, Command),
        case Result of
            {error, Reason} ->
                io:format("Error: ~p~n", [Reason]),
                halt(1);
            Output ->
                io:format("~s~n", [Output])
        end
    catch
        _:Error ->
            io:format("Error: ~p~n", [Error]),
            halt(1)
    end;
main(_) ->
    io:format("Usage: ssh_exec Host Port User Command~n"),
    halt(1).
