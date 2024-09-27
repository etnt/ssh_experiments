-module(ssh_channel_test).
-export([test/0]).

init() ->
    application:ensure_all_started(crypto),
    application:ensure_all_started(asn1),
    application:ensure_all_started(public_key),
    application:ensure_all_started(ssh).

test() ->
    init(),
    %%case ssh:connect("127.0.0.1", 22, [{user, "admin"}, {password, "admin"}, {preferred_algorithms, [{cipher, ['aes128-ctr']}]}, {connect_timeout, 10000}]) of
    case ssh:connect("127.0.0.1", 22, [{user, "admin"},
                                       {password, "admin"},
                                       %%{preferred_algorithms, [{cipher, ['aes128-ctr']}]},
                                       {connect_timeout, 10000}]) of
        {ok, Connection} ->
            io:format("SSH connection established~n"),
            case create_and_use_channels(Connection) of
                ok -> 
                    io:format("Channels created and used successfully~n");
                {error, Reason} ->
                    io:format("Error in channel operations: ~p~n", [Reason])
            end,
            ssh:close(Connection);
        {error, Reason} ->
            io:format("Failed to connect: ~p~n", [Reason])
    end.


create_and_use_channels(Connection) ->
    try
        {ok, Channel1} = create_netconf_channel(Connection),
        {ok, Channel2} = create_netconf_channel(Connection),

        ok = send_hello_msg(Connection, Channel1),
        receive_data(Channel1),
        io:format("Closing Channel(~p)~n", [Channel1]),
        ok = ssh_connection:close(Connection, Channel1),

        timer:sleep(2000),

        ok = send_hello_msg(Connection, Channel2),
        receive_data(Channel2),
        io:format("Closing Channel(~p)~n", [Channel2]),
        ok = ssh_connection:close(Connection, Channel2)

    catch
        {X,Y} ->
            io:format("ERROR: ~p~n",[{X,Y}])
    end.


create_netconf_channel(Connection) ->
    case ssh_connection:session_channel(Connection, infinity) of
        {ok, Channel} ->
            io:format("Channel(~p) created successfully~n", [Channel]),
            io:format("Attempting to start NETCONF subsystem on Channel(~p)~n", [Channel]),
            case ssh_connection:subsystem(Connection, Channel, "netconf", infinity) of
                success ->
                    io:format("NETCONF subsystem started on Channel(~p)~n", [Channel]),
                    {ok, Channel};
                Else ->
                    io:format("Failed to start NETCONF subsystem on Channel(~p): ~p~n", [Channel, Else]),
                    {error, {netconf_subsystem_failed, Channel, Else}}
            end;
        Error ->
            io:format("Failed to create Channel: ~p~n", [Error]),
            {error, {channel_creation_failed, Error}}
    end.

send_hello_msg(Connection, Channel) ->
    HelloMessage = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><hello xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><capabilities><capability>urn:ietf:params:netconf:base:1.1</capability></capabilities></hello>",
    io:format("Sending Hello message on Channel(~p)~n", [Channel]),
    ok = ssh_connection:send(Connection, Channel, HelloMessage, infinity).



receive_data(Channel) ->
    receive
        {ssh_cm, _, {data, Channel, _, Data}} ->
            io:format("Data on Channel ~p: ~p~n", [Channel, Data]);
        {ssh_cm, _, {closed, Channel}} ->
            io:format("Channel ~p closed~n", [Channel])
    after 10000 ->
        io:format("Timeout waiting for data on Channel ~p~n", [Channel])
    end.
