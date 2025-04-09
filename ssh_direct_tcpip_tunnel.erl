-module(ssh_direct_tcpip_tunnel).

-export([direct_tcpip_tunnel/6]).

-export([restconf_test/6]).
-export([netconf_test/6]).

%%-define(dbg(FmtStr,Args), ok).
-define(dbg(FmtStr, Args),
    io:format("~p(~p): " ++ FmtStr, [?MODULE, ?LINE | Args])
).

restconf_test(LocalIp, LocalPort, RemoteIp, RemotePort, SshHost, Options) ->
    assert_ip_address(local_ip, LocalIp),
    assert_ip_address(remote_ip, RemoteIp),

    ssh_exec:start_deps(),

    SshOptions = prepare_ssh_options(Options),
    ?dbg("SSH Options: ~p~n", [SshOptions]),

    %% Establish SSH connection
    {ok, ConnRef} = ssh:connect(SshHost, 22, SshOptions),

    %% Create a direct TCP/IP tunnel
    {ok, ChannelId} = direct_tcpip_tunnel(
        ConnRef,
        list_to_binary(LocalIp),
        % Originator address
        LocalPort,
        list_to_binary(RemoteIp),
        % Destination address
        RemotePort,
        % Timeout
        infinity
    ),

    %% Send data through the tunnel
    DestHost = RemoteIp ++ ":" ++ integer_to_list(RemotePort),
    Msg =
        "GET /restconf/data HTTP/1.1\r\n"
        "Host: " ++ DestHost ++
            "\r\n"
            "Authorization: Basic YWRtaW46YWRtaW4=\r\n\r\n",
    ok = ssh_connection:send(ConnRef, ChannelId, Msg),

    tloop(ConnRef, ChannelId),

    %% Close the channel when done
    ssh_connection:close(ConnRef, ChannelId).

netconf_test(LocalIp, LocalPort, RemoteIp, RemotePort, SshHost, Options) ->
    assert_ip_address(local_ip, LocalIp),
    assert_ip_address(remote_ip, RemoteIp),

    ssh_exec:start_deps(),

    SshOptions = prepare_ssh_options(Options),
    ?dbg("SSH Options: ~p~n", [SshOptions]),

    %% Establish SSH connection
    {ok, ConnRef} = ssh:connect(SshHost, 22, SshOptions),

    %% Create a direct TCP/IP tunnel
    {ok, ChannelId} = direct_tcpip_tunnel(
        ConnRef,
        list_to_binary(LocalIp),
        % Originator address
        LocalPort,
        list_to_binary(RemoteIp),
        % Destination address
        RemotePort,
        % Timeout
        infinity
    ),

    %% Send Netconf Hello message through the tunnel
    HelloMsg =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<hello xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
        "  <capabilities>\n"
        "    <capability>urn:ietf:params:netconf:base:1.0</capability>\n"
        "  </capabilities>\n"
        % End-of-message delimiter for Netconf
        "</hello>\n]]>]]>",

    ok = ssh_connection:send(ConnRef, ChannelId, HelloMsg),

    tloop(ConnRef, ChannelId),

    %% Close the channel when done
    ssh_connection:close(ConnRef, ChannelId).



%% Receive data (in a receive loop)
tloop(ConnRef, ChannelId) ->
    receive
        %% DataTypeCode: valid values are 0 ("normal") and 1 ("stderr"), see RFC 4254, Section 5.2.
        {ssh_cm, ConnRef, {data, ChannelId, 0 = _DataTypeCode, Data}} ->
            io:format("RECEIVED:~n~s~n", [binary_to_list(Data)]),
            tloop(ConnRef, ChannelId);
        {ssh_cm, ConnRef, {eof, ChannelId}} ->
            io:format("Connection closed by peer~n");
        Other ->
            io:format("Other message: ~p~n", [Other]),
            tloop(ConnRef, ChannelId)
    after 10000 ->
        io:format("Timeout waiting for response~n")
    end.

assert_ip_address(What, IpStr) when is_list(IpStr) ->
    case inet:parse_address(IpStr) of
        {ok, _Ip} -> ok;
        _ -> throw({error, {What, IpStr}})
    end.

%% @doc Opens a direct TCP/IP channel to a remote host through the SSH server.
%% Returns a channel ID that can be used with ssh_connection:send/3 and receiving
%% messages {ssh_cm, ConnectionRef, {data, ChannelId, Type, Data}}.

direct_tcpip_tunnel(
    ConnectionRef,
    OriginatorIP,
    OriginatorPort,
    DestHost,
    DestPort,
    Timeout
) when
    is_binary(OriginatorIP) andalso is_binary(DestHost)
->
    %% NOTE: According to RFC 4251 , the type 'string' is defined as:
    %%
    %%  Arbitrary length binary string.  Strings are allowed to contain
    %%  arbitrary binary data, including null characters and 8-bit
    %%  characters.  They are stored as a uint32 containing its length
    %%  (number of bytes that follow) and zero (= empty string) or more
    %%  bytes that are the value of the string.  Terminating null
    %%  characters are not used.

    %% Create direct-tcpip channel
    ssh_connection:open_channel(
        ConnectionRef,
        "direct-tcpip",
        <<
            (byte_size(DestHost)):32,
            DestHost/binary,
            DestPort:32,
            (byte_size(OriginatorIP)):32,
            OriginatorIP/binary,
            OriginatorPort:32
        >>,
        Timeout
    ).

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
    ?dbg("INFO debug_fun Msg=~p~n", [_Msg]),
    ok.

%%on_connect(Username, B, C) ->
%%  ?dbg("~p on_connect: ~p ~p ~p\n",[self(), Username,B,C]),
%%  ok.

on_disconnect(_A) ->
    ?dbg("INFO ~p on_disconnect: ~p\n", [self(), _A]),
    ok.
