-module(ssh_agent_forward).

-export([netconf_ssh_test/5, netconf_ssh_test/6]).

%%-define(dbg(FmtStr,Args), ok).
-define(dbg(FmtStr, Args),
    io:format("~p(~p): " ++ FmtStr, [?MODULE, ?LINE | Args])
).

%% @doc Establish a full SSH connection to the destination host via a jump host
%% and connect to the Netconf subsystem (with password authentication)
netconf_ssh_test(RemoteIp, RemotePort, SshHost, Options, RemoteUser, Password) ->
    assert_ip_address(remote_ip, RemoteIp),

    ssh_exec:start_deps(),

    SshOptions = prepare_ssh_options(Options),
    ?dbg("SSH Options: ~p~n", [SshOptions]),

    %% Establish SSH connection to the jump host
    {ok, ConnRef} = ssh:connect(SshHost, 22, SshOptions),

    %% Build SSH command to connect to destination host with netconf subsystem
    SSHCmd = io_lib:format(
        "ssh -l ~s ~s -p ~w -s netconf -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=no",
        [RemoteUser, RemoteIp, RemotePort]
    ),

    %% Execute the SSH command on the jump host
    {ok, ChannelId} = ssh_connection:session_channel(ConnRef, infinity),
    success = ssh_connection:exec(ConnRef, ChannelId, SSHCmd, infinity),

    %% Use the tloop_with_pw function to handle password prompts
    tloop_with_pw(ConnRef, ChannelId, Password),

    %% Close the channel when done
    ssh_connection:close(ConnRef, ChannelId).

%% For backward compatibility
netconf_ssh_test(RemoteIp, RemotePort, SshHost, Options, RemoteUser) ->
    assert_ip_address(remote_ip, RemoteIp),

    ssh_exec:start_deps(),

    SshOptions = prepare_ssh_options(Options),
    ?dbg("SSH Options: ~p~n", [SshOptions]),

    %% Establish SSH connection to the jump host
    {ok, ConnRef} = ssh:connect(SshHost, 22, SshOptions),

    %% Build SSH command to connect to destination host with netconf subsystem
    SSHCmd = io_lib:format(
        "ssh -l ~s ~s -p ~w -s netconf -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -A",
        [RemoteUser, RemoteIp, RemotePort]
    ),

    %% Execute the SSH command on the jump host
    {ok, ChannelId} = ssh_connection:session_channel(ConnRef, infinity),
    success = ssh_connection:exec(ConnRef, ChannelId, SSHCmd, infinity),

    %% Send Netconf Hello message through the nested SSH connection
    HelloMsg =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<hello xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
        "  <capabilities>\n"
        "    <capability>urn:ietf:params:netconf:base:1.0</capability>\n"
        "  </capabilities>\n"
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

%% Receive data with password support
tloop_with_pw(ConnRef, ChannelId, Password) ->
    receive
        %% DataTypeCode: 0 is normal output, 1 is stderr
        {ssh_cm, ConnRef, {data, ChannelId, 0 = _DataTypeCode, Data}} ->
            io:format("RECEIVED:~n~s~n", [binary_to_list(Data)]),
            tloop_with_pw(ConnRef, ChannelId, Password);
        {ssh_cm, ConnRef, {data, ChannelId, 1 = _DataTypeCode, Data}} ->
            DataStr = binary_to_list(Data),
            io:format("STDERR: ~s~n", [DataStr]),
            %% Check if this is a password prompt
            case
                lists:member($:, DataStr) andalso
                    (string:str(DataStr, "assword") > 0 orelse
                        string:str(DataStr, "word:") > 0)
            of
                true ->
                    %% Send password followed by newline
                    ok = ssh_connection:send(ConnRef, ChannelId, [
                        Password, "\n"
                    ]),
                    tloop_with_pw(ConnRef, ChannelId, Password);
                false ->
                    tloop_with_pw(ConnRef, ChannelId, Password)
            end;
        {ssh_cm, ConnRef, {eof, ChannelId}} ->
            io:format("Connection closed by peer~n");
        Other ->
            io:format("Other message: ~p~n", [Other]),
            tloop_with_pw(ConnRef, ChannelId, Password)
    after 10000 ->
        io:format("Timeout waiting for response~n")
    end.

assert_ip_address(What, IpStr) when is_list(IpStr) ->
    case inet:parse_address(IpStr) of
        {ok, _Ip} -> ok;
        _ -> throw({error, {What, IpStr}})
    end.

prepare_ssh_options(Options) ->
    User = proplists:get_value(user, Options),

    BaseOptions =
        [
            {silently_accept_hosts, true},
            {user, User},
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

on_disconnect(_A) ->
    ?dbg("INFO ~p on_disconnect: ~p\n", [self(), _A]),
    ok.
