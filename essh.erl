-module(essh).
-export([exec/4]).

-include_lib("public_key/include/public_key.hrl").

-define(dbg(FmtStr, Args), io:format("(~p): " ++ FmtStr, [?LINE | Args])).

% SSH Protocol Constants
-define(SSH_PORT, 22).
-define(SSH_VERSION, "SSH-2.0-ErlangSSH_1.0").
-define(CRLF, "\r\n").

% RFC 4253 Section 7.1 Number of name-list fields in KEXINIT
-define(KEXINIT_NAMELIST_COUNT, 10).
% Cookie length in KEXINIT
-define(KEXINIT_COOKIE_LENGTH, 16).
% Reserved field length in KEXINIT
-define(KEXINIT_RESERVED_LENGTH, 4).

% SSH Message Type Constants
-define(SSH_MSG_KEXINIT, 20).
-define(SSH_MSG_KEXDH_INIT, 30).
-define(SSH_MSG_KEXDH_REPLY, 31).
-define(SSH_MSG_NEWKEYS, 21).
-define(SSH_MSG_USERAUTH_REQUEST, 50).
-define(SSH_MSG_USERAUTH_SUCCESS, 51).
-define(SSH_MSG_USERAUTH_FAILURE, 52).
-define(SSH_MSG_CHANNEL_OPEN, 90).
-define(SSH_MSG_CHANNEL_OPEN_CONFIRMATION, 91).
-define(SSH_MSG_CHANNEL_REQUEST, 98).
-define(SSH_MSG_CHANNEL_DATA, 94).
-define(SSH_MSG_CHANNEL_EOF, 96).
-define(SSH_MSG_CHANNEL_CLOSE, 97).

% Channel Types and Codes
-define(CHANNEL_TYPE_SESSION, "session").
-define(CHANNEL_REQUEST_EXEC, "exec").

% Crypto Constants

% RFC 4253 6.2
-define(DH_G, 2).
-define(DH_P,
    16#FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
).

% Records
-record(ssh_conn, {
    socket :: gen_tcp:socket(),
    host :: string(),
    port :: integer(),
    version :: string(),
    server_version :: string(),
    kex_algorithm :: binary(),
    host_key_algorithm :: binary(),
    % Server's KEXINIT message
    server_kexinit :: binary(),
    % Client's KEXINIT message
    client_kexinit :: binary(),
    shared_secret :: binary(),
    session_id :: binary(),
    encrypt_key :: binary(),
    decrypt_key :: binary(),
    encrypt_mac_key :: binary(),
    decrypt_mac_key :: binary(),
    % Added for CTR mode
    encrypt_seq = 0 :: non_neg_integer(),
    % Added for CTR mode
    decrypt_seq = 0 :: non_neg_integer(),
    authenticated = false :: boolean()
}).

%% @doc Execute a command on a remote host using SSH
-spec exec(string(), string(), string(), string()) ->
    {ok, binary()} | {error, term()}.
exec(RemoteIp, RemoteUser, RemotePasswd, Command) ->
    case connect(RemoteIp) of
        {ok, Conn} ->
            try
                % Perform key exchange
                {ok, KexConn} = perform_key_exchange(Conn),

                % Authentication
                {ok, AuthConn} = authenticate(
                    KexConn, RemoteUser, RemotePasswd
                ),

                % Open Channel and execute command
                {ok, Channel} = open_channel(AuthConn),
                execute_command(AuthConn, Channel, Command)
            after
                close_connection(Conn)
            end;
        {error, Reason} ->
            {error, {connection_failed, Reason}}
    end.

%% Connection and Version Exchange
connect(Host) -> connect(Host, ?SSH_PORT).

connect(Host, Port) ->
    case gen_tcp:connect(Host, Port, [binary, {active, false}]) of
        {ok, Socket} ->
            perform_version_exchange(#ssh_conn{
                socket = Socket,
                host = Host,
                port = Port,
                version = ?SSH_VERSION
            });
        {error, Reason} ->
            {error, {tcp_connection_failed, Reason}}
    end.

perform_version_exchange(Conn = #ssh_conn{socket = Socket, version = Version}) ->
    ok = gen_tcp:send(Socket, Version ++ ?CRLF),
    case gen_tcp:recv(Socket, 0, 5000) of
        {ok, ServerVersionBin} ->
            ServerVersion = string:trim(binary_to_list(ServerVersionBin)),
            case validate_version_string(ServerVersion) of
                {ok, _} ->
                    {ok, Conn#ssh_conn{server_version = ServerVersion}};
                {error, Reason} ->
                    {error, {invalid_server_version, Reason}}
            end;
        {error, Reason} ->
            {error, {version_exchange_failed, Reason}}
    end.

%% Key Exchange
perform_key_exchange(Conn = #ssh_conn{socket = Socket}) ->
    % Send KEXINIT with debugging
    ?dbg(" Starting key exchange~n", []),
    Cookie = crypto:strong_rand_bytes(16),
    {KexInit, RawPayload} = create_kexinit(Cookie),

    % Log the raw payload details
    ?dbg(
        " Client KEXINIT details:~n"
        "  Raw payload size: ~p bytes~n"
        "  Message type: ~p~n"
        "  Hex dump:~n~s~n",
        [
            byte_size(RawPayload),
            case RawPayload of
                <<?SSH_MSG_KEXINIT, _/binary>> -> "SSH_MSG_KEXINIT";
                _ -> "Unknown"
            end,
            binary_to_list(binary:encode_hex(RawPayload))
        ]
    ),

    % Store raw payload in connection state and send packet
    ConnWithKexInit = Conn#ssh_conn{client_kexinit = RawPayload},
    ok = gen_tcp:send(Socket, KexInit),

    % Log successful KEXINIT storage and send
    ?dbg(
        " Sent KEXINIT and stored in connection state:~n"
        "  Raw payload length: ~p bytes~n"
        "  Content: ~p~n",
        [byte_size(RawPayload), RawPayload]
    ),

    % Generate curve25519 key pair
    ?dbg(" Selected KEX algorithm: ~p~n", [
        ConnWithKexInit#ssh_conn.kex_algorithm
    ]),
    ?dbg(" Generating curve25519 key pair~n", []),
    case crypto:generate_key(eddh, x25519) of
        {PubKey, PrivKey} ->
            ?dbg(
                " Generated curve25519 keys:~n"
                "  Private key size: ~p bytes~n"
                "  Public key size: ~p bytes~n",
                [byte_size(PrivKey), byte_size(PubKey)]
            ),

            % Create DH init payload according to RFC 5656
            DhInitPayload =
                <<?SSH_MSG_KEXDH_INIT, (encode_string(PubKey))/binary>>,
            ?dbg(
                " DH init payload:~n"
                "  Total size: ~p bytes~n"
                "  Message type: ~p~n"
                "  Public key hex: ~s~n",
                [
                    byte_size(DhInitPayload),
                    ?SSH_MSG_KEXDH_INIT,
                    binary_to_list(binary:encode_hex(PubKey))
                ]
            ),

            % Add SSH binary packet format with padding according to RFC 4253 Section 6
            MinPadding = 4,
            BaseLength = byte_size(DhInitPayload) + 5,
            DhInitPaddingLength =
                MinPadding + (8 - (BaseLength + MinPadding) rem 8),
            DhInitPadding = crypto:strong_rand_bytes(DhInitPaddingLength),
            DhInitPacketLen =
                byte_size(DhInitPayload) + DhInitPaddingLength + 1,
            DhInitPacket =
                <<DhInitPacketLen:32/big, DhInitPaddingLength,
                    DhInitPayload/binary, DhInitPadding/binary>>,

            ?dbg(
                " Sending DH init packet:~n"
                "  Total packet size: ~p bytes~n"
                "  Padding length: ~p bytes~n"
                "  Full packet hex:~n~s~n",
                [
                    byte_size(DhInitPacket),
                    DhInitPaddingLength,
                    binary_to_list(binary:encode_hex(DhInitPacket))
                ]
            ),
            % Send the DH init packet
            case gen_tcp:send(Socket, DhInitPacket) of
                ok ->
                    ?dbg(" Successfully sent DH init packet~n", []),
                    receive_and_process_server_response(
                        Socket, ConnWithKexInit, PrivKey, PubKey, Cookie
                    );
                Error ->
                    {error, {send_failed, Error}}
            end;
        Error ->
            {error, {key_generation_failed, Error}}
    end.

receive_and_process_server_response(
    Socket, ConnWithKexInit, PrivKey, PubKey, Cookie
) ->
    case receive_kex_dh_reply(Socket, ConnWithKexInit) of
        {ok, ServerPubKey, HostKey, Signature, NegotiatedConn} ->
            process_server_keys(
                Socket,
                NegotiatedConn,
                PrivKey,
                PubKey,
                Cookie,
                ServerPubKey,
                HostKey,
                Signature
            );
        Error ->
            Error
    end.

process_server_keys(
    Socket,
    NegotiatedConn,
    PrivKey,
    PubKey,
    Cookie,
    ServerPubKey,
    HostKey,
    Signature
) ->
    ?dbg(" Computing shared secret using curve25519~n", []),
    % Compute shared secret using curve25519
    SharedSecret = crypto:compute_key(eddh, ServerPubKey, PrivKey, x25519),
    ?dbg(
        " Computed shared secret:~n"
        "  Size: ~p bytes~n"
        "  Hex: ~s~n",
        [
            byte_size(SharedSecret),
            binary_to_list(binary:encode_hex(SharedSecret))
        ]
    ),

    % Compute session hash
    SessionId = compute_hash(
        NegotiatedConn, Cookie, HostKey, PubKey, ServerPubKey, SharedSecret
    ),

    % Verify signature but continue even if it fails
    ?dbg(" Attempting signature verification~n", []),
    ?dbg(" Signature size: ~p bytes~n", [byte_size(Signature)]),

    % Derive keys (we'll need these regardless of verification result)
    {EncKey, DecKey, EncMacKey, DecMacKey} = derive_keys(
        SharedSecret, SessionId
    ),

    case verify_signature(HostKey, SessionId, Signature) of
        ok ->
            ?dbg(" Signature verification successful~n", []);
        {error, Reason} ->
            % Log warning but continue
            ?dbg(" WARNING: Host key verification failed: ~p~n", [Reason]),
            ?dbg(" Continuing connection without host key verification~n", [])
    end,

    % Continue with connection regardless of verification result
    NewkeysPayload = <<?SSH_MSG_NEWKEYS>>,
    NewkeysPaddingLength =
        (8 - ((byte_size(NewkeysPayload) + 5) rem 8)) rem 8 + 8,
    NewkeysPadding = crypto:strong_rand_bytes(NewkeysPaddingLength),
    NewkeysPacketLen = byte_size(NewkeysPayload) + NewkeysPaddingLength + 1,
    NewkeysPacket =
        <<NewkeysPacketLen:32/big, NewkeysPaddingLength, NewkeysPayload/binary,
            NewkeysPadding/binary>>,

    case gen_tcp:send(Socket, NewkeysPacket) of
        ok ->
            ?dbg(" Sent NEWKEYS, waiting for server NEWKEYS~n", []),
            receive_newkeys_response(
                Socket,
                NegotiatedConn,
                SharedSecret,
                SessionId,
                EncKey,
                DecKey,
                EncMacKey,
                DecMacKey
            );
        {error, SendError} ->
            {error, {newkeys_send_failed, SendError}}
    end.

receive_newkeys_response(
    Socket,
    NegotiatedConn,
    SharedSecret,
    SessionId,
    EncKey,
    DecKey,
    EncMacKey,
    DecMacKey
) ->
    case gen_tcp:recv(Socket, 4, 5000) of
        {ok, <<PacketLen:32/big>>} ->
            case gen_tcp:recv(Socket, PacketLen, 5000) of
                {ok, <<PaddingLen, PayloadAndPadding/binary>>} ->
                    PayloadLen = PacketLen - PaddingLen - 1,
                    <<Payload:PayloadLen/binary, _/binary>> = PayloadAndPadding,
                    case Payload of
                        <<?SSH_MSG_NEWKEYS>> ->
                            ?dbg(" Received NEWKEYS from server~n", []),
                            {ok, NegotiatedConn#ssh_conn{
                                shared_secret = SharedSecret,
                                session_id = SessionId,
                                encrypt_key = EncKey,
                                decrypt_key = DecKey,
                                encrypt_mac_key = EncMacKey,
                                decrypt_mac_key = DecMacKey
                            }};
                        Other ->
                            {error, {unexpected_newkeys_response, Other}}
                    end;
                {error, RecvError} ->
                    {error, {newkeys_recv_failed, RecvError}}
            end;
        {error, RecvError} ->
            {error, {newkeys_recv_failed, RecvError}}
    end.

%% Key Exchange Support Functions
create_kexinit(Cookie) ->
    case byte_size(Cookie) =:= ?KEXINIT_COOKIE_LENGTH of
        false ->
            throw({error, {invalid_cookie_length, byte_size(Cookie)}});
        true ->
            ok
    end,

    % Create all name-lists according to RFC 4253 Section 7.1
    NameLists = [
        % kex algorithms
        "curve25519-sha256,ecdh-sha2-nistp256,diffie-hellman-group16-sha512,diffie-hellman-group14-sha256",
        % server host key algorithms
        "rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256,ssh-ed25519",
        % encryption client->server
        "aes128-ctr",
        % encryption server->client
        "aes128-ctr",
        % mac client->server
        "hmac-sha2-256",
        % mac server->client
        "hmac-sha2-256",
        % compression client->server
        "none",
        % compression server->client
        "none",
        % languages client->server
        "",
        % languages server->client
        ""
    ],

    % Ensure correct number of name-lists
    case length(NameLists) =:= ?KEXINIT_NAMELIST_COUNT of
        false ->
            throw({error, {invalid_namelist_count, length(NameLists)}});
        true ->
            ok
    end,

    % Create the raw payload
    RawPayload = list_to_binary(
        [
            ?SSH_MSG_KEXINIT,
            Cookie
        ] ++ [encode_string(L) || L <- NameLists] ++
            [
                % First KEX follows
                0,
                % Reserved
                <<0:32>>
            ]
    ),

    % Log raw payload creation
    io:format(
        "Debug: Created KEXINIT raw payload:~n"
        "  Size: ~p bytes~n"
        "  First byte: ~p~n"
        "  Hex dump:~n~s~n",
        [
            byte_size(RawPayload),
            case RawPayload of
                <<FirstByte:8, _/binary>> -> FirstByte;
                _ -> undefined
            end,
            binary_to_list(binary:encode_hex(RawPayload))
        ]
    ),

    % Add SSH binary packet format with padding
    MinPadding = 4,
    % 5 = 4 (length field) + 1 (padding length field)
    BaseLength = byte_size(RawPayload) + 5,
    PaddingLength = MinPadding + (8 - (BaseLength + MinPadding) rem 8),
    Padding = crypto:strong_rand_bytes(PaddingLength),
    PacketLen = byte_size(RawPayload) + PaddingLength + 1,

    % Create complete packet
    Packet =
        <<PacketLen:32/big, PaddingLength, RawPayload/binary, Padding/binary>>,

    % Log packet details
    io:format(
        "Debug: Created KEXINIT packet:~n"
        "  Total size: ~p bytes~n"
        "  Raw payload size: ~p bytes~n"
        "  Padding size: ~p bytes~n",
        [
            byte_size(Packet),
            byte_size(RawPayload),
            PaddingLength
        ]
    ),

    % Return both the complete packet and the raw payload
    {Packet, RawPayload}.

negotiate_algorithm(ClientAlgs, ServerAlgs) ->
    ClientList = string:tokens(ClientAlgs, ","),
    ServerList = string:tokens(ServerAlgs, ","),
    negotiate_algorithm(ClientList, ServerList, []).

negotiate_algorithm([], _, []) ->
    throw({error, no_matching_algorithm});
negotiate_algorithm([], _, [First | _]) ->
    First;
negotiate_algorithm([Alg | Rest], ServerList, Acc) ->
    case lists:member(Alg, ServerList) of
        true -> negotiate_algorithm([], [], [Alg | Acc]);
        false -> negotiate_algorithm(Rest, ServerList, Acc)
    end.

receive_kex_dh_reply(Socket, Conn) ->
    io:format(
        "Debug: Waiting for server's key exchange messages~n"
        "  Current algorithms:~n"
        "    KEX: ~p~n"
        "    Host Key: ~p~n",
        [
            Conn#ssh_conn.kex_algorithm,
            Conn#ssh_conn.host_key_algorithm
        ]
    ),

    case gen_tcp:recv(Socket, 4, 5000) of
        {ok, <<PacketLen:32/big>>} ->
            io:format(
                "Debug: Received packet header:~n"
                "  Packet length: ~p bytes~n",
                [PacketLen]
            ),
            case gen_tcp:recv(Socket, PacketLen, 5000) of
                {ok, <<PaddingLen, PayloadAndPadding/binary>>} ->
                    PayloadLen = PacketLen - PaddingLen - 1,
                    <<Payload:PayloadLen/binary, _Padding/binary>> =
                        PayloadAndPadding,
                    ?dbg(" Got payload of length ~p: ~p~n", [
                        PayloadLen, Payload
                    ]),
                    case Payload of
                        <<?SSH_MSG_KEXINIT, Cookie:16/bytes, Rest/binary>> ->
                            io:format(
                                "Debug: Received server KEXINIT:~n"
                                "  Cookie: ~s~n"
                                "  Rest size: ~p bytes~n"
                                "  Full payload hex:~n~s~n",
                                [
                                    binary_to_list(binary:encode_hex(Cookie)),
                                    byte_size(Rest),
                                    binary_to_list(binary:encode_hex(Rest))
                                ]
                            ),
                            % Try to extract the required name-list fields, allowing trailing data
                            % According to RFC 4253 Section 7.1, decode exactly KEXINIT_NAMELIST_COUNT name-lists
                            case
                                decode_strings(
                                    Rest, [], ?KEXINIT_NAMELIST_COUNT
                                )
                            of
                                {ok,
                                    [
                                        KeyExch,
                                        HostKeys,
                                        CiphersS2C,
                                        CiphersC2S,
                                        MacsS2C,
                                        MacsC2S
                                        | _
                                    ] = NameLists,
                                    RemainingData} when
                                    length(NameLists) >= ?KEXINIT_NAMELIST_COUNT
                                ->
                                    io:format(
                                        "Debug: Successfully decoded all ~p name-lists~n"
                                        "  Remaining data size: ~p bytes~n"
                                        "  Remaining data hex:~n~s~n",
                                        [
                                            ?KEXINIT_NAMELIST_COUNT,
                                            byte_size(RemainingData),
                                            binary_to_list(
                                                binary:encode_hex(RemainingData)
                                            )
                                        ]
                                    ),
                                    io:format(
                                        "Debug: Server algorithm lists:~n"
                                        "  Key Exchange:     ~s~n"
                                        "  Host Keys:        ~s~n"
                                        "  Ciphers (S->C):   ~s~n"
                                        "  Ciphers (C->S):   ~s~n"
                                        "  MACs (S->C):      ~s~n"
                                        "  MACs (C->S):      ~s~n",
                                        [
                                            KeyExch,
                                            HostKeys,
                                            CiphersS2C,
                                            CiphersC2S,
                                            MacsS2C,
                                            MacsC2S
                                        ]
                                    ),

                                    % Negotiate algorithms
                                    KexAlg = negotiate_algorithm(
                                        "curve25519-sha256,ecdh-sha2-nistp256,diffie-hellman-group16-sha512,diffie-hellman-group14-sha256",
                                        binary_to_list(KeyExch)
                                    ),
                                    HostKeyAlg = negotiate_algorithm(
                                        "rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256,ssh-ed25519",
                                        binary_to_list(HostKeys)
                                    ),

                                    io:format(
                                        "Debug: Algorithm negotiation results:~n"
                                        "  Selected KEX:      ~s~n"
                                        "  Selected Host Key: ~s~n",
                                        [KexAlg, HostKeyAlg]
                                    ),

                                    % Store negotiated algorithms and raw KEXINIT
                                    NewConn = Conn#ssh_conn{
                                        kex_algorithm = list_to_binary(KexAlg),
                                        host_key_algorithm = list_to_binary(
                                            HostKeyAlg
                                        ),
                                        % Store complete KEXINIT payload
                                        server_kexinit = Payload
                                    },

                                    io:format(
                                        "Debug: Stored server KEXINIT:~n"
                                        "  Raw payload size: ~p bytes~n"
                                        "  Full hex dump:~n~s~n",
                                        [
                                            byte_size(Payload),
                                            binary_to_list(
                                                binary:encode_hex(Payload)
                                            )
                                        ]
                                    ),

                                    put(current_conn, NewConn),
                                    receive_kex_dh_reply(Socket, NewConn);
                                Error ->
                                    io:format(
                                        "Debug: Failed to decode server KEXINIT strings: ~p~n"
                                        "  Expected ~p name-list fields~n"
                                        "  Raw data hex dump:~n~s~n",
                                        [
                                            Error,
                                            ?KEXINIT_NAMELIST_COUNT,
                                            binary_to_list(
                                                binary:encode_hex(Rest)
                                            )
                                        ]
                                    ),
                                    {error, algorithm_negotiation_failed}
                            end;
                        <<?SSH_MSG_KEXDH_REPLY, Rest/binary>> ->
                            ?dbg(" Received KEXDH_REPLY message~n", []),
                            case decode_strings(Rest) of
                                {ok, [HostKey, PubKey, Signature]} ->
                                    % Log host key details
                                    case decode_strings(HostKey) of
                                        {ok, [KeyType | KeyParts]} ->
                                            io:format(
                                                "Debug: Server host key:~n"
                                                "  Type: ~s~n"
                                                "  Size: ~p bytes~n"
                                                "  Components: ~p parts~n"
                                                "  Full hex dump:~n~s~n",
                                                [
                                                    KeyType,
                                                    byte_size(HostKey),
                                                    length(KeyParts),
                                                    binary_to_list(
                                                        binary:encode_hex(
                                                            HostKey
                                                        )
                                                    )
                                                ]
                                            );
                                        KeyError ->
                                            io:format(
                                                "Debug: Failed to decode host key: ~p~n",
                                                [KeyError]
                                            )
                                    end,

                                    % Log DH public key details
                                    io:format(
                                        "Debug: Server DH public key:~n"
                                        "  Size: ~p bytes~n"
                                        "  Hex dump:~n~s~n",
                                        [
                                            byte_size(PubKey),
                                            binary_to_list(
                                                binary:encode_hex(PubKey)
                                            )
                                        ]
                                    ),

                                    % Log signature details
                                    case decode_strings(Signature) of
                                        {ok, [SigType | SigParts]} ->
                                            io:format(
                                                "Debug: Server signature:~n"
                                                "  Type: ~s~n"
                                                "  Size: ~p bytes~n"
                                                "  Components: ~p parts~n"
                                                "  Full hex dump:~n~s~n",
                                                [
                                                    SigType,
                                                    byte_size(Signature),
                                                    length(SigParts),
                                                    binary_to_list(
                                                        binary:encode_hex(
                                                            Signature
                                                        )
                                                    )
                                                ]
                                            );
                                        SigError ->
                                            io:format(
                                                "Debug: Failed to decode signature: ~p~n",
                                                [SigError]
                                            )
                                    end,

                                    % Get negotiated connection state
                                    NegotiatedConn =
                                        case get(current_conn) of
                                            undefined ->
                                                io:format(
                                                    "Debug: Warning - No saved connection state, using initial state~n"
                                                ),
                                                Conn;
                                            SavedConn ->
                                                io:format(
                                                    "Debug: Using negotiated connection state:~n"
                                                    "  KEX Algorithm: ~p~n"
                                                    "  Host Key Algorithm: ~p~n",
                                                    [
                                                        SavedConn#ssh_conn.kex_algorithm,
                                                        SavedConn#ssh_conn.host_key_algorithm
                                                    ]
                                                ),
                                                SavedConn
                                        end,

                                    {ok, PubKey, HostKey, Signature,
                                        NegotiatedConn};
                                Error ->
                                    {error, {decode_failed, Error}}
                            end;
                        Other ->
                            io:format(
                                "Debug: Got unexpected message type: ~p~n"
                                "Message hex dump:~n~s~n",
                                [
                                    Other,
                                    binary_to_list(binary:encode_hex(Other))
                                ]
                            ),
                            {error, {unexpected_message, Other}}
                    end;
                {error, Reason} ->
                    {error, {packet_read_failed, Reason}}
            end;
        {error, Reason} ->
            {error, {packet_length_read_failed, Reason}}
    end.

decode_strings(Data) ->
    decode_strings(Data, [], -1).

decode_strings(Data, Acc, Count) ->
    try
        decode_strings_impl(Data, Acc, Count)
    catch
        error:Reason ->
            io:format(
                "Debug: String decoding failed:~n"
                "  Reason: ~p~n"
                "  Data size: ~p bytes~n"
                "  Data hex dump:~n~s~n",
                [
                    Reason,
                    byte_size(Data),
                    binary_to_list(binary:encode_hex(Data))
                ]
            ),
            {error, {malformed_data, Reason}}
    end.

decode_strings_impl(Data, Acc, 0) ->
    {ok, lists:reverse(Acc), Data};
decode_strings_impl(<<>>, Acc, _) ->
    {ok, lists:reverse(Acc)};
decode_strings_impl(Data, Acc, Count) ->
    case Data of
        <<Len:32/big, Rest/binary>> when byte_size(Rest) >= Len ->
            <<String:Len/binary, NewRest/binary>> = Rest,
            NewCount =
                if
                    Count > 0 -> Count - 1;
                    true -> Count
                end,
            decode_strings_impl(NewRest, [String | Acc], NewCount);
        <<Len:32/big, Rest/binary>> ->
            io:format(
                "Debug: String length field (~p) larger than remaining data (~p bytes)~n"
                "Hex dump of remaining data:~n~s~n",
                [
                    Len,
                    byte_size(Rest),
                    binary_to_list(binary:encode_hex(Rest))
                ]
            ),
            {error, {insufficient_data, Len, byte_size(Rest)}};
        Other when byte_size(Other) < 4 ->
            case Count of
                0 ->
                    {ok, lists:reverse(Acc), Other};
                _ ->
                    io:format(
                        "Debug: Incomplete string length field:~n"
                        "  Remaining size: ~p bytes~n"
                        "  Hex dump:~n~s~n",
                        [
                            byte_size(Other),
                            binary_to_list(binary:encode_hex(Other))
                        ]
                    ),
                    {error, {malformed_data, truncated}}
            end;
        Other ->
            io:format(
                "Debug: Malformed string data:~n"
                "  Remaining size: ~p bytes~n"
                "  Hex dump:~n~s~n",
                [
                    byte_size(Other),
                    binary_to_list(binary:encode_hex(Other))
                ]
            ),
            {error, {malformed_data, truncated}}
    end.

compute_hash(Conn, _Cookie, HostKey, ClientPubKey, ServerPubKey, SharedSecret) ->
    % According to RFC 4253 Section 8, the exchange hash H is computed as the hash of:
    % V_C || V_S || I_C || I_S || K_S || e || f || K
    % where || denotes concatenation.

    % V_C, client version string (CR and NL excluded)
    ClientVersion = list_to_binary(string:trim(Conn#ssh_conn.version)),
    % V_S, server version string (CR and NL excluded)
    ServerVersion = list_to_binary(string:trim(Conn#ssh_conn.server_version)),

    % I_C, client's KEXINIT payload - use raw message WITHOUT encoding
    ClientKexInit = Conn#ssh_conn.client_kexinit,

    % I_S, server's KEXINIT payload - use raw message WITHOUT encoding
    ServerKexInit = Conn#ssh_conn.server_kexinit,

    % K_S, server host key
    EncodedHostKey = encode_string(HostKey),

    % e, client's ephemeral public key
    EncodedClientPubKey = encode_mpint(ClientPubKey),

    % f, server's ephemeral public key
    EncodedServerPubKey = encode_mpint(ServerPubKey),

    % K, shared secret
    EncodedSharedSecret = encode_mpint(SharedSecret),

    % Detailed logging of exchange hash components
    io:format(
        "Debug: Exchange hash components:~n"
        "  V_C (client version): ~p~n"
        "    Length: ~p bytes~n"
        "    Hex: ~s~n~n"
        "  V_S (server version): ~p~n"
        "    Length: ~p bytes~n"
        "    Hex: ~s~n~n"
        "  I_C (client KEXINIT): ~p bytes~n"
        "    First byte: ~p~n"
        "    Hex: ~s~n~n"
        "  I_S (server KEXINIT): ~p bytes~n"
        "    First byte: ~p~n"
        "    Hex: ~s~n~n"
        "  K_S (host key): ~p bytes~n"
        "    Hex: ~s~n~n"
        "  e (client ephemeral): ~p bytes~n"
        "    Hex: ~s~n~n"
        "  f (server ephemeral): ~p bytes~n"
        "    Hex: ~s~n~n"
        "  K (shared secret): ~p bytes~n"
        "    Hex: ~s~n",
        [
            ClientVersion,
            byte_size(ClientVersion),
            binary_to_list(binary:encode_hex(ClientVersion)),
            ServerVersion,
            byte_size(ServerVersion),
            binary_to_list(binary:encode_hex(ServerVersion)),
            byte_size(ClientKexInit),
            case ClientKexInit of
                <<FirstByte:8, _/binary>> -> FirstByte;
                _ -> undefined
            end,
            binary_to_list(binary:encode_hex(ClientKexInit)),
            byte_size(ServerKexInit),
            case ServerKexInit of
                <<FirstByte:8, _/binary>> -> FirstByte;
                _ -> undefined
            end,
            binary_to_list(binary:encode_hex(ServerKexInit)),
            byte_size(EncodedHostKey),
            binary_to_list(binary:encode_hex(EncodedHostKey)),
            byte_size(EncodedClientPubKey),
            binary_to_list(binary:encode_hex(EncodedClientPubKey)),
            byte_size(EncodedServerPubKey),
            binary_to_list(binary:encode_hex(EncodedServerPubKey)),
            byte_size(EncodedSharedSecret),
            binary_to_list(binary:encode_hex(EncodedSharedSecret))
        ]
    ),

    % Concatenate all components for hash computation
    HashData =
        <<ClientVersion/binary, ServerVersion/binary,
            % Raw KEXINIT without encoding
            ClientKexInit/binary,
            % Raw KEXINIT without encoding
            ServerKexInit/binary, EncodedHostKey/binary,
            EncodedClientPubKey/binary, EncodedServerPubKey/binary,
            EncodedSharedSecret/binary>>,

    io:format(
        "Debug: Final exchange hash data:~n"
        "  Total length: ~p bytes~n"
        "  Hex dump:~n~s~n",
        [
            byte_size(HashData),
            binary_to_list(binary:encode_hex(HashData))
        ]
    ),

    crypto:hash(sha256, HashData).

verify_signature(HostKey, SessionId, Signature) ->
    ?dbg(
        "Beginning signature verification~n"
        "  Session ID size: ~p bytes~n"
        "  Session ID (hex): ~s~n"
        "  Signature size: ~p bytes~n"
        "  Signature (hex): ~s~n",
        [
            byte_size(SessionId),
            binary_to_list(binary:encode_hex(SessionId)),
            byte_size(Signature),
            binary_to_list(binary:encode_hex(Signature))
        ]
    ),

    try
        % Log the host key details
        case decode_strings(HostKey) of
            {ok, [Type | RestHostKey]} ->
                io:format(
                    "Debug: Host key details:~n"
                    "  Algorithm: ~p~n"
                    "  Raw key components (hex):~n",
                    [Type]
                ),
                % Log all key components
                lists:foreach(
                    fun(Component) ->
                        io:format("    ~s~n", [
                            binary_to_list(binary:encode_hex(Component))
                        ])
                    end,
                    RestHostKey
                ),
                % Log SSH key format info
                case try_decode_key_info(HostKey) of
                    ok ->
                        ok;
                    {error, DecodeError} ->
                        io:format(
                            "Debug: Failed to decode SSH key structure: ~p~n", [
                                DecodeError
                            ]
                        )
                end;
            DecodeError ->
                ?dbg(" Failed to decode host key: ~p~n", [DecodeError]),
                io:format(
                    "Debug: Raw host key dump:~n~s~n",
                    [binary_to_list(binary:encode_hex(HostKey))]
                )
        end,

        % Log the signature details
        case decode_strings(Signature) of
            {ok, [SigType | RestSig]} ->
                io:format(
                    "Debug: Signature details:~n"
                    "  Algorithm: ~p~n"
                    "  Raw signature components (hex):~n",
                    [SigType]
                ),
                lists:foreach(
                    fun(Component) ->
                        io:format("    ~s~n", [
                            binary_to_list(binary:encode_hex(Component))
                        ])
                    end,
                    RestSig
                );
            SigError ->
                ?dbg(" Failed to decode signature: ~p~n", [SigError])
        end,

        % Improved key type handling
        case decode_strings(HostKey) of
            % Handle ECDSA keys
            {ok, [<<"ecdsa-sha2-nistp256">>, _Curve, KeyBlob]} ->
                ?dbg(" Found ECDSA key~n", []),
                case decode_strings(Signature) of
                    {ok, [<<"ecdsa-sha2-nistp256">>, SigBlob]} ->
                        PubKey = crypto:ec_key_parse(
                            <<"EC-PUB">>, secp256r1, KeyBlob
                        ),
                        case
                            crypto:verify(ecdsa, sha256, SessionId, SigBlob, [
                                PubKey
                            ])
                        of
                            true -> ok;
                            false -> {error, signature_mismatch}
                        end;
                    _ ->
                        {error, invalid_signature_format}
                end;
            % Handle ED25519 keys
            {ok, [<<"ssh-ed25519">>, KeyBlob]} ->
                case decode_strings(Signature) of
                    {ok, [<<"ssh-ed25519">>, SigBlob]} ->
                        case
                            crypto:verify(
                                eddsa, none, SessionId, SigBlob, [KeyBlob], [
                                    ed25519
                                ]
                            )
                        of
                            true -> ok;
                            false -> {error, signature_mismatch}
                        end;
                    _ ->
                        {error, invalid_signature_format}
                end;
            % Handle RSA keys (all variants)
            {ok, [KeyType | _KeyBlob]} when
                KeyType =:= <<"ssh-rsa">>;
                KeyType =:= <<"rsa-sha2-512">>;
                KeyType =:= <<"rsa-sha2-256">>
            ->
                ?dbg(" Found RSA key type: ~p~n", [KeyType]),
                handle_rsa_key(HostKey, SessionId, Signature);
            % Unsupported key type
            {ok, [KeyType | _]} ->
                ?dbg(" Unsupported key type: ~p~n", [KeyType]),
                {error, {unsupported_key_type, KeyType}};
            % Error decoding key
            Error ->
                ?dbg(" Error decoding host key: ~p~n", [Error]),
                {error, {invalid_host_key, Error}}
        end
    catch
        error:{badmatch, Reason} ->
            ?dbg(" Signature verification failed with badmatch: ~p~n", [Reason]),
            {error, {signature_verification_failed, {badmatch, Reason}}};
        error:badarg ->
            ?dbg(" Signature verification failed with badarg~n", []),
            {error, {signature_verification_failed, badarg}};
        error:function_clause ->
            ?dbg(" Signature verification failed with function_clause~n", []),
            {error, {signature_verification_failed, function_clause}};
        error:Why ->
            ?dbg(" Signature verification failed with error: ~p~n", [Why]),
            {error, {signature_verification_failed, Why}};
        exit:Why ->
            ?dbg(" Signature verification failed with exit: ~p~n", [Why]),
            {error, {signature_verification_failed, Why}}
    end.

handle_rsa_key(HostKey, SessionId, Signature) ->
    case ssh_file:decode(HostKey, ssh2_pubkey) of
        #'RSAPublicKey'{} = PubKey ->
            ?dbg(" Successfully decoded RSA public key~n", []),
            case decode_strings(Signature) of
                {ok, [<<"rsa-sha2-512">>, RsaSignature]} ->
                    ?dbg(" Found rsa-sha2-512 signature~n", []),
                    try_verify_rsa(PubKey, SessionId, RsaSignature, sha512);
                {ok, [<<"rsa-sha2-256">>, RsaSignature]} ->
                    ?dbg(" Found rsa-sha2-256 signature~n", []),
                    try_verify_rsa(PubKey, SessionId, RsaSignature, sha256);
                {ok, [<<"ssh-rsa">>, RsaSignature]} ->
                    ?dbg(" Found ssh-rsa signature~n", []),
                    try_verify_rsa(PubKey, SessionId, RsaSignature, sha1);
                {ok, [UnknownSigType, _]} ->
                    ?dbg(" Unknown signature type: ~p~n", [UnknownSigType]),
                    {error, {unsupported_signature_type, UnknownSigType}};
                Error ->
                    ?dbg(" Failed to decode signature: ~p~n", [Error]),
                    {error, {invalid_signature_format, Error}}
            end;
        DecodedKey ->
            ?dbg(" Failed to decode RSA key: ~p~n", [DecodedKey]),
            {error, {invalid_rsa_key, DecodedKey}}
    end.

try_verify_rsa(PubKey, SessionId, Signature, HashType) ->
    ?dbg(
        " Attempting RSA verification with public_key module~n"
        "  HashType=~p~n"
        "  SessionId size: ~p bytes~n"
        "  Signature size: ~p bytes~n",
        [HashType, byte_size(SessionId), byte_size(Signature)]
    ),

    DigestType =
        case HashType of
            sha512 -> sha512;
            sha256 -> sha256;
            sha1 -> sha
        end,

    try
        case public_key:verify(SessionId, DigestType, Signature, PubKey) of
            true ->
                ?dbg(" RSA verification successful with ~p~n", [HashType]),
                ok;
            false ->
                ?dbg(" RSA verification failed with ~p~n", [HashType]),
                {error, {signature_mismatch, HashType}}
        end
    catch
        error:Error ->
            ?dbg(" RSA verification failed with error: ~p~n", [Error]),
            {error, {verification_error, Error}}
    end.

derive_keys(SharedSecret, SessionId) ->
    % Derive encryption and MAC keys using SHA-256 as per RFC 4253 section 7.2
    FullEncKey = crypto:hash(sha256, [SharedSecret, SessionId, <<"A">>]),
    FullDecKey = crypto:hash(sha256, [SharedSecret, SessionId, <<"B">>]),
    EncMacKey = crypto:hash(sha256, [SharedSecret, SessionId, <<"C">>]),
    DecMacKey = crypto:hash(sha256, [SharedSecret, SessionId, <<"D">>]),

    % Truncate encryption keys to 16 bytes for AES-128-CTR
    <<EncKey:16/binary, _/binary>> = FullEncKey,
    <<DecKey:16/binary, _/binary>> = FullDecKey,

    % Return truncated encryption keys (16 bytes) and full MAC keys (32 bytes)
    {EncKey, DecKey, EncMacKey, DecMacKey}.

%% Version String Validation
validate_version_string(VersionStr) ->
    case string:prefix(VersionStr, "SSH-2.0-") of
        nomatch -> {error, unsupported_version};
        _Rest -> {ok, #{version => "2.0"}}
    end.

%% Authentication
authenticate(Conn = #ssh_conn{socket = Socket}, Username, Password) ->
    ?dbg(
        "authenticate/3:~n"
        "  Username: ~s~n"
        "  Password: ~s~n",
        [Username, Password]
    ),
    AuthRequest = create_auth_request(Username, Password),
    {AuthRequestEnc, NewConn} = encrypt_packet(AuthRequest, Conn),

    case gen_tcp:send(Socket, AuthRequestEnc) of
        ok ->
            ?dbg("Sent authentication request: ~p~n", [AuthRequestEnc]),
            case receive_auth_response(NewConn) of
                {ok, success} ->
                    {ok, NewConn#ssh_conn{authenticated = true}};
                {ok, failure} ->
                    {error, authentication_failed};
                Error ->
                    Error
            end;
        {error, Reason} ->
            ?dbg("Failed to send authentication request: ~p~n", [Reason]),
            {error, {auth_send_failed, Reason}}
    end.

create_auth_request(Username, Password) ->
    <<
        ?SSH_MSG_USERAUTH_REQUEST,
        (encode_string(Username))/binary,
        (encode_string("ssh-connection"))/binary,
        (encode_string("password"))/binary,
        % No old password
        0,
        (encode_string(Password))/binary
    >>.

receive_auth_response(Conn = #ssh_conn{socket = Socket}) ->
    case gen_tcp:recv(Socket, 0, 5000) of
        {ok, EncryptedPacket} ->
            case decrypt_packet(EncryptedPacket, Conn) of
                {ok, <<?SSH_MSG_USERAUTH_SUCCESS, _/binary>>} ->
                    {ok, success};
                {ok, <<?SSH_MSG_USERAUTH_FAILURE, _/binary>>} ->
                    {ok, failure};
                {error, Reason} ->
                    {error, {auth_response_decrypt_failed, Reason}}
            end;
        {error, Reason} ->
            {error, {auth_response_failed, Reason}}
    end.

%% Encryption/Decryption
encrypt_packet(
    Packet,
    Conn = #ssh_conn{
        encrypt_key = Key, encrypt_mac_key = MacKey, encrypt_seq = Seq
    }
) ->
    % Ensure packet length is multiple of block size (16 bytes for AES)
    PaddingLength = 16 - (byte_size(Packet) rem 16),
    Padding = crypto:strong_rand_bytes(PaddingLength),

    % Create packet with length and padding

    % +1 for padding_length field
    PacketLen = byte_size(Packet) + PaddingLength + 1,
    FullPacket =
        <<PacketLen:32/big, PaddingLength, Packet/binary, Padding/binary>>,

    % Generate CTR IV using sequence number
    IV = <<Seq:64/big, 0:64/big>>,

    % Encrypt with AES-CTR
    EncryptedData = crypto:crypto_one_time(
        aes_128_ctr, Key, IV, FullPacket, true
    ),

    % Generate HMAC over sequence number and encrypted data
    Mac = crypto:mac(
        hmac, sha256, MacKey, <<Seq:32/big, EncryptedData/binary>>
    ),

    % Update sequence number for next packet
    NewConn = Conn#ssh_conn{encrypt_seq = (Seq + 1) band 16#ffffffff},

    % Return final packet and updated connection state
    {<<EncryptedData/binary, Mac/binary>>, NewConn}.

decrypt_packet(
    Packet,
    Conn = #ssh_conn{
        decrypt_key = Key, decrypt_mac_key = MacKey, decrypt_seq = Seq
    }
) ->
    try
        % Split packet into encrypted data and MAC

        % SHA256 produces 32-byte MAC
        MacSize = 32,
        DataSize = byte_size(Packet) - MacSize,
        <<EncryptedData:DataSize/binary, ReceivedMac:MacSize/binary>> = Packet,

        % Verify MAC
        ExpectedMac = crypto:mac(
            hmac, sha256, MacKey, <<Seq:32/big, EncryptedData/binary>>
        ),
        case crypto:secure_compare(ReceivedMac, ExpectedMac) of
            true ->
                % Generate CTR IV using sequence number
                IV = <<Seq:64/big, 0:64/big>>,

                % Decrypt with AES-CTR
                DecryptedData = crypto:crypto_one_time(
                    aes_128_ctr, Key, IV, EncryptedData, false
                ),

                % Parse packet format
                <<PacketLen:32/big, PaddingLength, Payload:PacketLen/binary,
                    _Padding/binary>> = DecryptedData,

                % Extract actual payload (without padding)
                PayloadLen = PacketLen - PaddingLength - 1,
                <<ActualPayload:PayloadLen/binary, _/binary>> = Payload,

                % Update sequence number for next packet
                NewConn = Conn#ssh_conn{
                    decrypt_seq = (Seq + 1) band 16#ffffffff
                },

                % Return decrypted payload and updated connection state
                {ok, ActualPayload, NewConn};
            false ->
                {error, invalid_mac}
        end
    catch
        error:Reason ->
            {error, {decrypt_failed, Reason}}
    end.

%% Channel Operations
open_channel(Conn = #ssh_conn{socket = Socket, authenticated = true}) ->
    ChannelId = generate_channel_id(),
    WindowSize = 32768,
    MaxPacketSize = 32768,

    ChannelOpen = <<
        ?SSH_MSG_CHANNEL_OPEN,
        (encode_string(?CHANNEL_TYPE_SESSION))/binary,
        ChannelId:32/big,
        WindowSize:32/big,
        MaxPacketSize:32/big
    >>,

    {ChannelOpenEnc, Conn2} = encrypt_packet(ChannelOpen, Conn),
    case gen_tcp:send(Socket, ChannelOpenEnc) of
        ok ->
            case receive_channel_response(Socket, ChannelId, Conn2) of
                % Store RemoteId if needed later
                {ok, _RemoteId, NewConn} ->
                    {ok, ChannelId, NewConn};
                Error ->
                    Error
            end;
        {error, SendError} ->
            {error, {send_failed, SendError}}
    end;
open_channel(_) ->
    {error, not_authenticated}.

receive_channel_response(Socket, LocalId, Conn) ->
    case gen_tcp:recv(Socket, 0, 5000) of
        {ok, EncryptedPacket} ->
            case decrypt_packet(EncryptedPacket, Conn) of
                {ok,
                    <<?SSH_MSG_CHANNEL_OPEN_CONFIRMATION, LocalId:32/big,
                        RemoteId:32/big, _WindowSize:32/big,
                        _MaxPacketSize:32/big, _/binary>>,
                    NewConn} ->
                    {ok, RemoteId, NewConn};
                {error, Reason} ->
                    {error, {channel_open_failed, Reason}}
            end;
        {error, Reason} ->
            {error, {recv_failed, Reason}}
    end.

%% Execute Command
execute_command(Conn = #ssh_conn{socket = Socket}, ChannelId, Command) ->
    ExecRequest = <<
        ?SSH_MSG_CHANNEL_REQUEST,
        ChannelId:32/big,
        (encode_string(?CHANNEL_REQUEST_EXEC))/binary,
        % Want reply
        1,
        (encode_string(Command))/binary
    >>,

    {ExecRequestEnc, Conn2} = encrypt_packet(ExecRequest, Conn),
    case gen_tcp:send(Socket, ExecRequestEnc) of
        ok ->
            collect_output(Conn2, ChannelId, []);
        {error, SendError} ->
            {error, {send_failed, SendError}}
    end.

collect_output(Conn = #ssh_conn{socket = Socket}, ChannelId, AccOutput) ->
    case gen_tcp:recv(Socket, 0, 5000) of
        {ok, EncryptedPacket} ->
            case decrypt_packet(EncryptedPacket, Conn) of
                {ok,
                    <<?SSH_MSG_CHANNEL_DATA, ChannelId:32/big, DataLen:32/big,
                        Data:DataLen/binary, _/binary>>,
                    NewConn} ->
                    collect_output(NewConn, ChannelId, [Data | AccOutput]);
                {ok, <<?SSH_MSG_CHANNEL_EOF, ChannelId:32/big, _/binary>>, _} ->
                    {ok, list_to_binary(lists:reverse(AccOutput))};
                {ok, <<?SSH_MSG_CHANNEL_CLOSE, ChannelId:32/big, _/binary>>, _} ->
                    {ok, list_to_binary(lists:reverse(AccOutput))};
                {error, Reason} ->
                    {error, {decrypt_failed, Reason}}
            end;
        {error, Reason} ->
            {error, {recv_failed, Reason}}
    end.

%% Utility Functions
encode_mpint(Int) when is_binary(Int) ->
    case Int of
        <<0, Rest/binary>> when Rest =/= <<>> ->
            % Remove leading zeros except single zero
            encode_mpint(Rest);
        <<FirstByte, _/binary>> when FirstByte >= 16#80 ->
            % Add zero byte if first bit is 1
            <<(byte_size(Int) + 1):32/big, 0, Int/binary>>;
        _ ->
            <<(byte_size(Int)):32/big, Int/binary>>
    end.

encode_string(Str) when is_list(Str) ->
    encode_string(list_to_binary(Str));
encode_string(StrBin) when is_binary(StrBin) ->
    <<(byte_size(StrBin)):32/big, StrBin/binary>>.

generate_channel_id() ->
    rand:uniform(16#FFFFFFFF).

%% Connection Closure
close_connection(#ssh_conn{socket = Socket}) ->
    gen_tcp:close(Socket).

%% Helper Functions
try_decode_key_info(HostKey) ->
    try
        case ssh_file:decode(HostKey, ssh2_pubkey) of
            [#'RSAPublicKey'{modulus = N, publicExponent = E} | _] ->
                io:format(
                    "Debug: RSA key details:~n"
                    "  Modulus size: ~p bits~n"
                    "  Public exponent: ~p~n",
                    [bit_size(crypto:int_to_bin(N)), E]
                ),
                ok;
            [{'ECPoint', Point} | _] ->
                io:format(
                    "Debug: EC key details:~n"
                    "  Point size: ~p bytes~n",
                    [byte_size(Point)]
                ),
                ok;
            Other ->
                ?dbg(" Unknown key structure: ~p~n", [Other]),
                ok
        end
    catch
        error:DecodeError ->
            {error, DecodeError}
    end.
