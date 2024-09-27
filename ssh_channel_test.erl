-module(ssh_channel_test).
-export([test/0]).

test() ->
    {ok, Connection} = ssh:connect("localhost", 22, []),  % Replace "localhost" with your SSH server address
    {ok, Channel1} = ssh_connection:session_channel(Connection, []),
    {ok, Channel2} = ssh_connection:session_channel(Connection, []),

    % Perform some operation on Channel1 (optional - uncomment and add your code)
    % ssh_connection:exec(Channel1, "ls -l", []), 

    ssh_connection:close(Channel1),

    % Check the status of Channel2
    case ssh_connection:status(Channel2) of
        {ok, open} ->
            io:format("Channel 2 is still open~n"),
            ssh_connection:close(Channel2);  % Close Channel2 explicitly
        {error, _Reason} ->
            io:format("Channel 2 is closed: ~p~n", [_Reason])
    end,

    ssh:close(Connection).
