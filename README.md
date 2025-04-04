# SSH Experiments
> Just some experiments with the Erlang SSH library

## Prepare password less SSH keys

Start by creating a password less SSH key pair and copy the public key
to the authorized keys of the `user@host` where we want to connect to:

```shell
mkdir -p  ~/.ssh/pwless
cd ~/.ssh/pwless

# Create the keys
ssh-keygen -t rsa -b 4096

# Set proper permission on the public key:
chmod 600 id_rsa.pub

# Copy the public key to the authorized keys of our target host
ssh-copy-id id_rsa tobbe@hedlund
```

## SSH tunnel (native Erlang, short and simple)

Here we make use of the `ssh:tcpip_tunnel_to_server/6` function,
which makes it almost too easy... :-)

``` erlang
{ok,Tunnel} = ssh_tcpip_tunnel:local("127.0.0.1",9933,"127.0.0.1",8008,"hedlund",[{user,"tobbe"},{user_dir,"/home/tobbe/.ssh/pwless/"}]).
```

Then we can use `curl` like this:

``` bash
curl -v -k -u admin:admin  'https://127.0.0.1:9933/restconf/data/'
```

Note that we run the request over SSL (https) which is then tunneled via
SSH to the Target.

Stop the tunnel:

```erlang
ok = ssh_tunnel:stop(Tunnel).
```

The Erlang code is very short and simple:

``` erlang
start_local_tunnel(LocalIp, LocalPort, RemoteIp, RemotePort, SshHost, SshOptions) ->
    {Host, Port} = parse_ssh_host(SshHost),
    try ssh:connect(Host, Port, SshOptions) of
        {ok, Connection} ->
            case ssh:tcpip_tunnel_to_server(Connection,
                                            LocalIp, LocalPort,
                                            RemoteIp, RemotePort,
                                            _Timeout = infinity)
            of
                {ok, _ListenPort} ->
                    wait_loop(Connection);
                Else ->
                    {error, Else}
            end;
        Error ->
            {error, {ssh_connect_failed, Error}}
    catch
        _:Error ->
            {error, {ssh_connect_failed, Error}}
    end.
```


## SSH Tunneling (native Erlang, using Netcat)

Here we setup a SSH tunnel without any particular support
from the remote SSH server. We do so by creating a SSH connection
to the remote server where we run the `netcat` command which will
relay the TCP traffic from our local Client to the Remote Target.

``` mermaid
flowchart LR
    Curl[Curl Client] <-->|Connect to 127.0.0.1:9933| LocalHost[LocalHost at 127.0.0.1:9933]
    LocalHost <-->|Forward via SSH Tunnel| RemoteHost[Remote SSH Server]
    RemoteHost <-->|Relay traffic | Netcat[Netcat]
    Netcat <-->|Relay traffic | Target[Target at 127.0.0.1:8889]
    
```

In the Erlang shell we can start it as:

``` erlang
{ok,Tunnel} = ssh_nc_tunnel:local("127.0.0.1",9933,"127.0.0.1",8889,"hedlund",[{user,"tobbe"},{user_dir,"/home/tobbe/.ssh/pwless/"}]).
```

Then we can use `curl` like this:

``` bash
curl -v -k -u admin:admin  'https://127.0.0.1:9933/restconf/data/'
```

Note that we run the request over SSL (https) which is then tunneled via
SSH to the Target.

Stop the tunnel:

```erlang
ok = ssh_tunnel:stop(Tunnel).
```



## SSH Tunneling (using the SSH command)

The `ssh_tunnel` module provides functionality to create SSH tunnels using system SSH commands.

### Usage

Start by creating a password less SSH key pair as shown above.

```erlang
% Start local port forwarding: local:9191 -> remote:8008) , 
% tunnel is setup to host: "hedlund" as user: "tobbe" using
% the identity (i.e private SSH key): "/home/tobbe/.ssh/pwless/id_rsa"
{ok, Tunnel} = ssh_tunnel:local("127.0.0.1",9191,"127.0.0.1",8008,"hedlund",[{user,"tobbe"},{identity,"/home/tobbe/.ssh/pwless/id_rsa"}]).
```

You can check that the tunnel is listening to the port you have specified:

``` bash
netstat -tlpn
```

Try to access the remote end point via the tunnel (make sure you have something running on the remote host...):

```shell
curl -is -u admin:admin http://127.0.0.1:9191/restconf/data
```

You can setup a reverse SSH tunnel similarly:

```erlang
% Start remote port forwarding (e.g. remote:9191 -> local:8008)
{ok, Tunnel} = ssh_tunnel:remote("127.0.0.1",8008,"127.0.0.1",9191,"hedlund",[{user,"tobbe"},{identity,"/home/tobbe/.ssh/pwless/id_rsa"}]).
```

Stop the tunnel:

```erlang
ok = ssh_tunnel:stop(Tunnel).
```

Options:
- `user` (required): SSH username
- `identity`: (required) Path to SSH identity file

Requirements:
- SSH server must be running on the target host
- SSH client must be installed locally
- Appropriate SSH keys/credentials must be configured

### Alternative: setup SSH as a SOCKS server

Setup the SSH/SOCKS server to listen on port: 1080

``` bash
 ssh -nNT -D 1080 -i ~/.ssh/hedlund_pwless tobbe@hedlund
```

Now we can access _anything_ on the inside, e.g:

``` bash
curl -u admin:admin --proxy socks5://127.0.0.1:1080 http://127.0.0.1:8008/restconf/data
```

## SSH Command Execution

The `ssh_exec` module provides functionality to execute remote commands and start remote shells over SSH.

### Usage

```erlang
% Execute a remote command
ssh_exec:exec("hedlund", 22, "tobbe", "id").

% Start a remote shell
ssh_exec:shell("hedlund", 22, [{user, "tobbe"}]).
```

The module handles SSH connection setup automatically, including starting required applications and managing SSH keys from the user's .ssh directory.

