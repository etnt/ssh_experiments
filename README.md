# SSH Experiments
> Just some experiments with the Erlang SSH library

## Jumphost

The "jumphost" concept, also known as a "jump server" or "bastion host," 
is a fundamental security practice in network administration.

Jumphosts act as a bridge between different security zones,
providing a single point of entry and control.

SSH's tunneling capabilities makes it an ideal protocol for securely
accessing remote devices through an intermediary server.

The following Erlang code examples explores how to implement establishing a
secure SSH connection to the jumphost, and then using that connection
to forward traffic to the target device behind it.

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

## JumpHost via open_port

As I understand it, the `-J` switch in the `ssh` command is not directly implemented at the base SSH protocol level described in RFC 4254. Instead, the -J switch is a feature implemented by the OpenSSH client (and potentially other SSH clients). It provides a convenient way to establish a connection to a destination host by first hopping through one or more intermediary SSH servers (the jumphosts).

The Erlang SSH library doesn't seem to have a direct -J function, it provides the underlying mechanisms (SSH connections and TCP forwarding) that would allow you to build this functionality yourself in Erlang, but it would probably require a substantial effort.

So an alternative solution is to run the ssh command via an Erlang port. However, the ssh command expects a terminal when it prompts for passwords. Hence, we use a simple pty wrapper (ssh_pty_wrapper.c). Compile it as:

``` bash
cc -o ssh_pty_wrapper ssh_pty_wrapper.c -lutil
```

Example:

``` erlang
1>  ssh_tunnel:netconf_jump_test("hedlund", [{user,"tobbe"},{user_password,"qwe123"}], "127.0.0.1", 2022, "admin", "admin").
<pw1>: sending JumpPassword: qwe123
<pw2>: <<"\r\n">>
<pw2>: sending RemotePassword: admin
<run>: <<"\r\n">>
<run>: <<"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n<hello xmlns=\"urn:iet.....snip....
```
 
## SSH Agent Forwarding

The `ssh_agent_forward` module demonstrates how to establish SSH connections through
a jump host to access Netconf services on remote devices.

Since Netconf (per default) runs over SSH we need to do something similar to our other
example below that uses Netcat; here however we are using the `ssh` command instead.
Top be able to provide a password to the remote device we also use the `sshpass` command. 

### Usage

```erlang
%% Connect to a Netconf service with explicit password authentication
ssh_agent_forward:netconf_sshpass_test("127.0.0.1",2022,"hedlund",
    [{user,"tobbe"},{user_dir,"/home/tobbe/.ssh/pwless/"}], "admin", "admin").

<?xml version="1.0" encoding="UTF-8"?>
<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
<capabilities>
<capability>urn:ietf:params:netconf:base:1.0</c....snip....
```

Another (untested) possibility is to use `-A` (Agent Forwarding) switch in the
issued `ssh` command on the Jumphost. Thus, key-authentication (i.e no password)
would be possible. Note that this hasn't been tested since it wasn't supported by
the Netconf device used for testing.

This approach differs from the previous tunneling methods by:
1. Using nested SSH connections rather than port forwarding
2. Automatically connecting to the Netconf SSH subsystem
3. Supporting both agent forwarding (untested!) and password authentication (tested!)
4. Sending Netconf protocol messages directly through the established connection

Note that the password authentication method requires the `sshpass` utility to be installed on the jump host.


## SSH tunnel (using direct-tcpip message)
  
Instead of having to setup a Listen TCP socket to first
connect to before sending data to be forwarded at the remote end
(as in the example below), this code directly setup a SSH connection
and a 'direct-tcpip' channel to forward the request on the remote side.

```erlang
ssh_direct_tcpip_tunnel:restconf_test("127.0.0.1",9933,"127.0.0.1",8008,"hedlund",[{user,"tobbe"},{user_dir,"/home/tobbe/.ssh/pwless/"}]).
HTTP/1.1 200 OK
Date: Mon, 07 Apr 2025 11:23:12 GMT
Cache-Control: private, no-cache, must-revalidate, proxy-revalidate
Etag: W/"1743-611321-810071+xml"
Content-Type: application/yang-data+xml
Transfer-Encoding: chunked
...

100C
<data xmlns="urn:ietf:params:xml:ns:yang:ietf-restconf">
  <yang-library xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-library">
    <module-set>....snip...
```

Note that this code makes use of a, for internal use, exported function:
`ssh_connection:open_channel/4`.

Also note, as from the: https://datatracker.ietf.org/doc/html/rfc4254#page-18

* The `forwarded-tcpip` global request message is used when a party
    wishes that connections to a port on the other side be forwarded
    to the local side.

* The `direct-tcpip` channel open message may also be sent for ports
    for which no forwarding has been explicitly requested. The receiving
    side must decide whether to allow the forwarding.


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

Note that this also works for Netconf:

``` erlang
# We have a Netconf/SSH server running on port 2022 on the Target host.
{ok,Tunnel} = ssh_tcpip_tunnel:local("127.0.0.1",9933,"127.0.0.1",2022,"hedlund",[{user,"tobbe"},{user_dir,"/home/tobbe/.ssh/pwless/"}]).
```

```bash
# From the Local host we run:
$ netconf-console --host 127.0.0.1 --port 9933 --hello
<?xml version="1.0" encoding="UTF-8"?>
<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <capabilities>
    <capability>urn:ietf:params:netconf:base:1.0</capability>
    <capability>urn:ietf:params:netconf:base:1.1</capa.....snip...
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


