# SSH Experiments
> Just some experiments with the Erlang SSH library

## SSH Tunneling

The `ssh_tunnel` module provides functionality to create SSH tunnels using system SSH commands.

### Usage

Start by creating a password less SSH key pair and copy the public key
to the authorized keys of the user@host where we want to connect to:

```shell
cd ~/.ssh

# Create the keys: hedlund_pwless
ssh-keygen -t rsa -b 4096

# Set proper permission on the public key
chmod 600 hedlund_pwless.pub

# Copy the public key to the authorized keys of our target host
ssh-copy-id hedlund_pwless tobbe@hedlund
```

```erlang
% Start local port forwarding: local:9191 -> remote:8008) , 
% tunnel is setup to host: "hedlund" as user: "tobbe" using
% the identity (i.e private SSH key): "/home/tobbe/.ssh/hedlund_pwless"
{ok, Tunnel} = ssh_tunnel:local("127.0.0.1",9191,"127.0.0.1",8008,"hedlund",[{user,"tobbe"},{identity,"/home/tobbe/.ssh/hedlund_pwless"}]).
```

Try to access the remote end point via the tunnel (make sure you have something running on the remote host...):

```shell
curl -is -u admin:admin http://127.0.0.1:9191/restconf/data
```

You can setup a reverse SSH tunnel similarly:

```erlang
% Start remote port forwarding (e.g. remote:9191 -> local:8008)
{ok, Tunnel} = ssh_tunnel:remote("127.0.0.1",8008,"127.0.0.1",9191,"hedlund",[{user,"tobbe"},{identity,"/home/tobbe/.ssh/hedlund_pwless"}]).
```

Stop the tunnel:

```
ok = ssh_tunnel:stop(Tunnel).
```

Options:
- `user` (required): SSH username
- `identity`: Path to SSH identity file (optional)

Requirements:
- SSH server must be running on the target host
- SSH client must be installed locally
- Appropriate SSH keys/credentials must be configured

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

## Netconf SSH channel handling

Verify that we can close one Netconf (SSH) channel and still use the other open channel.

### Usage

```bash
erlc ssh_channel_test.erl

erl -noshell -s ssh_channel_test test -s init stop
```
