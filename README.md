# SSH Experiments
> Just some experiments with the Erlang SSH library

## SSH Tunneling

The `ssh_tunnel` module provides functionality to create SSH tunnels using system SSH commands.

### Usage

```erlang
% Start local port forwarding (e.g. local:8080 -> remote:80)
{ok, Tunnel} = ssh_tunnel:local(8080, "remote-host", 80, "ssh-host", [{user, "username"}]).

% Start remote port forwarding (e.g. remote:8080 -> local:80)
{ok, Tunnel} = ssh_tunnel:remote(8080, 80, "ssh-host", [{user, "username"}]).

% Stop a tunnel
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
