# SSH Experiments
> Just some experiments with the Erlang SSH library

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
