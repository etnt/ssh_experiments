# Netconf SSH channel handling

Verify that we can close one Netconf (SSH) channel and still use the other open channel.

## Usage

```bash
erlc ssh_channel_test.erl

erl -noshell -s ssh_channel_test test -s init stop
```
