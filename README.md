# webterm-server

A simple no-frills webterm server.

```
Usage: webterm-server [OPTIONS] [COMMAND] [ARGS]...

Arguments:
  [COMMAND]  The command to execute [default: webterm-login]
  [ARGS]...  Arguments for the command

Options:
  -v, --verbose...       Print more messages
  -q, --quiet...         Print less messages
  -l, --listen <LISTEN>  The address to bind to [default: localhost:8080]
  -h, --help             Print help
```

## Customizing login behaviour

### No login required
You can have the webterm server spawn a shell without requiring the user to login.
Simply adjust the command line arguments:
```
webterm-server -- /usr/bin/zsh -l
```

### Require password of a specific user
You can also have the webterm server start `su -l MYUSER`.
The `su` program will ask for a password before starting a login shell for `MYUSER`.
```
webterm-server -- /usr/bin/su -l MYUSER
```

### Password login for any user
You could try to use the `/sbin/login` program.
However, the `login` program requires root permissions to function on many systems.

You can mimic the behaviour of `login` with a small shell script:
```sh
#!/bin/sh
read -p "Username: " -r username
exec su -l "$username"
```

This script is included in the repository as `webterm-login`.
You can install it somewhere and have the webterm server run it for new sessions:

```
webterm-server -- /usr/local/bin/webterm-login
```
