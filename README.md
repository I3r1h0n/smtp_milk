# SMTP Milk - User Enumeration Tool

## description
A tool to quickly enumerate users in smtp, over provided wordlist. Multithreaded, single target, can stop and continue the enum.

## usage
Help output:
```
usage: smtp_milk.py [-h] -H <host[:port]> -e <file> [-l <1|2|3>] [-T <n>] [-o <file>] [-t <secs>] [-c <line>]

SMTP Milk - User Enumeration Tool (VRFY / RCPT TO)

options:
  -h, --help            show this help message and exit
  -H, --host <host[:port]>
                        Target SMTP server, e.g. 192.168.1.10 or 192.168.1.10:587
                        (default port: 25).
  -e, --emails <file>   File of usernames or email addresses to test (one per line).
  -l, --level <1|2|3>   Enumeration technique:
                          1 = VRFY only
                          2 = RCPT TO only
                          3 = both (default)
  -T, --threads <n>     Number of concurrent threads per technique (default: 10).
  -o, --output <file>   File to append successful findings to.
  -t, --timeout <secs>  Per-connection timeout in seconds (default: 10).
  -c, --continue <line>
                        Resume from this line number in the wordlist (1-based, default: 1).
                        Use the number printed on Ctrl+C to resume a previous run.
```

## creds

prod by _I3r1h0n_.
