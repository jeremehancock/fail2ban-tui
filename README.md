# fail2ban-tui

A small terminal screen for [fail2ban](https://github.com/fail2ban/fail2ban): see what is being blocked, check that the blocks really work, and unban an address safely.

```
 fail2ban on myserver                                                       updated 19:42:10

 Jail                               Banned now    Total   Refused   Firewall chain
 nginx-proxy-manager                         5      508        41   f2b-npm
 nginx-proxy-manager-dos                     0       46         -   -
 nginx-proxy-manager-severe                118      491       212   f2b-npm-severe

 nginx-proxy-manager: 5 banned
 Address                                         Banned      Left   Refused  Also in
 203.0.113.47                                   20m ago       39m        12  nginx-proxy-manager-severe
 198.51.100.23                                   5m ago       55m         0

 Enter details   u unban   U unban everywhere   / find   r refresh   ? help   q quit
```

## What it shows

- **Every jail** with how many addresses it is banning now and in total.
- **Every banned address**: when it was banned, how long is left, and which other jails also ban it.
- **Refused**: how many packets the firewall has actually turned away from that address since fail2ban last started. A number above 0 proves the ban is doing its job. fail2ban itself only tells you it *decided* to ban someone, not whether the firewall rule is reached.
- **Why it was banned**: press Enter on an address to see its most recent requests from the jail's own log files. Lines from Nginx Proxy Manager are shortened to `time  status method host/path`, for example `09:05:43  404 GET example.com/wp-login.php`.
- **A red warning at the top** if the bans can't be working, for example when they sit in the `FORWARD` chain behind Docker's own rules (see [Docker](#docker) below), or a jail has bans but no firewall rules.

## Requirements

- Linux with fail2ban 0.11 or newer, using an iptables-based action (`iptables-multiport`, `iptables-allports` and similar). The Refused column needs `iptables-save`; without it everything else still works.
- Python 3.10 or newer. Nothing to install: it only uses Python's standard library.
- Root, because fail2ban only answers root (run it with `sudo`).

## Install

Copy the one file to the server:

```
curl -fsSLO https://raw.githubusercontent.com/jeremehancock/fail2ban-tui/main/fail2ban_tui.py
```

(or `git clone` the repo).

## Use

```
sudo python3 fail2ban_tui.py
```

| Key | What it does |
|---|---|
| Up / Down (or j / k) | Move |
| Tab (or Left / Right) | Switch between the jail list and the address list |
| Enter | Details and recent requests for the selected address |
| u | Unban the address from this jail (asks first) |
| U | Unban the address from every jail (asks first) |
| / | Find an address: type part of it, then Enter |
| Esc | Clear the search |
| r | Refresh now (it also refreshes every 30 seconds) |
| ? | Help |
| q | Quit |

For a quick look without the full screen, or to paste somewhere:

```
sudo python3 fail2ban_tui.py --summary
```

It prints each jail, any warnings, and the banned addresses the firewall has refused most.

## Safe by design

- **It only changes something when you unban**, and only after you press `y` to confirm. Everything else is reading.
- **No shell.** Every command runs as a plain list of arguments, so an odd-looking entry in a log file can't make it run anything else. Addresses are checked to be real IP addresses before they're passed to `fail2ban-client`.
- **No network connections.** No lookups of banned addresses on outside services.
- **Gentle on the server.** Commands time out after 15 seconds, and log lookups read at most the last 2 MB of each log file (64 MB in total), only when you ask for an address's details.
- **The terminal is always put back**, even if something goes wrong.

## Docker

On a server running Docker, fail2ban's default iptables actions put their rules in `INPUT`, and many guides put them in `FORWARD`. Neither blocks traffic going to a Docker container (for example a reverse proxy like Nginx Proxy Manager): Docker lets that traffic in through its own rules first, and moves its rules back to the top whenever a container changes. The bans are logged, but nothing is blocked.

Put the bans in Docker's `DOCKER-USER` chain instead. Docker checks it before its own rules and never moves it:

```ini
[nginx-proxy-manager]
enabled = true
filter = nginx-proxy-manager
logpath = /path/to/npm/data/logs/proxy-host-*_access.log
action = iptables-multiport[name=npm, port="80,443", protocol=tcp, chain=DOCKER-USER]
```

Give each jail its own `name` (the firewall chain is called `f2b-<name>`), and make fail2ban start after Docker so `DOCKER-USER` exists when it starts:

```
sudo mkdir -p /etc/systemd/system/fail2ban.service.d
printf '[Unit]\nAfter=docker.service\n' | sudo tee /etc/systemd/system/fail2ban.service.d/after-docker.conf
sudo systemctl daemon-reload && sudo systemctl restart fail2ban
```

fail2ban-tui warns you if a jail's bans are stuck behind Docker, and the Refused column shows whether banned addresses are really being turned away.

## License

MIT, see [LICENSE](LICENSE).
