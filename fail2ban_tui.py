#!/usr/bin/env python3
"""fail2ban-tui: see what fail2ban is blocking, and unban addresses safely.

Run on the server with:  sudo python3 fail2ban_tui.py
Plain text summary:      sudo python3 fail2ban_tui.py --summary

Only uses Python's standard library. It changes nothing on the server except
when you unban an address (and only after you confirm). It makes no network
connections.
"""

import argparse
import curses
import ipaddress
import os
import re
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime

VERSION = "2.0.0"
REFRESH_SECONDS = 30
CMD_TIMEOUT = 15
LOG_TAIL_BYTES = 2 * 1024 * 1024      # read at most this much from the end of each log file
LOG_TOTAL_BYTES = 64 * 1024 * 1024    # and at most this much in total, per lookup
RECENT_LINES = 12                     # recent log lines shown for an address
TIME_FMT = "%Y-%m-%d %H:%M:%S"        # fail2ban's own time format (local time)


# --------------------------------------------------------------------------
# Running commands (always as a list, never through a shell)
# --------------------------------------------------------------------------

def run(cmd):
    """Run a command and return (ok, stdout, stderr). Never raises."""
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=CMD_TIMEOUT)
        return res.returncode == 0, res.stdout, res.stderr.strip()
    except FileNotFoundError:
        return False, "", f"{cmd[0]} not found"
    except subprocess.TimeoutExpired:
        return False, "", f"{cmd[0]} took longer than {CMD_TIMEOUT} seconds"
    except OSError as e:
        return False, "", str(e)


def valid_ip(text):
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


# --------------------------------------------------------------------------
# Reading fail2ban
# --------------------------------------------------------------------------

@dataclass
class Ban:
    ip: str
    jail: str
    start: datetime | None
    seconds: int          # ban length; -1 means forever
    end: datetime | None
    blocked: int | None = None   # packets the firewall refused from this address


@dataclass
class Jail:
    name: str
    failed_now: int = 0
    banned_total: int = 0
    bans: list = field(default_factory=list)
    logpaths: list = field(default_factory=list)
    chain: str | None = None      # firewall chain holding this jail's bans
    action_chains: list = field(default_factory=list)  # f2b-<name> for each of the jail's actions


BAN_LINE = re.compile(r"^(\S+)\s+(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) \+ (-?\d+) = (.+)$")


def parse_time(text):
    try:
        return datetime.strptime(text.strip(), TIME_FMT)
    except ValueError:
        return None


def jail_names():
    ok, out, err = run(["fail2ban-client", "status"])
    if not ok:
        raise RuntimeError(err or "fail2ban-client status failed (is fail2ban running?)")
    for line in out.splitlines():
        if "Jail list:" in line:
            names = line.split("Jail list:", 1)[1]
            return [n.strip() for n in names.split(",") if n.strip()]
    return []


def status_value(out, label):
    m = re.search(re.escape(label) + r":\s*(\d+)", out)
    return int(m.group(1)) if m else 0


_STATIC = {}   # jail name -> (logpaths, action_chains); these don't change while the tool runs


def read_jail(name):
    jail = Jail(name)
    ok, out, _ = run(["fail2ban-client", "status", name])
    if ok:
        jail.failed_now = status_value(out, "Currently failed")
        jail.banned_total = status_value(out, "Total banned")
    ok, out, _ = run(["fail2ban-client", "get", name, "banip", "--with-time"])
    if ok:
        for line in out.splitlines():
            m = BAN_LINE.match(line.strip())
            if m and valid_ip(m.group(1)):
                jail.bans.append(Ban(m.group(1), name, parse_time(m.group(2)),
                                     int(m.group(3)), parse_time(m.group(4))))
    jail.bans.sort(key=lambda b: b.start or datetime.min, reverse=True)
    if name in _STATIC:
        jail.logpaths, jail.action_chains = _STATIC[name]
        return jail
    ok, out, _ = run(["fail2ban-client", "get", name, "logpath"])
    if ok:
        for line in out.splitlines():
            line = line.strip()
            if line[:3] in ("|- ", "`- "):
                jail.logpaths.append(line[3:])
    # Each iptables action keeps its bans in a chain called f2b-<name>; ask fail2ban for <name>.
    ok, out, _ = run(["fail2ban-client", "get", name, "actions"])
    if ok and ":" in out:
        for action in out.split(":", 1)[1].replace("\n", ",").split(","):
            action = action.strip()
            if not action:
                continue
            ok, value, _ = run(["fail2ban-client", "get", name, "action", action, "name"])
            value = value.strip()
            if ok and value and re.fullmatch(r"[\w.-]+", value):
                jail.action_chains.append("f2b-" + value)
    _STATIC[name] = (jail.logpaths, jail.action_chains)
    return jail


# --------------------------------------------------------------------------
# Reading the firewall (iptables-save with counters, one call)
# --------------------------------------------------------------------------

@dataclass
class Firewall:
    available: bool = False
    note: str = ""
    # chain name -> {ip: packets}
    blocked: dict = field(default_factory=dict)
    # chain name -> list of (parent chain, position, rule text) that jump to it
    jumps: dict = field(default_factory=dict)
    # parent chain -> ordered list of jump targets / verdicts
    order: dict = field(default_factory=dict)


RULE = re.compile(r"^\[(\d+):(\d+)\] -A (\S+) (.*)$")


def read_firewall():
    fw = Firewall()
    ok, out, err = run(["iptables-save", "-c", "-t", "filter"])
    if not ok:
        fw.note = f"Firewall counters unavailable: {err or 'iptables-save failed'}"
        return fw
    fw.available = True
    ok6, out6, _ = run(["ip6tables-save", "-c", "-t", "filter"])
    _read_rules(fw, out)
    if ok6:
        six = Firewall()
        _read_rules(six, out6)
        for chain, ips in six.blocked.items():
            fw.blocked.setdefault(chain, {}).update(ips)
        for chain, refs in six.jumps.items():
            fw.jumps.setdefault(chain, [])
    return fw


def _read_rules(fw, out):
    for line in out.splitlines():
        m = RULE.match(line)
        if not m:
            continue
        packets, chain, rest = int(m.group(1)), m.group(3), m.group(4)
        target = re.search(r"-j (\S+)", rest)
        target = target.group(1) if target else ""
        fw.order.setdefault(chain, []).append(target)
        if target.startswith("f2b-"):
            fw.jumps.setdefault(target, []).append((chain, len(fw.order[chain]), rest))
        if chain.startswith("f2b-"):
            src = re.search(r"-s (\S+?)(?:/(?:32|128))?(?:\s|$)", rest)
            if src and target in ("REJECT", "DROP"):
                fw.blocked.setdefault(chain, {})
                fw.blocked[chain][src.group(1)] = fw.blocked[chain].get(src.group(1), 0) + packets


def firewall_warnings(fw, jails):
    """Plain-English warnings when bans exist but can't be working."""
    warnings = []
    if not fw.available:
        return [fw.note] if fw.note else []
    docker = any(name.startswith("DOCKER") for name in fw.order) or any(
        target.startswith("DOCKER") for targets in fw.order.values() for target in targets)
    for jail in jails:
        if not jail.chain:
            if jail.bans:
                warnings.append(f"{jail.name}: has bans but no firewall rules were found for them.")
            continue
        jumps = fw.jumps.get(jail.chain, [])
        if not jumps:
            warnings.append(f"{jail.name}: its firewall chain {jail.chain} isn't connected, so its bans block nothing.")
            continue
        for parent, pos, _ in jumps:
            if parent == "FORWARD" and docker:
                earlier = fw.order.get("FORWARD", [])[:pos - 1]
                if any(t in ("DOCKER-FORWARD", "DOCKER", "ACCEPT") for t in earlier):
                    warnings.append(f"{jail.name}: bans sit in FORWARD after Docker's rules, so Docker lets "
                                    f"banned traffic in first. Use chain=DOCKER-USER in the jail's action.")
    return warnings


def match_chains(fw, jails):
    """Work out which f2b-* chain belongs to which jail.

    First by the action names fail2ban reports (exact). Only for a jail where that
    isn't available, by which chain holds most of the jail's banned addresses.
    """
    taken = set()
    known = set(fw.blocked) | set(fw.jumps)
    for jail in jails:
        for chain in jail.action_chains:
            if chain in known and chain not in taken:
                jail.chain = chain
                taken.add(chain)
                break
        if jail.chain:
            for ban in jail.bans:
                ban.blocked = fw.blocked.get(jail.chain, {}).get(ban.ip)
    for jail in sorted((j for j in jails if not j.chain and not j.action_chains),
                       key=lambda j: -len(j.bans)):
        ips = {b.ip for b in jail.bans}
        best, score = None, 0
        for chain, blocked in fw.blocked.items():
            if chain in taken:
                continue
            overlap = len(ips & set(blocked))
            if overlap > score:
                best, score = chain, overlap
        if best:
            jail.chain = best
            taken.add(best)
            for ban in jail.bans:
                ban.blocked = fw.blocked[best].get(ban.ip)


# --------------------------------------------------------------------------
# Snapshot of everything, refreshed together
# --------------------------------------------------------------------------

@dataclass
class Snapshot:
    jails: list
    firewall: Firewall
    warnings: list
    taken: datetime

    def all_bans(self):
        return [b for j in self.jails for b in j.bans]

    def jails_for(self, ip):
        return [j.name for j in self.jails if any(b.ip == ip for b in j.bans)]


def take_snapshot():
    jails = [read_jail(n) for n in jail_names()]
    fw = read_firewall()
    if fw.available:
        match_chains(fw, jails)
    return Snapshot(jails, fw, firewall_warnings(fw, jails), datetime.now())


# --------------------------------------------------------------------------
# Why was it banned: recent lines from the jail's own log files
# --------------------------------------------------------------------------

NPM_LINE = re.compile(r'^\[([^\]]+)\] - - (\d{3}) - (\w+) (\w+) (\S+) "([^"]*)" \[Client ([^\]]+)\]')


def tail(path, limit):
    with open(path, "rb") as f:
        f.seek(0, os.SEEK_END)
        size = f.tell()
        f.seek(max(0, size - limit))
        data = f.read()
    return data.decode("utf-8", "replace").splitlines()


def recent_requests(ip, logpaths):
    pattern = re.compile(r"(?<![\w.:])" + re.escape(ip) + r"(?![\w.:])")
    found, budget = [], LOG_TOTAL_BYTES
    files = []
    for p in logpaths:
        try:
            files.append((os.path.getmtime(p), p))
        except OSError:
            pass
    for _, path in sorted(files, reverse=True):
        if budget <= 0:
            break
        try:
            lines = tail(path, min(LOG_TAIL_BYTES, budget))
            budget -= LOG_TAIL_BYTES
        except OSError:
            continue
        for line in lines:
            if pattern.search(line):
                found.append(line)
    return [pretty_line(l) for l in sorted(found, key=npm_sort_key)[-RECENT_LINES:]]


def npm_sort_key(line):
    m = NPM_LINE.match(line)
    if m:
        try:
            return datetime.strptime(m.group(1).split()[0], "%d/%b/%Y:%H:%M:%S").isoformat()
        except ValueError:
            pass
    return line


def pretty_line(line):
    """Nginx Proxy Manager lines become 'time  status method host path'."""
    m = NPM_LINE.match(line)
    if not m:
        return "".join(ch if ch.isprintable() else "?" for ch in line)
    when = m.group(1).split()[0].split(":", 1)[-1]
    text = f"{when}  {m.group(2)} {m.group(3)} {m.group(5)}{m.group(6)}"
    return "".join(ch if ch.isprintable() else "?" for ch in text)


# --------------------------------------------------------------------------
# Small formatting helpers
# --------------------------------------------------------------------------

def ago(when, now):
    if not when:
        return "?"
    s = int((now - when).total_seconds())
    return duration(s) + " ago" if s >= 0 else "just now"


def left(ban, now):
    if ban.seconds < 0:
        return "forever"
    if not ban.end:
        return "?"
    s = int((ban.end - now).total_seconds())
    return duration(s) if s > 0 else "ending"


def duration(s):
    s = abs(s)
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m"
    if s < 86400:
        return f"{s // 3600}h {s % 3600 // 60}m"
    return f"{s // 86400}d {s % 86400 // 3600}h"


def blocked_text(ban):
    return "?" if ban.blocked is None else str(ban.blocked)


# --------------------------------------------------------------------------
# Plain text summary (--summary)
# --------------------------------------------------------------------------

def summary():
    snap = take_snapshot()
    now = datetime.now()
    print(f"fail2ban on {socket.gethostname()}  ({now.strftime(TIME_FMT)})\n")
    for w in snap.warnings:
        print(f"WARNING: {w}")
    if snap.warnings:
        print()
    print(f"{'Jail':32} {'Banned now':>10} {'Banned total':>12}  Firewall chain")
    for j in snap.jails:
        print(f"{j.name:32} {len(j.bans):>10} {j.banned_total:>12}  {j.chain or '-'}")
    bans = snap.all_bans()
    print(f"\n{len({b.ip for b in bans})} addresses banned right now.")
    if snap.firewall.available:
        hit = sorted((b for b in bans if b.blocked), key=lambda b: -b.blocked)
        print(f"{len({b.ip for b in hit})} of them came back and were refused by the firewall.")
        if hit:
            print("\nMost refused:")
            for b in hit[:10]:
                print(f"  {b.ip:40} {b.blocked:>8} packets  ({b.jail}, banned {ago(b.start, now)})")
    else:
        print(snap.firewall.note)


# --------------------------------------------------------------------------
# The interactive screen
# --------------------------------------------------------------------------

HELP = [
    "Keys",
    "",
    "  Up/Down, j/k     move",
    "  Left/Right, Tab  switch between jails and addresses",
    "  Enter            details and recent requests for an address",
    "  u                unban the address from this jail",
    "  U                unban the address from every jail",
    "  /                find an address (type part of it, Enter)",
    "  Esc              clear the search / close a window",
    "  r                refresh now (it also refreshes every 30 seconds)",
    "  q                quit",
    "",
    "Columns",
    "",
    "  Banned     when fail2ban banned it",
    "  Left       time until the ban ends",
    "  Refused    packets the firewall turned away from it since fail2ban",
    "             last started; above 0 proves the ban really blocks",
    "",
    "Press any key to close.",
]


class App:
    def __init__(self, scr):
        self.scr = scr
        self.snap = None
        self.error = ""
        self.message = ""
        self.jail_i = 0
        self.ban_i = 0
        self.ban_top = 0
        self.focus = "jails"
        self.search = ""
        self.last_refresh = 0.0
        curses.curs_set(0)
        scr.timeout(1000)
        scr.keypad(True)
        curses.use_default_colors()
        if curses.has_colors():
            curses.init_pair(1, curses.COLOR_RED, -1)
            curses.init_pair(2, curses.COLOR_GREEN, -1)
            curses.init_pair(3, curses.COLOR_YELLOW, -1)
            curses.init_pair(4, curses.COLOR_CYAN, -1)
        self.refresh_data()

    # ---- data ----
    def refresh_data(self):
        try:
            self.snap = take_snapshot()
            self.error = ""
        except RuntimeError as e:
            self.error = str(e)
        self.last_refresh = time.time()
        self.clamp()

    def jail(self):
        if not self.snap or not self.snap.jails:
            return None
        return self.snap.jails[self.jail_i]

    def visible_bans(self):
        if not self.snap:
            return []
        if self.search:
            return [b for b in self.snap.all_bans() if self.search in b.ip]
        j = self.jail()
        return j.bans if j else []

    def clamp(self):
        if self.snap:
            self.jail_i = max(0, min(self.jail_i, len(self.snap.jails) - 1))
        n = len(self.visible_bans())
        self.ban_i = max(0, min(self.ban_i, n - 1))

    # ---- drawing ----
    def put(self, y, x, text, attr=0):
        h, w = self.scr.getmaxyx()
        if y < 0 or y >= h or x >= w:
            return
        try:
            self.scr.addnstr(y, x, text, max(0, w - x - 1), attr)
        except curses.error:
            pass

    def color(self, n):
        return curses.color_pair(n) if curses.has_colors() else 0

    def draw(self):
        self.scr.erase()
        h, w = self.scr.getmaxyx()
        if h < 12 or w < 70:
            self.put(0, 0, "Window too small: make it at least 70 x 12.")
            self.scr.refresh()
            return
        now = datetime.now()
        title = f" fail2ban on {socket.gethostname()} "
        stamp = f" updated {self.snap.taken.strftime('%H:%M:%S')} " if self.snap else ""
        self.put(0, 0, title, curses.A_REVERSE | curses.A_BOLD)
        self.put(0, len(title), " " * max(0, w - len(title) - len(stamp) - 1), curses.A_REVERSE)
        self.put(0, max(len(title), w - len(stamp) - 1), stamp, curses.A_REVERSE)
        y = 1
        if self.error:
            self.put(y, 1, f"Can't read fail2ban: {self.error}", self.color(1) | curses.A_BOLD)
            y += 1
        if self.snap:
            for warn in self.snap.warnings[:3]:
                self.put(y, 1, "! " + warn, self.color(1) | curses.A_BOLD)
                y += 1
        y += 1
        self.draw_jails(y, now)
        list_y = y + (len(self.snap.jails) if self.snap else 0) + 3
        self.draw_bans(list_y, h - 2, now)
        foot = self.message or "Enter details   u unban   U unban everywhere   / find   r refresh   ? help   q quit"
        self.put(h - 1, 0, " " + foot.ljust(w - 2), curses.A_REVERSE)
        self.scr.refresh()

    def draw_jails(self, y, now):
        active = self.focus == "jails" and not self.search
        self.put(y, 1, f"{'Jail':34}{'Banned now':>11}{'Total':>9}{'Refused':>10}   Firewall chain",
                 curses.A_BOLD | curses.A_UNDERLINE)
        if not self.snap:
            return
        for i, j in enumerate(self.snap.jails):
            refused = sum(b.blocked or 0 for b in j.bans) if j.chain else None
            line = (f"{j.name[:33]:34}{len(j.bans):>11}{j.banned_total:>9}"
                    f"{'-' if refused is None else refused:>10}   {j.chain or '-'}")
            attr = curses.A_REVERSE if (i == self.jail_i and active) else (
                curses.A_BOLD if i == self.jail_i else 0)
            self.put(y + 1 + i, 1, line, attr)

    def draw_bans(self, y, bottom, now):
        bans = self.visible_bans()
        if self.search:
            label = f"Find \"{self.search}\": {len(bans)} match(es) in all jails   (Esc to clear)"
        else:
            j = self.jail()
            label = f"{j.name}: {len(bans)} banned" if j else "No jails"
        self.put(y, 1, label, self.color(4) | curses.A_BOLD)
        head = f"{'Address':40}{'Banned':>14}{'Left':>10}{'Refused':>10}  {'Jail' if self.search else 'Also in'}"
        self.put(y + 1, 1, head, curses.A_BOLD | curses.A_UNDERLINE)
        rows = max(1, bottom - (y + 2))
        if self.ban_i < self.ban_top:
            self.ban_top = self.ban_i
        elif self.ban_i >= self.ban_top + rows:
            self.ban_top = self.ban_i - rows + 1
        if not bans:
            self.put(y + 2, 3, "Nothing banned here right now.")
            return
        active = self.focus == "bans" or self.search
        for row, ban in enumerate(bans[self.ban_top:self.ban_top + rows]):
            i = self.ban_top + row
            others = [n for n in self.snap.jails_for(ban.ip) if n != ban.jail]
            also = ban.jail if self.search else ", ".join(others)
            line = f"{ban.ip:40}{ago(ban.start, now):>14}{left(ban, now):>10}{blocked_text(ban):>10}  {also}"
            attr = curses.A_REVERSE if (i == self.ban_i and active) else 0
            if not attr and ban.blocked:
                attr = self.color(2)
            self.put(y + 2 + row, 1, line, attr)
        if len(bans) > rows:
            self.put(bottom, 1, f"{self.ban_i + 1} of {len(bans)}", curses.A_DIM)

    # ---- windows ----
    def popup(self, lines, wait=True):
        h, w = self.scr.getmaxyx()
        width = min(w - 4, max(len(l) for l in lines) + 4)
        height = min(h - 2, len(lines) + 2)
        win = curses.newwin(height, width, max(0, (h - height) // 2), max(0, (w - width) // 2))
        win.erase()
        win.box()
        for i, l in enumerate(lines[:height - 2]):
            try:
                win.addnstr(1 + i, 2, l, width - 4)
            except curses.error:
                pass
        win.refresh()
        if wait:
            self.scr.timeout(-1)
            key = self.scr.getch()
            self.scr.timeout(1000)
            return key
        return None

    def confirm(self, question):
        key = self.popup([question, "", "Press y to confirm, any other key to cancel."])
        return key in (ord("y"), ord("Y"))

    def details(self, ban):
        now = datetime.now()
        jail = next((j for j in self.snap.jails if j.name == ban.jail), None)
        self.popup([f"Looking through {ban.jail}'s logs for {ban.ip} ..."], wait=False)
        reqs = recent_requests(ban.ip, jail.logpaths if jail else [])
        self.draw()
        in_jails = self.snap.jails_for(ban.ip)
        lines = [
            f"Address:   {ban.ip}",
            f"Banned by: {', '.join(in_jails)}",
            f"Banned:    {ban.start.strftime(TIME_FMT) if ban.start else '?'} ({ago(ban.start, now)})",
            f"Ends:      {'never' if ban.seconds < 0 else (ban.end.strftime(TIME_FMT) if ban.end else '?')}"
            f" ({left(ban, now)} left)",
            f"Refused:   {blocked_text(ban)} packets since fail2ban last started",
            "",
            "Most recent requests in the logs:" if reqs else "No requests from it in the recent logs.",
        ] + ["  " + r for r in reqs] + ["", "Press any key to close."]
        self.popup(lines)

    def ask_search(self):
        h, w = self.scr.getmaxyx()
        self.put(h - 1, 0, " Find address: ".ljust(w - 1), curses.A_REVERSE)
        curses.echo()
        curses.curs_set(1)
        self.scr.timeout(-1)
        try:
            raw = self.scr.getstr(h - 1, 16, 45)
        except curses.error:
            raw = b""
        curses.noecho()
        curses.curs_set(0)
        self.scr.timeout(1000)
        text = raw.decode("utf-8", "replace").strip()
        self.search = "".join(ch for ch in text if ch in "0123456789abcdefABCDEF.:").lower()
        self.ban_i = self.ban_top = 0

    # ---- actions ----
    def unban(self, everywhere):
        bans = self.visible_bans()
        if not bans:
            return
        ban = bans[self.ban_i]
        if not valid_ip(ban.ip):
            self.message = f"Refusing to unban '{ban.ip}': not a valid address."
            return
        if everywhere:
            where = self.snap.jails_for(ban.ip)
            if not self.confirm(f"Unban {ban.ip} from every jail ({', '.join(where)})?"):
                self.message = "Cancelled."
                return
            ok, _, err = run(["fail2ban-client", "unban", ban.ip])
        else:
            if ban.jail not in [j.name for j in self.snap.jails]:
                return
            if not self.confirm(f"Unban {ban.ip} from {ban.jail}?"):
                self.message = "Cancelled."
                return
            ok, _, err = run(["fail2ban-client", "set", ban.jail, "unbanip", ban.ip])
        self.message = f"Unbanned {ban.ip}." if ok else f"Unban failed: {err}"
        self.refresh_data()

    def key(self, k):
        n_bans = len(self.visible_bans())
        if k in (ord("q"), ord("Q")):
            return False
        if k in (curses.KEY_UP, ord("k")):
            if self.focus == "jails" and not self.search:
                self.jail_i, self.ban_i, self.ban_top = max(0, self.jail_i - 1), 0, 0
            else:
                self.ban_i = max(0, self.ban_i - 1)
        elif k in (curses.KEY_DOWN, ord("j")):
            if self.focus == "jails" and not self.search:
                last = len(self.snap.jails) - 1 if self.snap else 0
                self.jail_i, self.ban_i, self.ban_top = min(last, self.jail_i + 1), 0, 0
            else:
                self.ban_i = min(max(0, n_bans - 1), self.ban_i + 1)
        elif k == curses.KEY_NPAGE:
            self.focus = "bans"
            self.ban_i = min(max(0, n_bans - 1), self.ban_i + 10)
        elif k == curses.KEY_PPAGE:
            self.focus = "bans"
            self.ban_i = max(0, self.ban_i - 10)
        elif k in (9, curses.KEY_RIGHT, curses.KEY_LEFT, ord("l"), ord("h")):
            self.focus = "bans" if self.focus == "jails" else "jails"
        elif k in (10, 13, curses.KEY_ENTER):
            if self.focus == "jails" and not self.search:
                self.focus = "bans"
            elif n_bans:
                self.details(self.visible_bans()[self.ban_i])
        elif k == ord("u") and (self.focus == "bans" or self.search):
            self.unban(everywhere=False)
        elif k == ord("U") and (self.focus == "bans" or self.search):
            self.unban(everywhere=True)
        elif k == ord("/"):
            self.ask_search()
        elif k == 27:
            self.search, self.message = "", ""
        elif k in (ord("r"), ord("R")):
            self.refresh_data()
        elif k == ord("?"):
            self.popup(HELP)
        self.clamp()
        return True

    def loop(self):
        while True:
            if time.time() - self.last_refresh >= REFRESH_SECONDS:
                self.refresh_data()
            self.draw()
            k = self.scr.getch()
            if k == -1 or k == curses.KEY_RESIZE:
                continue
            self.message = ""
            if not self.key(k):
                return


def main():
    parser = argparse.ArgumentParser(
        description="See what fail2ban is blocking and unban addresses. Run with sudo.")
    parser.add_argument("--summary", action="store_true", help="print a plain text summary and exit")
    parser.add_argument("--version", action="version", version=f"fail2ban-tui {VERSION}")
    args = parser.parse_args()
    if os.geteuid() != 0:
        sys.exit("fail2ban-tui needs root to talk to fail2ban. Run it with sudo.")
    if args.summary:
        try:
            summary()
        except RuntimeError as e:
            sys.exit(f"Can't read fail2ban: {e}")
        return
    try:
        curses.wrapper(lambda scr: App(scr).loop())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
