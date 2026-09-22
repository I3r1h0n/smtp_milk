#!/usr/bin/env python3

###############################################################################
#                                                                             #
#  smtp_milk.py — SMTP User Enumeration Tool                                  #
#  Based on iSMTP v1.6 by Alton Johnson (alton.jx@gmail.com)                  #
#                                                                             #
###############################################################################

import sys
import time
import smtplib
import argparse
import socket
import threading
import queue


# ANSI colours
class C:
    blue  = "\033[1;36m"
    green = "\033[1;32m"
    red   = "\033[1;31m"
    white = "\033[1;37m"
    yellow = "\033[1;33m"
    reset = "\033[0;00m"


BANNER = (
    "\n " + "-" * 69 + "\n"
    " " + C.white + " smtp_milk — SMTP User Enumeration Tool\n"
    " " + C.reset + "-" * 69 + "\n"
)

# Thread-safe live stats
class Stats:
    """Single overwriting status line on stderr. All methods are thread-safe"""

    def __init__(self, total: int, server: str):
        self._lock  = threading.Lock()
        self.total  = total
        self.done   = 0
        self.found  = 0
        self.server = server
        self._last  = 0

    def update(self, found_delta: int = 0):
        with self._lock:
            self.done  += 1
            self.found += found_delta
            self._redraw()

    def _redraw(self):
        line = (
            f"\r  [{self.done}/{self.total}]  "
            f"found: {C.green}{self.found}{C.reset}  "
            f"server: {C.white}{self.server}{C.reset}  "
        )
        pad = max(0, self._last - len(line))
        sys.stderr.write(line + " " * pad)
        sys.stderr.flush()
        self._last = len(line)

    def finish(self):
        with self._lock:
            sys.stderr.write("\n")
            sys.stderr.flush()


# Progress tracker (for resume)
class Progress:
    """
    Tracks the lowest line number that is currently in-flight or still queued.
    On Ctrl+C this gives us the safe resume point — the earliest entry that may not have been tested
    """

    def __init__(self, start_line: int):
        self._lock       = threading.Lock()
        # set of line numbers currently being processed by a worker thread
        self._in_flight: set[int] = set()
        # lowest line number still waiting in the queue
        self._queue_min: int = start_line

    def begin(self, line_no: int):
        with self._lock:
            self._in_flight.add(line_no)

    def end(self, line_no: int):
        with self._lock:
            self._in_flight.discard(line_no)

    def update_queue_min(self, line_no: int):
        with self._lock:
            self._queue_min = line_no

    def resume_line(self) -> int:
        with self._lock:
            candidates = list(self._in_flight)
            if candidates:
                return min(min(candidates), self._queue_min)
            return self._queue_min


# Thread-safe output file writer
class ResultWriter:
    def __init__(self, path: str | None):
        self._path = path
        self._lock = threading.Lock()

    def write_one(self, entry: str):
        if not self._path:
            return
        with self._lock:
            try:
                with open(self._path, "a") as fh:
                    fh.write(entry + "\n")
            except OSError as e:
                sys.stderr.write(
                    f"\n  {C.red}Warning: could not write to output file: {e}{C.reset}\n"
                )


# Helpers
def _banner_domain(smtp_host: str, smtp_port: int, timeout: float) -> str:
    try:
        s = socket.create_connection((smtp_host, smtp_port), timeout=timeout)
        raw = s.recv(1024).decode(errors="replace")
        s.close()
        parts = raw.split()
        if len(parts) > 1:
            chunks = parts[1].split(".")
            if len(chunks) >= 2:
                return ".".join(chunks[-2:])
    except Exception:
        pass
    return "example.com"


def _new_connection(smtp_host: str, smtp_port: int, domain: str, timeout: float) -> smtplib.SMTP | None:
    try:
        srv = smtplib.SMTP(smtp_host, smtp_port, timeout=timeout)
        srv.docmd("helo", domain)
        return srv
    except Exception:
        return None


# Worker: VRFY
def _vrfy_worker(
    work_q:       queue.Queue,
    found:        list,
    found_lock:   threading.Lock,
    stats:        Stats,
    progress:     Progress,
    writer:       ResultWriter,
    smtp_host:    str,
    smtp_port:    int,
    domain:       str,
    timeout:      float,
    abort:        threading.Event,
    consec_fails: list,
    consec_lock:  threading.Lock,
):
    srv = _new_connection(smtp_host, smtp_port, domain, timeout)
    if srv is None:
        while True:
            try:
                line_no, entry = work_q.get_nowait()
                progress.begin(line_no)
                progress.end(line_no)
                work_q.task_done()
                stats.update()
            except queue.Empty:
                break
        return

    while not abort.is_set():
        try:
            line_no, entry = work_q.get_nowait()
        except queue.Empty:
            break

        progress.begin(line_no)
        user = entry[:entry.find("@")] if "@" in entry else entry

        try:
            resp = srv.docmd("VRFY", user)
        except Exception:
            srv = _new_connection(smtp_host, smtp_port, domain, timeout)
            if srv is None:
                progress.end(line_no)
                work_q.task_done()
                stats.update()
                abort.set()
                break
            try:
                resp = srv.docmd("VRFY", user)
            except Exception:
                progress.end(line_no)
                work_q.task_done()
                stats.update()
                continue

        code = resp[0]

        if code in (502, 252) or (
            code == 550
            and "user unknown" not in (
                resp[1].decode(errors="replace")
                if isinstance(resp[1], bytes) else resp[1]
            ).lower()
        ):
            abort.set()
            progress.end(line_no)
            work_q.task_done()
            stats.update()
            break

        if code == 250:
            hit = f"VRFY:{entry}"
            with found_lock:
                found.append(hit)
            writer.write_one(hit)
            with consec_lock:
                consec_fails[0] = 0
            progress.end(line_no)
            stats.update(found_delta=1)
        else:
            with consec_lock:
                consec_fails[0] += 1
                if consec_fails[0] >= 15:
                    abort.set()
            progress.end(line_no)
            stats.update()

        work_q.task_done()

    try:
        srv.quit()
    except Exception:
        pass


# Worker: RCPT TO
def _rcpt_worker(
    work_q:     queue.Queue,
    found:      list,
    found_lock: threading.Lock,
    stats:      Stats,
    progress:   Progress,
    writer:     ResultWriter,
    smtp_host:  str,
    smtp_port:  int,
    domain:     str,
    timeout:    float,
    abort:      threading.Event,
):
    srv = _new_connection(smtp_host, smtp_port, domain, timeout)
    if srv is None:
        while True:
            try:
                line_no, entry = work_q.get_nowait()
                progress.begin(line_no)
                progress.end(line_no)
                work_q.task_done()
                stats.update()
            except queue.Empty:
                break
        return

    try:
        srv.docmd("mail from:", "<pentest@company.com>")
    except Exception:
        return

    while not abort.is_set():
        try:
            line_no, entry = work_q.get_nowait()
        except queue.Empty:
            break

        progress.begin(line_no)

        try:
            resp = srv.docmd("rcpt to:", f"<{entry}>")
        except socket.timeout:
            progress.end(line_no)
            work_q.task_done()
            stats.update()
            continue
        except Exception:
            srv = _new_connection(smtp_host, smtp_port, domain, timeout)
            if srv is None:
                progress.end(line_no)
                work_q.task_done()
                stats.update()
                abort.set()
                break
            try:
                srv.docmd("mail from:", "<pentest@company.com>")
                resp = srv.docmd("rcpt to:", f"<{entry}>")
            except Exception:
                progress.end(line_no)
                work_q.task_done()
                stats.update()
                continue

        if resp[0] == 250:
            hit = f"RCPT:{entry}"
            with found_lock:
                found.append(hit)
            writer.write_one(hit)
            progress.end(line_no)
            stats.update(found_delta=1)
        else:
            progress.end(line_no)
            stats.update()

        work_q.task_done()

    try:
        srv.quit()
    except Exception:
        pass


# Technique runners
def _fill_queue(work_q: queue.Queue, progress: Progress,
                email_list: list, start_line: int):
    """
    Put (line_no, entry) pairs into the queue
    line_no is the 1-based position in the ORIGINAL full wordlist
    Also keeps progress.queue_min updated
    """
    for i, entry in enumerate(email_list):
        line_no = start_line + i
        progress.update_queue_min(line_no)
        work_q.put((line_no, entry))


def run_vrfy(
    email_list:  list,
    start_line:  int,
    smtp_host:   str,
    smtp_port:   int,
    domain:      str,
    timeout:     float,
    num_threads: int,
    stats:       Stats,
    progress:    Progress,
    writer:      ResultWriter,
    abort:       threading.Event,
) -> list:
    print(f"\n  {C.white}Performing SMTP VRFY test...{C.reset}\n")

    probe_srv = _new_connection(smtp_host, smtp_port, domain, timeout)
    if probe_srv is None:
        print(f"  {C.red}Cannot connect for VRFY probe.{C.reset}")
        stats.done += len(email_list)
        return []
    probe_entry = email_list[0]
    probe_user  = (probe_entry[:probe_entry.find("@")]
                   if "@" in probe_entry else probe_entry)
    try:
        pr = probe_srv.docmd("VRFY", probe_user)
        probe_srv.quit()
    except Exception:
        print(f"  {C.red}VRFY probe failed — skipping.{C.reset}")
        stats.done += len(email_list)
        return []

    if pr[0] in (502, 252):
        print(f"  {C.red}Server is not vulnerable to SMTP VRFY enumeration.{C.reset}")
        stats.done += len(email_list)
        return []

    work_q       = queue.Queue()
    found        = []
    found_lock   = threading.Lock()
    consec_fails = [0]
    consec_lock  = threading.Lock()

    _fill_queue(work_q, progress, email_list, start_line)

    threads = []
    for _ in range(min(num_threads, len(email_list))):
        t = threading.Thread(
            target=_vrfy_worker,
            args=(work_q, found, found_lock, stats, progress, writer,
                  smtp_host, smtp_port, domain, timeout,
                  abort, consec_fails, consec_lock),
            daemon=True,
        )
        t.start()
        threads.append(t)

    work_q.join()
    for t in threads:
        t.join()

    if abort.is_set() and not found:
        print(
            f"\n  {C.red}Too many consecutive failures — "
            f"server likely not vulnerable to VRFY.{C.reset}"
        )

    return found


def run_rcpt(
    email_list:  list,
    start_line:  int,
    smtp_host:   str,
    smtp_port:   int,
    domain:      str,
    timeout:     float,
    num_threads: int,
    stats:       Stats,
    progress:    Progress,
    writer:      ResultWriter,
    abort:       threading.Event,
) -> list:
    print(f"\n  {C.white}Performing SMTP RCPT TO test...{C.reset}\n")

    email_domain = next((e[e.find("@"):] for e in email_list if "@" in e), "@example.com")
    probe_srv = _new_connection(smtp_host, smtp_port, domain, timeout)
    if probe_srv is None:
        print(f"  {C.red}Cannot connect for RCPT TO probe.{C.reset}")
        stats.done += len(email_list)
        return []
    try:
        probe_srv.docmd("mail from:", "<pentest@company.com>")
        pr = probe_srv.docmd("rcpt to:", f"<invalidemail_x9q8z{email_domain}>")
        probe_srv.quit()
    except Exception:
        print(f"  {C.red}RCPT TO probe failed — skipping.{C.reset}")
        stats.done += len(email_list)
        return []

    if str(pr[0])[0] == "2" or pr[0] == 554:
        print(f"  {C.red}Server is not vulnerable to SMTP RCPT TO enumeration.{C.reset}")
        stats.done += len(email_list)
        return []

    work_q     = queue.Queue()
    found      = []
    found_lock = threading.Lock()

    _fill_queue(work_q, progress, email_list, start_line)

    threads = []
    for _ in range(min(num_threads, len(email_list))):
        t = threading.Thread(
            target=_rcpt_worker,
            args=(work_q, found, found_lock, stats, progress, writer,
                  smtp_host, smtp_port, domain, timeout, abort),
            daemon=True,
        )
        t.start()
        threads.append(t)

    work_q.join()
    for t in threads:
        t.join()

    return found


# Top-level enumeration
def enumerate_server(
    smtp_host:   str,
    smtp_port:   int,
    email_list:  list,
    start_line:  int,
    enum_level:  int,
    timeout:     float,
    num_threads: int,
    writer:      ResultWriter,
    abort:       threading.Event,
) -> tuple[list, Progress]:
    server_tag = f"{smtp_host}:{smtp_port}"
    techniques = (2 if enum_level == 3 else 1)
    stats      = Stats(total=len(email_list) * techniques, server=server_tag)
    progress   = Progress(start_line=start_line)
    domain     = _banner_domain(smtp_host, smtp_port, timeout)
    all_found  = []

    if enum_level in (1, 3):
        hits = run_vrfy(email_list, start_line, smtp_host, smtp_port, domain,
                        timeout, num_threads, stats, progress, writer, abort)
        all_found.extend(hits)

    if enum_level in (2, 3):
        hits = run_rcpt(email_list, start_line, smtp_host, smtp_port, domain,
                        timeout, num_threads, stats, progress, writer, abort)
        all_found.extend(hits)

    stats.finish()
    return all_found, progress


# CLI
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="smtp_milk.py",
        description="SMTP Milk - User Enumeration Tool (VRFY / RCPT TO)",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    p.add_argument(
        "-H", "--host",
        metavar="<host[:port]>",
        required=True,
        help="Target SMTP server, e.g. 192.168.1.10 or 192.168.1.10:587\n(default port: 25).",
    )
    p.add_argument(
        "-e", "--emails",
        metavar="<file>",
        required=True,
        help="File of usernames or email addresses to test (one per line).",
    )
    p.add_argument(
        "-l", "--level",
        metavar="<1|2|3>",
        type=int,
        choices=[1, 2, 3],
        default=3,
        help=(
            "Enumeration technique:\n"
            "  1 = VRFY only\n"
            "  2 = RCPT TO only\n"
            "  3 = both (default)"
        ),
    )
    p.add_argument(
        "-T", "--threads",
        metavar="<n>",
        type=int,
        default=10,
        help="Number of concurrent threads per technique (default: 10).",
    )
    p.add_argument(
        "-o", "--output",
        metavar="<file>",
        default=None,
        help="File to append successful findings to.",
    )
    p.add_argument(
        "-t", "--timeout",
        metavar="<secs>",
        type=float,
        default=10.0,
        help="Per-connection timeout in seconds (default: 10).",
    )
    p.add_argument(
        "-c", "--continue",
        metavar="<line>",
        type=int,
        default=1,
        dest="start_line",
        help=(
            "Resume from this line number in the wordlist (1-based, default: 1).\n"
            "Use the number printed on Ctrl+C to resume a previous run."
        ),
    )
    return p


# Entry point
def main():
    parser = build_parser()
    args   = parser.parse_args()

    print(BANNER)

    # Parse host / port
    if ":" in args.host:
        h, p = args.host.rsplit(":", 1)
        smtp_host, smtp_port = h.strip(), int(p)
    else:
        smtp_host, smtp_port = args.host.strip(), 25

    # Load wordlist
    try:
        with open(args.emails) as fh:
            all_lines = [ln.strip() for ln in fh if ln.strip()]
    except OSError as e:
        print(f"{C.red}Error reading email list: {e}{C.reset}")
        sys.exit(1)

    if not all_lines:
        print(f"{C.red}Error: email list is empty.{C.reset}")
        sys.exit(1)

    # Apply --continue offset (1-based → 0-based index)
    start_line = max(1, args.start_line)
    if start_line > len(all_lines):
        print(f"{C.red}Error: --continue {start_line} exceeds wordlist length "
              f"({len(all_lines)} lines).{C.reset}")
        sys.exit(1)

    email_list = all_lines[start_line - 1:]   # slice from resume point

    if args.threads < 1:
        print(f"{C.red}Error: --threads must be >= 1.{C.reset}")
        sys.exit(1)

    # Prepare output file — append when resuming so old hits are preserved
    writer = ResultWriter(args.output)
    if args.output and start_line == 1:
        # Fresh run: write header
        try:
            with open(args.output, "w") as fh:
                fh.write(
                    f"# smtp_milk results — {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                    f"# target: {smtp_host}:{smtp_port}\n\n"
                )
        except OSError as e:
            print(f"{C.red}Error creating output file: {e}{C.reset}")
            sys.exit(1)
    elif args.output and start_line > 1:
        # Resuming: note the continuation in the file
        try:
            with open(args.output, "a") as fh:
                fh.write(
                    f"\n# resumed from line {start_line} — "
                    f"{time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                )
        except OSError as e:
            print(f"{C.red}Error opening output file: {e}{C.reset}")
            sys.exit(1)

    socket.setdefaulttimeout(args.timeout)

    print(f"  {C.white}Target     :{C.reset} {smtp_host}:{smtp_port}")
    print(f"  {C.white}Wordlist   :{C.reset} {len(all_lines)} lines total")
    if start_line > 1:
        print(f"  {C.yellow}Resuming   : from line {start_line} "
              f"({len(email_list)} remaining){C.reset}")
    else:
        print(f"  {C.white}Logins     :{C.reset} {len(email_list)}")
    print(f"  {C.white}Threads    :{C.reset} {args.threads}")
    print(f"  {C.white}Level      :{C.reset} {args.level}  "
          f"({'VRFY' if args.level == 1 else 'RCPT TO' if args.level == 2 else 'VRFY + RCPT TO'})")
    if args.output:
        print(f"  {C.white}Output     :{C.reset} {args.output}")

    abort    = threading.Event()
    progress = None
    start    = time.time()
    hits     = []

    try:
        hits, progress = enumerate_server(
            smtp_host=smtp_host,
            smtp_port=smtp_port,
            email_list=email_list,
            start_line=start_line,
            enum_level=args.level,
            timeout=args.timeout,
            num_threads=args.threads,
            writer=writer,
            abort=abort,
        )

    except KeyboardInterrupt:
        # Signal all threads to stop and wait briefly for them to drain
        abort.set()
        time.sleep(0.3)

        resume_at = progress.resume_line() if progress else start_line
        elapsed   = time.time() - start

        sys.stderr.write("\n")          # end the stats line cleanly
        print(f"\n  {C.yellow}Interrupted by user.{C.reset}")
        print(f"\n  {C.white}Resume from line :{C.reset} "
              f"{C.yellow}{resume_at}{C.reset}")
        print(f"  {C.white}Re-run with      :{C.reset} "
              f"--continue {resume_at}")
        if hits:
            print(f"\n  {C.green}Hits found so far: {len(hits)}{C.reset}")
        if args.output:
            print(f"  Results (partial): {args.output}")
        print(f"  Stopped after    : {elapsed:.1f}s\n")
        sys.exit(130)   # conventional exit code for Ctrl+C

    elapsed = time.time() - start

    print(f"\n{'─' * 5}")
    if hits:
        print(f"\n  {C.green}Valid accounts found:{C.reset}")
        for item in hits:
            method, _, value = item.partition(":")
            print(f"    {C.blue}[+]{C.reset} {value}  {C.white}({method}){C.reset}")
    else:
        print(f"\n  {C.red}No valid accounts found.{C.reset}")

    print(f"\n  Total found  : {C.green}{len(hits)}{C.reset}")
    if args.output:
        print(f"  Results file : {args.output}")
    print(f"  Completed in : {elapsed:.1f}s\n")


if __name__ == "__main__":
    main()
