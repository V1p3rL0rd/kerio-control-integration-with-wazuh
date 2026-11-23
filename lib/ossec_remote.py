#!/usr/bin/env python3
"""Manage the Kerio Control syslog <remote> block in Wazuh ossec.conf.

ossec.conf is not a strictly valid XML document (it may contain several
<ossec_config> roots), so the file is edited as text and only the managed
block between BEGIN/END markers is ever rewritten.

Subcommands:
  inspect  print JSON with the managed block state and conflicting blocks
  render   write a new ossec.conf with the managed block added/updated
  remove   write a new ossec.conf without the managed block

Exit codes: 0 ok, 2 usage/input error, 3 conflict (unmanaged block on the
same port/protocol; re-run with --adopt to take it over).
"""
import argparse
import ipaddress
import json
import re
import sys

MARK = "kerio-control-integration-with-wazuh-siem"
BEGIN = "<!-- BEGIN %s: Kerio Control syslog receiver (managed by deploy.sh) -->" % MARK
END = "<!-- END %s -->" % MARK

MANAGED_RE = re.compile(
    r"[ \t]*" + re.escape(BEGIN) + r".*?" + re.escape(END) + r"[ \t]*\n?",
    re.DOTALL,
)
REMOTE_RE = re.compile(r"<remote>(.*?)</remote>", re.DOTALL)
TAG_RE = r"<{0}>\s*(.*?)\s*</{0}>"
COMMENT_BEFORE_RE = re.compile(r"(?:[ \t]*<!--(?:(?!-->).)*?-->[ \t]*\n)?[ \t]*$", re.DOTALL)


def tag(body, name, default=None):
    m = re.search(TAG_RE.format(re.escape(name)), body, re.DOTALL)
    return m.group(1).strip() if m else default


def remote_blocks(text):
    """Yield dicts for every <remote> block outside the managed block."""
    managed = MANAGED_RE.search(text)
    for m in REMOTE_RE.finditer(text):
        if managed and managed.start() <= m.start() < managed.end():
            continue
        body = m.group(1)
        connection = tag(body, "connection", "secure")
        default_proto = "udp" if connection == "syslog" else "tcp"
        protocols = [p.strip().lower() for p in tag(body, "protocol", default_proto).split(",") if p.strip()]
        default_port = "514" if connection == "syslog" else "1514"
        yield {
            "start": m.start(),
            "end": m.end(),
            "connection": connection,
            "port": tag(body, "port", default_port),
            "protocols": protocols,
            "allowed_ips": re.findall(TAG_RE.format("allowed-ips"), body, re.DOTALL),
            "text": m.group(0),
        }


def conflicts(text, port, proto):
    return [b for b in remote_blocks(text) if b["port"] == str(port) and proto in b["protocols"]]


def format_allowed_ip(val):
    val = val.strip()
    return val if "/" in val else "%s/32" % val


def build_block(port, proto, kerio_ip, listen_ip, indent="  "):
    i2 = indent * 2
    allowed = format_allowed_ip(kerio_ip)
    lines = [
        indent + BEGIN,
        indent + "<remote>",
        i2 + "<connection>syslog</connection>",
        i2 + "<port>%s</port>" % port,
        i2 + "<protocol>%s</protocol>" % proto,
        i2 + "<allowed-ips>%s</allowed-ips>" % allowed,
    ]
    if listen_ip and listen_ip != "0.0.0.0":
        lines.append(i2 + "<local_ip>%s</local_ip>" % listen_ip)
    lines.extend([
        indent + "</remote>",
        indent + END,
    ])
    return "\n".join(lines) + "\n"


def remove_span_with_comment(text, start, end):
    """Remove text[start:end] plus a directly preceding comment mentioning Kerio."""
    head = text[:start]
    m = COMMENT_BEFORE_RE.search(head)
    if m and "kerio" in m.group(0).lower():
        head = head[:m.start()]
    tail = text[end:]
    if tail.startswith("\n"):
        tail = tail[1:]
    return head.rstrip(" \t") + tail


def tidy(text):
    """Collapse runs of blank lines left around the managed block by edits."""
    return re.sub(re.escape(END) + r"\n(?:[ \t]*\n){2,}", END + "\n\n", text)


def render(text, port, proto, kerio_ip, listen_ip, adopt):
    new, found = _render(text, port, proto, kerio_ip, listen_ip, adopt)
    return (tidy(new) if new is not None else None), found


def _render(text, port, proto, kerio_ip, listen_ip, adopt):
    found = conflicts(text, port, proto)
    if found and not adopt:
        return None, found

    # If adopting, remove conflicting unmanaged blocks from back to front
    if found and adopt:
        for b in sorted(found, key=lambda x: x["start"], reverse=True):
            text = remove_span_with_comment(text, b["start"], b["end"])

    m = MANAGED_RE.search(text)
    if m:
        indent = re.match(r"[ \t]*", text[m.start():]).group(0) or "  "
        new_block = build_block(port, proto, kerio_ip, listen_ip, indent)
        return text[:m.start()] + new_block + text[m.end():], []

    # Managed block does not exist: place after the first <ossec_config> tag
    first_tag = re.search(r"<ossec_config[^>]*>\n?", text)
    if not first_tag:
        sys.stderr.write("error: no <ossec_config> tag found in ossec.conf\n")
        sys.exit(2)
    pos = first_tag.end()
    block = build_block(port, proto, kerio_ip, listen_ip, "  ")
    return text[:pos] + "\n" + block + text[pos:], []


def inspect(text, port, proto):
    m = MANAGED_RE.search(text)
    info = {"managed": bool(m), "conflicts": []}
    if m:
        body = m.group(0)
        info["managed_port"] = tag(body, "port")
        info["managed_proto"] = tag(body, "protocol")
        info["managed_allowed_ips"] = re.findall(TAG_RE.format("allowed-ips"), body, re.DOTALL)
        info["managed_local_ip"] = tag(body, "local_ip")
    for b in conflicts(text, port, proto):
        info["conflicts"].append({
            "port": b["port"],
            "protocols": b["protocols"],
            "allowed_ips": b["allowed_ips"],
            "snippet": b["text"][:120],
        })
    return info


def remove(text):
    m = MANAGED_RE.search(text)
    if not m:
        return text, False
    return tidy(text[:m.start()] + text[m.end():]), True


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    p_insp = sub.add_parser("inspect")
    p_insp.add_argument("file")
    p_insp.add_argument("--port", type=int, default=514)
    p_insp.add_argument("--proto", choices=["tcp", "udp"], default="udp")

    p_rnd = sub.add_parser("render")
    p_rnd.add_argument("file")
    p_rnd.add_argument("--port", type=int, default=514)
    p_rnd.add_argument("--proto", choices=["tcp", "udp"], default="udp")
    p_rnd.add_argument("--kerio-ip", required=True)
    p_rnd.add_argument("--listen-ip", required=True)
    p_rnd.add_argument("--adopt", action="store_true")
    p_rnd.add_argument("-o", "--output")

    p_rm = sub.add_parser("remove")
    p_rm.add_argument("file")
    p_rm.add_argument("-o", "--output")

    args = p.parse_args()

    for ip_arg in ["kerio_ip", "listen_ip"]:
        val = getattr(args, ip_arg, None)
        if val:
            try:
                if "/" in val:
                    ipaddress.IPv4Network(val, strict=False)
                else:
                    ipaddress.IPv4Address(val)
            except ValueError as e:
                sys.stderr.write("invalid %s %r: %s\n" % (ip_arg, val, e))
                sys.exit(2)

    try:
        with open(args.file, "r", encoding="utf-8") as f:
            text = f.read()
    except OSError as e:
        sys.stderr.write("cannot read %s: %s\n" % (args.file, e))
        sys.exit(2)

    if args.cmd == "inspect":
        info = inspect(text, args.port, args.proto)
        print(json.dumps(info, indent=2, sort_keys=True))
        sys.exit(3 if info["conflicts"] else 0)

    elif args.cmd == "render":
        new_text, found = render(text, args.port, args.proto, args.kerio_ip, args.listen_ip, args.adopt)
        if new_text is None:
            sys.stderr.write("conflict: unmanaged <remote> block on %s/%s already exists; use --adopt to replace\n"
                             % (args.port, args.proto))
            sys.exit(3)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(new_text)
        else:
            sys.stdout.write(new_text)

    elif args.cmd == "remove":
        new_text, removed = remove(text)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(new_text)
        else:
            sys.stdout.write(new_text)
        sys.exit(0 if removed else 1)


if __name__ == "__main__":
    main()
