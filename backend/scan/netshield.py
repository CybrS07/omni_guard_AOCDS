"""Net-Shield module: a Graph Neural Network that reads this PC's network traffic as a GRAPH and spots worms.

Why a graph: one connection alone says little. A worm leaves a SHAPE: something connects IN to a service, and right after
that the same program connects OUT to many other machines on the same port, and those machines do the same. Scanners have a
different shape (one program touching many addresses, mostly unanswered). Normal traffic is many small stars around a
browser, an updater or a chat program.

Graph
  nodes   every running program that has connections (a "process" node) and every remote address (an "ip" node)
  edges   outbound   process -> address        inbound   address -> process (it connected to a port this PC listens on)
  node features (14 numbers, see FEATURES): kind, private address, in / out degree, ports touched, share of half-open
          connections, share on lateral-movement ports (SMB, RDP, SSH, WinRM ...), single-port concentration, spread over
          subnets, backdoor ports, "inbound then fan-out" chain, fan-out size, share of new connections.
Network (netshield_gnn_int8.onnx, INT8, runs on the CPU in about a millisecond)
  two message-passing layers with separate weights for self / outgoing / incoming neighbours + a graph-wide readout
  -> per node:  normal | scanning | propagating
The graph is cut to the 64 busiest nodes. Result: verdict ok | suspicious | worm, the nodes involved, and the response that
fits (stop the program, block the source address) which the Rust agent runs when automatic response is on.

Scapy / packet capture is NOT needed: the Rust agent already reads the connection table every few seconds, which is enough
to build this graph and keeps the module safe to run without special drivers.
"""
from __future__ import annotations  # type hints may refer to names defined later

import ipaddress  # understands IP addresses
from collections import Counter, defaultdict  # counting helpers
from dataclasses import dataclass  # a simple container class
from typing import Optional  # "a value or None"

import numpy as np  # the graph is made of numpy arrays

import ai_common  # runs the ONNX model

N_MAX = 64  # the graph is cut to the 64 busiest nodes
# the 14 numbers that describe one node
FEATURES = ["is_process", "is_ip", "is_private", "out_degree", "in_degree", "ports_touched", "half_open_share", "lateral_share",
            "top_port_share", "subnet_spread", "backdoor_port", "inbound_then_fanout", "fanout", "new_share"]
F = len(FEATURES)  # how many numbers per node
CLASSES = ["normal", "scanning", "propagating"]  # what the model answers per node
LATERAL = {445, 139, 135, 3389, 22, 23, 5985, 5986, 1433, 3306, 5900, 5432, 2049, 513, 514}  # ports worms use to move between machines
BACKDOOR = {4444, 31337, 6667, 1337, 5555, 12345, 9001, 8888, 6666, 2323, 7777}  # ports backdoors like
THRESHOLD_WORM = 0.80  # probability needed to call something a worm
THRESHOLD_SUSPICIOUS = 0.55  # probability needed to call something suspicious
MIN_TARGETS = 5  # a program that talks to fewer machines than this is not scanning or spreading, whatever the model says
THRESHOLD_SCANNER_KILL = 0.90  # stopping a program that only scans needs more certainty than stopping a worm

_model = ai_common.OnnxModel("netshield_gnn_int8.onnx")  # the network, loaded on first use


def _split(addr: str) -> tuple[str, int]:
    """'1.2.3.4:445' -> ('1.2.3.4', 445); also understands '[::1]:80'."""
    a = (addr or "").strip()  # the text without spaces
    if a.startswith("["):  # IPv6 in brackets
        host, _, port = a[1:].partition("]:")
    else:
        host, _, port = a.rpartition(":")  # split at the last colon
    try:
        return host, int(port)  # the port as a number
    except ValueError:  # no valid port
        return host, 0


def _is_private(ip: str) -> bool:
    """True for addresses inside a home or company network."""
    try:
        o = ipaddress.ip_address(ip)
        return o.is_private or o.is_link_local
    except ValueError:  # not an address
        return False


def _usable(ip: str) -> bool:
    """True for real remote addresses (not loopback, not 0.0.0.0, not multicast)."""
    try:
        o = ipaddress.ip_address(ip)
        return not (o.is_loopback or o.is_unspecified or o.is_multicast)
    except ValueError:
        return False


def _subnet(ip: str) -> str:
    """The first three parts of an IPv4 address (its /24 network)."""
    return ".".join(ip.split(".")[:3]) if "." in ip else ip.rsplit(":", 2)[0]


@dataclass
class Graph:
    """The network traffic as a graph, ready for the model."""
    keys: list[str]  # node keys
    info: list[dict]  # facts about each node, for the dashboard
    x: np.ndarray  # (N_MAX, F) node features
    a_out: np.ndarray  # (N_MAX, N_MAX) row-normalised: mean over the nodes this node connects TO
    a_in: np.ndarray  # (N_MAX, N_MAX) row-normalised: mean over the nodes that connect TO this node
    n: int  # how many real nodes
    truncated: bool = False  # true when more than N_MAX nodes existed


class _Acc:
    """Collects the facts about one node while the graph is built."""
    __slots__ = ("kind", "name", "pid", "out", "inn", "ports", "lports", "syn", "total", "new", "nets")

    def __init__(self, kind: str, name: str, pid: int = 0):
        self.kind, self.name, self.pid = kind, name, pid  # process or ip, its name, its process id
        self.out: set[str] = set()  # node keys this node connects to
        self.inn: set[str] = set()  # node keys that connect to this node
        self.ports: Counter = Counter()  # remote ports (outbound) or ports touched (ip node)
        self.lports: set[int] = set()  # local ports it was contacted on (inbound)
        self.syn = self.total = self.new = 0  # half-open connections, all connections, new connections
        self.nets: set[str] = set()  # networks it touched


def build_graph(conns: list[dict], listening_ports=()) -> Graph:
    """conns: [{local, remote, state, pid, process, new?}]  (Rust `Connection`, plus optional `new`: first seen recently)."""
    listening = {int(p) for p in listening_ports}  # ports this PC listens on
    acc: dict[str, _Acc] = {}  # node key -> its facts

    def node(key: str, kind: str, name: str, pid: int = 0) -> _Acc:
        """The node with this key, created on first use."""
        if key not in acc:
            acc[key] = _Acc(kind, name, pid)
        return acc[key]

    for c in conns:  # every connection
        state = str(c.get("state", "")).upper()  # its state
        if state in ("LISTENING", "LISTEN"):  # a listening socket is not a connection
            continue
        rip, rport = _split(c.get("remote", ""))  # remote address and port
        _, lport = _split(c.get("local", ""))  # local port
        if not _usable(rip):  # loopback and the like are ignored
            continue
        pid, pname = int(c.get("pid", 0) or 0), str(c.get("process", "") or f"pid{c.get('pid', 0)}")  # who owns it
        pk, ik = f"p:{pid}:{pname}", f"i:{rip}"  # node keys of the program and of the address
        p, i = node(pk, "process", pname, pid), node(ik, "ip", rip)  # the two nodes
        inbound = lport in listening and rport not in listening  # someone connected to a port we listen on
        half = state in ("SYN_SENT", "SYN_RECEIVED", "SYN_RECV")  # a connection that was never answered
        new = bool(c.get("new", False))  # opened during the last minute
        i.nets.add(_subnet(rip))  # the address's network
        if inbound:  # edge: address -> program
            i.out.add(pk)
            p.inn.add(ik)
            p.lports.add(lport)
            i.ports[lport] += 1
            i.total += 1
            p.total += 1
            i.syn += half
            p.syn += half
            i.new += new
            p.new += new
        else:  # edge: program -> address
            p.out.add(ik)
            i.inn.add(pk)
            p.ports[rport] += 1
            i.ports[rport] += 1
            p.nets.add(_subnet(rip))
            p.total += 1
            i.total += 1
            p.syn += half
            i.syn += half
            p.new += new
            i.new += new

    # keep the 64 busiest nodes
    ranked = sorted(acc, key=lambda k: (-(len(acc[k].out) + len(acc[k].inn)), -acc[k].total, k))  # busiest first
    keep = ranked[:N_MAX]  # cut to 64
    index = {k: j for j, k in enumerate(keep)}  # node key -> row number
    x = np.zeros((N_MAX, F), dtype=np.float32)  # node features
    a_out = np.zeros((N_MAX, N_MAX), dtype=np.float32)  # outgoing edges
    a_in = np.zeros((N_MAX, N_MAX), dtype=np.float32)  # incoming edges
    info: list[dict] = []  # facts for the dashboard
    for k in keep:  # every kept node
        a, j = acc[k], index[k]  # its facts and its row
        out_d, in_d = len(a.out), len(a.inn)  # how many it connects to / is connected from
        tot = max(a.total, 1)  # connection count (never zero, it is a divisor)
        ports = a.ports  # ports it touched
        top = (max(ports.values()) / sum(ports.values())) if ports else 0.0  # how much one port dominates
        lateral = sum(v for p_, v in ports.items() if p_ in LATERAL) / max(sum(ports.values()), 1)  # share of lateral-movement ports
        shared = bool(a.lports & (set(ports) | LATERAL)) or any(p_ in LATERAL for p_ in a.lports)  # contacted on a port it also uses outbound
        chain = 1.0 if (a.kind == "process" and in_d >= 1 and out_d >= 5 and shared) else 0.0  # "inbound, then fan-out" worm shape
        row = [a.kind == "process", a.kind == "ip", a.kind == "ip" and _is_private(a.name),
               min(np.log1p(out_d) / 4.0, 1.0), min(np.log1p(in_d) / 4.0, 1.0), min(len(ports) / 16.0, 1.0),
               a.syn / tot, lateral, top, (len(a.nets) / max(out_d, 1)) if out_d else 0.0,
               1.0 if (set(ports) & BACKDOOR or a.lports & BACKDOOR) else 0.0, chain, min(out_d / 32.0, 1.0), a.new / tot]  # the 14 numbers, in the order of FEATURES
        x[j] = np.asarray(row, dtype=np.float32)
        outs = [index[o] for o in a.out if o in index]  # kept nodes it connects to
        ins = [index[o] for o in a.inn if o in index]  # kept nodes that connect to it
        for o in outs:
            a_out[j, o] = 1.0 / len(outs)  # equal weight per neighbour
        for o in ins:
            a_in[j, o] = 1.0 / len(ins)
        info.append({"key": k, "kind": a.kind, "name": a.name, "pid": a.pid, "out": out_d, "in": in_d, "ports": sorted(ports, key=lambda p_: -ports[p_])[:6],
                     "lateral_share": round(float(lateral), 2), "half_open_share": round(a.syn / tot, 2)})
    return Graph(keep, info, x, a_out, a_in, len(keep), truncated=len(acc) > N_MAX)


def _logits(g: Graph) -> np.ndarray:
    """Runs the network on one graph and returns its raw scores per node."""
    out = _model.run({"x": g.x[None], "a_out": g.a_out[None], "a_in": g.a_in[None]})[0]  # a batch of one graph
    return out[0]


def analyze(conns: list[dict], listening_ports=()) -> dict:
    """The whole job: connections -> graph -> GNN -> verdict + the nodes to blame + the response that fits."""
    base = {"verdict": "ok", "score": 0.0, "nodes": [], "reasons": [], "actions": [], "graph": {"nodes": 0, "edges": 0, "truncated": False}, "error": None}  # the default answer: all fine
    if not ai_common.available():  # no onnxruntime
        base["error"] = "onnxruntime is not installed"
        return base
    try:
        g = build_graph(conns, listening_ports)  # build the graph
        base["graph"] = {"nodes": g.n, "edges": int((g.a_out > 0).sum()), "truncated": g.truncated}
        if g.n == 0:  # nothing to judge
            return base
        p = ai_common.softmax(_logits(g), axis=1)[:g.n]  # probabilities per node: normal / scanning / propagating
    except Exception as e:  # a failing model must never break the service
        base["error"] = f"{type(e).__name__}: {e}"
        return base
    worm = scan = 0.0  # the strongest worm and scanner probabilities
    nodes = []  # nodes worth showing
    for j, meta in enumerate(g.info):
        pw, ps = float(p[j, 2]), float(p[j, 1])  # propagating and scanning probability
        if max(pw, ps) < THRESHOLD_SUSPICIOUS:  # normal
            continue
        if meta.get("kind") == "process" and meta.get("out", 0) < MIN_TARGETS:  # too few targets to be a scanner or worm
            continue
        label = "propagating" if pw >= ps else "scanning"  # the likelier of the two
        prob = max(pw, ps)
        nodes.append({**meta, "label": label, "prob": round(prob, 4)})
        worm, scan = max(worm, pw), max(scan, ps)
    nodes.sort(key=lambda n_: -n_["prob"])  # most likely first
    base["nodes"] = nodes[:12]
    score = max(worm, scan * 0.9)  # a scanner counts a little less than a worm
    base["score"] = round(score, 4)
    if worm >= THRESHOLD_WORM:
        base["verdict"] = "worm"
    elif score >= THRESHOLD_SUSPICIOUS:
        base["verdict"] = "suspicious"
    reasons, actions = [], []  # plain-English reasons and recommended responses
    for n_ in base["nodes"]:
        if n_["prob"] < THRESHOLD_SUSPICIOUS:
            continue
        if n_["kind"] == "process":  # a program
            what = "spreading like a worm: it was contacted from outside and now connects to many machines on the same port" if n_["label"] == "propagating" \
                else "scanning: it touches many addresses, most of them half-open"
            reasons.append(f"{n_['name']} (pid {n_['pid']}) is {what} ({n_['out']} targets, ports {n_['ports']}, {round(n_['prob'] * 100)}% sure)")
            if n_["prob"] >= (THRESHOLD_WORM if n_["label"] == "propagating" else THRESHOLD_SCANNER_KILL) and n_["pid"]:  # sure enough to recommend ending it
                actions.append({"kind": "kill_process", "pid": n_["pid"], "name": n_["name"], "reason": f"Net-Shield: {n_['label']} ({round(n_['prob'] * 100)}%)"})
        else:  # an address
            if n_["label"] == "propagating":
                reasons.append(f"{n_['name']} connected in and the traffic fanned out afterwards: likely the infected source ({round(n_['prob'] * 100)}% sure)")
                if n_["prob"] >= THRESHOLD_WORM:  # sure enough to recommend blocking it
                    actions.append({"kind": "block_ip", "ip": n_["name"], "reason": f"Net-Shield: source of worm propagation ({round(n_['prob'] * 100)}%)"})
    base["reasons"], base["actions"] = reasons[:8], actions[:8]  # keep the answer short
    return base


def status() -> dict:
    """What the status page shows about the model."""
    return {"model": _model.status(), "classes": CLASSES, "features": FEATURES, "max_nodes": N_MAX, "runtime": ai_common.available()}


def reload() -> None:
    """Forget the loaded model so the current file is read next time."""
    _model.reload()
