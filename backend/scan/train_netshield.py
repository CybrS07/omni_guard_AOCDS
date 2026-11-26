"""Train the Net-Shield graph neural network, export it to ONNX and quantise it to INT8.

    python train_netshield.py                  # generated traffic graphs
    python train_netshield.py --extra-json my_graphs.json   # your own labelled captures (see read_extra)

Training graphs are generated as lists of CONNECTIONS (the same raw input the agent sends at run time) and then turned into
graphs by `netshield.build_graph`, so training and run time cannot disagree about features.

Normal traffic: browsers, updaters, chat, DNS, file shares, SSH/RDP clients, and HARD cases that look busy but are harmless
(a backup client reaching 20 file servers over SMB, a torrent client with 60 peers, a browser with 40 tabs).
Bad traffic: internal and public scanners, multi-port scanners, and worms that spread over SMB, RDP, SSH and HTTP (an inbound
connection into a service, then the same program fanning out to many machines on that port, sometimes with several earlier
victims connecting back).

Honest evaluation: the first run leaves out three FAMILIES (the multi-port scanner, the SSH worm, the HTTP worm) and tests on
them. The shipped network is then trained on everything. Real captures always beat generated ones.
Needs the training extras (torch, onnx) - not shipped in the app:   uv sync --group train
"""
from __future__ import annotations

import argparse
import json
import os
import random
import time
from pathlib import Path

import numpy as np

import ai_common
import netshield
from netshield import CLASSES, F, N_MAX

BROWSERS = ["chrome.exe", "msedge.exe", "firefox.exe", "brave.exe"]
APPS = ["Teams.exe", "slack.exe", "OneDrive.exe", "Spotify.exe", "Code.exe", "steam.exe", "Zoom.exe", "Dropbox.exe", "python.exe", "node.exe", "git.exe", "curl.exe"]
SERVICES = ["svchost.exe", "System", "services.exe", "lsass.exe", "spoolsv.exe", "sshd.exe", "w3wp.exe", "nginx.exe"]


class World:
    """One generated host: keeps unique pids and the list of connections."""

    def __init__(self, r: random.Random):
        self.r = r
        self.conns: list[dict] = []
        self.listening: set[int] = set()
        self.labels: dict[str, int] = {}     # node key -> class
        self.pid = r.randrange(1000, 4000, 4)
        self.me = f"192.168.{r.randrange(0, 4)}.{r.randrange(2, 250)}"
        self.net = r.randrange(0, 4)

    def new_pid(self) -> int:
        self.pid += self.r.randrange(4, 400, 4)
        return self.pid

    def pub(self) -> str:
        r = self.r
        while True:
            ip = f"{r.randrange(11, 224)}.{r.randrange(0, 256)}.{r.randrange(0, 256)}.{r.randrange(1, 255)}"
            if not ip.startswith(("127.", "10.", "192.168.", "172.")):
                return ip

    def priv(self, same_net: bool = True) -> str:
        r = self.r
        return f"192.168.{self.net if same_net else r.randrange(0, 8)}.{r.randrange(1, 255)}"

    def out(self, name, pid, rip, rport, state="ESTABLISHED", new=False):
        self.conns.append({"local": f"{self.me}:{self.r.randrange(49152, 65535)}", "remote": f"{rip}:{rport}", "state": state, "pid": pid, "process": name, "new": new})

    def inn(self, name, pid, rip, lport, state="ESTABLISHED", new=False):
        self.listening.add(lport)
        self.conns.append({"local": f"{self.me}:{lport}", "remote": f"{rip}:{self.r.randrange(49152, 65535)}", "state": state, "pid": pid, "process": name, "new": new})

    def label(self, name, pid, cls):
        self.labels[f"p:{pid}:{name}"] = cls

    def label_ip(self, ip, cls):
        self.labels[f"i:{ip}"] = cls


def _states(r, n, half):
    return ["SYN_SENT" if r.random() < half else r.choice(["ESTABLISHED", "ESTABLISHED", "TIME_WAIT"]) for _ in range(n)]


# ---------------------------------------------------------------- normal
def n_browser(w):
    r, pid, name = w.r, w.new_pid(), w.r.choice(BROWSERS)
    for _ in range(r.randrange(5, 46)):
        w.out(name, pid, w.pub(), r.choice([443, 443, 443, 80, 8443]), r.choice(["ESTABLISHED", "ESTABLISHED", "TIME_WAIT", "SYN_SENT"] if r.random() < 0.3 else ["ESTABLISHED"]), new=r.random() < 0.45)


def n_app(w):
    r, pid, name = w.r, w.new_pid(), w.r.choice(APPS)
    for _ in range(r.randrange(1, 6)):
        w.out(name, pid, w.pub(), r.choice([443, 443, 80, 5228, 3478]), new=r.random() < 0.3)


def n_dns(w):
    r, pid = w.r, w.new_pid()
    for _ in range(r.randrange(1, 9)):
        w.out("svchost.exe", pid, w.pub() if r.random() < 0.7 else w.priv(), 53, "", new=r.random() < 0.6)


def n_fileserver(w):
    r, pid = w.r, w.new_pid()
    for _ in range(r.randrange(1, 5)):
        w.inn("System", pid, w.priv(r.random() < 0.8), r.choice([445, 445, 139]), new=r.random() < 0.3)


def n_backup(w):      # hard: many internal SMB targets, but established, old connections
    r, pid, name = w.r, w.new_pid(), w.r.choice(["backup.exe", "robocopy.exe", "veeam.exe", "syncthing.exe"])
    for _ in range(r.randrange(6, 22)):
        w.out(name, pid, w.priv(r.random() < 0.7), 445, "ESTABLISHED", new=r.random() < 0.2)


def n_torrent(w):     # hard: dozens of public peers, mixed ports
    r, pid, name = w.r, w.new_pid(), w.r.choice(["qbittorrent.exe", "utorrent.exe", "transmission.exe"])
    for _ in range(r.randrange(25, 70)):
        w.out(name, pid, w.pub(), r.randrange(1025, 65000), r.choice(["ESTABLISHED", "SYN_SENT", "ESTABLISHED"]), new=r.random() < 0.5)


def n_admin_clients(w):
    r = w.r
    for name, port in (("ssh.exe", 22), ("mstsc.exe", 3389), ("powershell.exe", 5985)):
        if r.random() < 0.4:
            pid = w.new_pid()
            for _ in range(r.randrange(1, 4)):
                w.out(name, pid, w.priv(r.random() < 0.7), port, "ESTABLISHED", new=r.random() < 0.3)


def n_dev_server(w):  # hard: listens, a few inbound from LAN
    r, pid = w.r, w.new_pid()
    port = r.choice([8080, 3000, 5000, 80, 8000])
    for _ in range(r.randrange(1, 6)):
        w.inn(r.choice(["node.exe", "python.exe", "nginx.exe", "w3wp.exe"]), pid, w.priv(), port, new=r.random() < 0.4)


def n_dfs(w):         # hard: a file server that is contacted AND talks to many peers (replication) - looks like a worm hop
    r, pid, port = w.r, w.new_pid(), w.r.choice([445, 445, 139, 3389])
    for _ in range(r.randrange(1, 4)):
        w.inn("System", pid, w.priv(), port, new=r.random() < 0.5)
    for st in _states(r, r.randrange(5, 18), r.uniform(0.0, 0.3)):
        w.out("System", pid, w.priv(r.random() < 0.8), port, st, new=r.random() < 0.5)


def n_monitor(w):     # hard: monitoring / inventory agent probing many internal hosts, fresh connections, a few half-open
    r, pid, name = w.r, w.new_pid(), w.r.choice(["zabbix_agentd.exe", "nagios.exe", "lansweeper.exe", "pdq.exe", "ansible.exe"])
    port = r.choice([22, 445, 5985, 161, 3389])
    for st in _states(r, r.randrange(8, 32), r.uniform(0.0, 0.35)):
        w.out(name, pid, w.priv(r.random() < 0.8), port, st, new=r.random() < 0.7)


NORMAL = [n_browser, n_browser, n_app, n_app, n_dns, n_fileserver, n_backup, n_torrent, n_admin_clients, n_dev_server, n_dfs, n_monitor]


# ---------------------------------------------------------------- bad
def _bad_name(r):
    return r.choice(["svchost.exe", "svch0st.exe", "".join(r.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(r.randrange(5, 9))) + ".exe", "update.exe", "winhost.exe", "rundll32.exe", "msedge_update.exe"])


def b_scan_internal(w):
    r, pid, name = w.r, w.new_pid(), _bad_name(w.r)
    port = r.choice([445, 3389, 22, 139, 135, 5985, 1433])
    n = r.randrange(15, 61)
    for st in _states(r, n, r.uniform(0.15, 0.95)):
        w.out(name, pid, w.priv(r.random() < 0.8), port, st, new=r.random() < r.uniform(0.5, 1.0))
    w.label(name, pid, 1)


def b_scan_public(w):
    r, pid, name = w.r, w.new_pid(), _bad_name(w.r)
    port = r.choice([445, 23, 22, 2323, 1433, 3389, 5555])
    for st in _states(r, r.randrange(20, 61), r.uniform(0.3, 0.95)):
        w.out(name, pid, w.pub(), port, st, new=r.random() < r.uniform(0.5, 1.0))
    w.label(name, pid, 1)


def b_scan_multiport(w):          # held out: slow / multi-port scanner
    r, pid, name = w.r, w.new_pid(), _bad_name(w.r)
    ports = [r.choice([21, 22, 23, 80, 135, 139, 443, 445, 1433, 3306, 3389, 5900, 8080]) for _ in range(r.randrange(3, 7))]
    for st in _states(r, r.randrange(8, 15), r.uniform(0.2, 0.8)):
        w.out(name, pid, w.priv() if r.random() < 0.6 else w.pub(), r.choice(ports), st, new=r.random() < r.uniform(0.4, 1.0))
    w.label(name, pid, 1)


def _worm(w, port, svc_names, inbound_sources=1, fan=(5, 50), public=False):
    r, pid = w.r, w.new_pid()
    name = r.choice(svc_names)
    for _ in range(inbound_sources):
        src = w.pub() if public else w.priv(r.random() < 0.7)
        w.inn(name, pid, src, port, "ESTABLISHED", new=True)
        w.label_ip(src, 2)
    for st in _states(r, r.randrange(*fan), r.uniform(0.05, 0.9)):
        w.out(name, pid, w.pub() if public or r.random() < 0.2 else w.priv(r.random() < 0.8), port, st, new=r.random() < r.uniform(0.4, 1.0))
    w.label(name, pid, 2)


def b_worm_smb(w):
    _worm(w, 445, ["System", "svchost.exe", "lsass.exe"], r_pick(w, 1, 3))


def b_worm_rdp(w):
    _worm(w, 3389, ["svchost.exe", "TermService", "rdpclip.exe"], r_pick(w, 1, 2))


def b_worm_multigen(w):
    _worm(w, w.r.choice([445, 135, 139]), ["svchost.exe", "System", "spoolsv.exe"], r_pick(w, 2, 5), fan=(12, 56), public=w.r.random() < 0.4)


def b_worm_ssh(w):                # held out
    _worm(w, 22, ["sshd.exe", "sshd", "dropbear"], r_pick(w, 1, 3), fan=(6, 40))


def b_worm_http(w):               # held out
    _worm(w, w.r.choice([8080, 80, 8000, 7001]), ["w3wp.exe", "tomcat.exe", "nginx.exe", "httpd.exe"], r_pick(w, 1, 3), fan=(8, 45), public=w.r.random() < 0.5)


def r_pick(w, lo, hi):
    return w.r.randrange(lo, hi + 1)


BAD = {f.__name__: f for f in [b_scan_internal, b_scan_public, b_scan_multiport, b_worm_smb, b_worm_rdp, b_worm_multigen, b_worm_ssh, b_worm_http]}
HELD = {"b_scan_multiport", "b_worm_ssh", "b_worm_http"}


def make_graph(r: random.Random, kind: str, allow=None, only=None):
    """kind: 'normal' | 'bad'. Returns (Graph, labels[N_MAX], family)."""
    w = World(r)
    for f in r.sample(NORMAL, r.randrange(2, 6)):
        f(w)
    fam = "normal"
    if kind == "bad":
        names = [n for n in BAD if (allow is None or n not in allow) and (only is None or n in only)]
        picks = r.sample(names, 1 if r.random() < 0.75 else min(2, len(names)))
        fam = "+".join(picks)
        for n in picks:
            BAD[n](w)
    # shuffle connection order: the order must not matter
    r.shuffle(w.conns)
    g = netshield.build_graph(w.conns, w.listening)
    y = np.full(N_MAX, -100, dtype=np.int64)
    for j, k in enumerate(g.keys):
        y[j] = w.labels.get(k, 0)
    return g, y, fam


def build(n, r, kind_mix=0.6, allow=None, only=None, kinds=None):
    G, Y, fams, kinds_out = [], [], [], []
    for _ in range(n):
        kind = kinds if kinds else ("bad" if r.random() < kind_mix else "normal")
        g, y, fam = make_graph(r, kind, allow=allow, only=only)
        G.append(g)
        Y.append(y)
        fams.append(fam)
        kinds_out.append(kind)
    x = np.stack([g.x for g in G])
    ao = np.stack([g.a_out for g in G])
    ai = np.stack([g.a_in for g in G])
    return x, ao, ai, np.stack(Y), fams, kinds_out


def read_extra(path: Path):
    """JSON list of {"connections": [...], "listening": [ports], "labels": {"p:<pid>:<name>": 1|2, "i:<ip>": 2}}"""
    G, Y = [], []
    for item in json.loads(Path(path).read_text(encoding="utf-8")):
        g = netshield.build_graph(item["connections"], item.get("listening", []))
        y = np.full(N_MAX, -100, dtype=np.int64)
        for j, k in enumerate(g.keys):
            y[j] = int(item.get("labels", {}).get(k, 0))
        G.append(g)
        Y.append(y)
    if not G:
        return None
    return np.stack([g.x for g in G]), np.stack([g.a_out for g in G]), np.stack([g.a_in for g in G]), np.stack(Y)


# ---------------------------------------------------------------- network
def make_net(hidden=24):
    import torch
    from torch import nn

    class Layer(nn.Module):
        def __init__(self, i, o):
            super().__init__()
            self.s, self.o, self.i = nn.Linear(i, o), nn.Linear(i, o, bias=False), nn.Linear(i, o, bias=False)

        def forward(self, h, ao, ai):
            return torch.relu(self.s(h) + torch.matmul(ao, self.o(h)) + torch.matmul(ai, self.i(h)))

    class GNN(nn.Module):
        def __init__(self):
            super().__init__()
            self.l1, self.l2 = Layer(F, hidden), Layer(hidden, hidden)
            self.out = nn.Sequential(nn.Linear(hidden * 2, hidden), nn.ReLU(), nn.Linear(hidden, len(CLASSES)))

        def forward(self, x, a_out, a_in):
            mask = (x.abs().sum(-1, keepdim=True) > 0).to(x.dtype)
            h = self.l2(self.l1(x, a_out, a_in) * mask, a_out, a_in) * mask
            g = h.sum(1, keepdim=True) / (mask.sum(1, keepdim=True) + 1e-6)     # readout: what does the whole graph look like
            return self.out(torch.cat([h, g.expand(-1, h.shape[1], -1)], dim=-1))

    return GNN()


def train(data, epochs, seed, log=print):
    import torch
    from torch import nn

    torch.manual_seed(seed)
    torch.set_num_threads(max(1, (os.cpu_count() or 2) // 2 + 1))
    x, ao, ai, y = (torch.from_numpy(a) for a in data)
    net = make_net()
    opt = torch.optim.AdamW(net.parameters(), lr=4e-3, weight_decay=1e-4)
    steps = epochs * ((len(y) + 63) // 64)
    sched = torch.optim.lr_scheduler.OneCycleLR(opt, max_lr=6e-3, total_steps=steps)
    lossf = nn.CrossEntropyLoss(weight=torch.tensor([1.0, 3.0, 4.0]), ignore_index=-100)
    g = torch.Generator().manual_seed(seed)
    for ep in range(epochs):
        net.train()
        order = torch.randperm(len(y), generator=g)
        tot = 0.0
        for s in range(0, len(y), 64):
            b = order[s:s + 64]
            opt.zero_grad()
            out = net(x[b], ao[b], ai[b])
            loss = lossf(out.reshape(-1, len(CLASSES)), y[b].reshape(-1))
            loss.backward()
            opt.step()
            sched.step()
            tot += float(loss.detach()) * len(b)
        if ep % 5 == 4 or ep == epochs - 1:
            log(f"  epoch {ep + 1:2d}/{epochs}  loss {tot / len(y):.4f}")
    net.eval()
    return net


def torch_logits(net, x, ao, ai):
    import torch

    with torch.no_grad():
        return net(torch.from_numpy(x), torch.from_numpy(ao), torch.from_numpy(ai)).numpy()


def ort_logits(path, x, ao, ai, batch=128):
    sess = ai_common._session(path)
    return np.concatenate([sess.run(None, {"x": x[i:i + batch], "a_out": ao[i:i + batch], "a_in": ai[i:i + batch]})[0] for i in range(0, len(x), batch)])


def evaluate(logits, y, kinds, tag):
    pred = logits.argmax(-1)
    valid = y != -100
    node_acc = float((pred[valid] == y[valid]).mean())
    p = ai_common.softmax(logits, axis=-1)
    worm_node = p[..., 2] * valid
    scan_node = p[..., 1] * valid
    score = np.maximum(worm_node.max(1), scan_node.max(1) * 0.9)
    flagged = score >= netshield.THRESHOLD_SUSPICIOUS
    bad = np.asarray([k == "bad" for k in kinds])
    has_worm = ((y == 2).any(1))
    worm_called = worm_node.max(1) >= netshield.THRESHOLD_WORM
    r = {"node_accuracy": round(node_acc, 4), "bad_graph_recall": round(float(flagged[bad].mean()), 4) if bad.any() else None,
         "worm_graph_recall": round(float(worm_called[has_worm].mean()), 4) if has_worm.any() else None,
         "false_alarm_rate_on_normal_graphs": round(float(flagged[~bad].mean()), 4) if (~bad).any() else None,
         "false_worm_call_rate_on_normal_graphs": round(float(worm_called[~bad].mean()), 4) if (~bad).any() else None, "graphs": int(len(y))}
    print(f"  {tag:<34} node acc {r['node_accuracy']:.3f}   bad graphs caught {r['bad_graph_recall']}   worms named {r['worm_graph_recall']}   warnings on normal {r['false_alarm_rate_on_normal_graphs']}   false WORM calls {r['false_worm_call_rate_on_normal_graphs']}   (n={r['graphs']})")
    return r


def export_onnx(net, path: Path):
    import torch

    x, ao, ai = torch.zeros(1, N_MAX, F), torch.zeros(1, N_MAX, N_MAX), torch.zeros(1, N_MAX, N_MAX)
    kw = dict(input_names=["x", "a_out", "a_in"], output_names=["logits"], dynamic_axes={"x": {0: "n"}, "a_out": {0: "n"}, "a_in": {0: "n"}, "logits": {0: "n"}}, opset_version=17)
    try:
        torch.onnx.export(net, (x, ao, ai), str(path), dynamo=False, **kw)
    except TypeError:
        torch.onnx.export(net, (x, ao, ai), str(path), **kw)


def quantize_int8(fp32: Path, out: Path):
    from onnxruntime.quantization import QuantType, quantize_dynamic
    from onnxruntime.quantization.shape_inference import quant_pre_process

    pre = fp32.with_name(fp32.stem + ".pre.onnx")
    quant_pre_process(str(fp32), str(pre), skip_symbolic_shape=True)
    quantize_dynamic(str(pre), str(out), weight_type=QuantType.QInt8, op_types_to_quantize=["MatMul", "Gemm"])
    pre.unlink(missing_ok=True)


def latency_ms(path, x, ao, ai, reps=40):
    sess = ai_common._session(path)
    f = {"x": x[:1], "a_out": ao[:1], "a_in": ai[:1]}
    sess.run(None, f)
    t = []
    for _ in range(reps):
        t0 = time.perf_counter()
        sess.run(None, f)
        t.append((time.perf_counter() - t0) * 1000)
    return round(float(np.median(t)), 2)


def main(argv=None) -> dict:
    ap = argparse.ArgumentParser()
    ap.add_argument("--graphs", type=int, default=5000)
    ap.add_argument("--epochs", type=int, default=30)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--out", default=str(ai_common.BUNDLED_DIR))
    ap.add_argument("--extra-json", action="append", default=[])
    a = ap.parse_args(argv)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    r = random.Random(a.seed)

    print(f"building {a.graphs} training graphs (3 families held out for the honest test) ...")
    tr = build(a.graphs, r, allow=HELD)
    te_known = build(600, random.Random(a.seed + 100), allow=HELD)
    te_novel = build(400, random.Random(a.seed + 200), only=HELD, kind_mix=0.8)
    print(f"  bad graph families seen: {len(BAD) - len(HELD)}; held out: {sorted(HELD)}")
    net = train(tr[:4], a.epochs, a.seed)
    print("evaluation run (trained WITHOUT the held-out families):")
    res_known = evaluate(torch_logits(net, *te_known[:3]), te_known[3], te_known[5], "A  new graphs, known families")
    res_novel = evaluate(torch_logits(net, *te_novel[:3]), te_novel[3], te_novel[5], "B  unseen families (held out)")
    ev32, ev8 = out / "_eval_fp32.onnx", out / "_eval_int8.onnx"
    export_onnx(net, ev32)
    quantize_int8(ev32, ev8)
    q_known = evaluate(ort_logits(ev8, *te_known[:3]), te_known[3], te_known[5], "A  INT8 (ONNX Runtime)")
    q_novel = evaluate(ort_logits(ev8, *te_novel[:3]), te_novel[3], te_novel[5], "B  INT8 (ONNX Runtime)")
    for f in (ev32, ev8):
        f.unlink(missing_ok=True)

    print("shipped model: trained on every family ...")
    full = build(a.graphs, random.Random(a.seed + 1), allow=None)
    data = list(full[:4])
    for p in a.extra_json:
        got = read_extra(Path(p))
        if got:
            data = [np.concatenate([d, g]) for d, g in zip(data, got)]
            print(f"added {len(got[0])} real graphs from {p}")
    net = train(tuple(data), a.epochs, a.seed + 1)
    fp32, int8 = out / "netshield_gnn_fp32.onnx", out / "netshield_gnn_int8.onnx"
    export_onnx(net, fp32)
    quantize_int8(fp32, int8)
    ref = torch_logits(net, *te_known[:3])
    o32, o8 = ort_logits(fp32, *te_known[:3]), ort_logits(int8, *te_known[:3])
    valid = te_known[3] != -100
    agree = float((o8.argmax(-1)[valid] == o32.argmax(-1)[valid]).mean())
    drift = float(np.abs(o32 - ref).max())
    lat32, lat8 = latency_ms(fp32, *te_known[:3]), latency_ms(int8, *te_known[:3])
    s32, s8 = fp32.stat().st_size / 1024, int8.stat().st_size / 1024
    print(f"size fp32 {s32:.0f} KB -> int8 {s8:.0f} KB   latency per graph fp32 {lat32} ms  int8 {lat8} ms   int8/fp32 agreement {agree:.4f}   torch-vs-onnx drift {drift:.5f}")
    fp32.unlink()
    report = {"trained_at": time.time(), "seed": a.seed, "epochs": a.epochs, "training_graphs": int(len(data[0])), "classes": CLASSES, "held_out_families": sorted(HELD),
              "known_families": res_known, "unseen_families": res_novel, "int8_known_families": q_known, "int8_unseen_families": q_novel,
              "int8_fp32_agreement": round(agree, 4), "size_kb_fp32": round(s32, 1), "size_kb_int8": round(s8, 1), "latency_ms_per_graph_fp32": lat32, "latency_ms_per_graph_int8": lat8,
              "note": "generated traffic; add real captures with --extra-json"}
    ai_common.write_manifest({"netshield_gnn_int8.onnx": {**report, "sha256": ai_common.sha256_of(int8)}}, out)
    return report


if __name__ == "__main__":
    main()
