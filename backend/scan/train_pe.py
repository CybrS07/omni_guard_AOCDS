"""Train the PE malware model from data/pe_dataset.npz (see build_dataset.py) and store the weights in models/pe_malware.h5.

Guards against fooling yourself:
  * split BY FAMILY: a malware family or a software package is never in train and test at the same time
  * a family counts at most --cap programs (so 267 files of one pack cannot dominate)
  * the scaler is fitted on the training part only, scaling is stored in the .h5
  * dropout + weight decay + early stopping on a validation set; the report says "overfit" / "underfit" when it sees it
  * grouped cross-validation and a label-shuffle control (must score ~50%, otherwise the table leaks the answer)
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np

import pefeatures
import pemodel

HERE = Path(__file__).resolve().parent


def group_split(groups: np.ndarray, y: np.ndarray, rng: np.random.Generator, fr=(0.6, 0.2, 0.2)):
    """Whole groups go to one side; tries a few shuffles until every side has both classes."""
    ug = np.unique(groups)
    for _ in range(200):
        rng.shuffle(ug)
        a, b = int(len(ug) * fr[0]), int(len(ug) * (fr[0] + fr[1]))
        side = {g: 0 if i < a else 1 if i < b else 2 for i, g in enumerate(ug)}
        s = np.array([side[g] for g in groups])
        if all(len(np.unique(y[s == k])) == 2 and (s == k).sum() >= 20 for k in range(3)):
            return s
    raise SystemExit("not enough different families / packages for a split; add more data")


def cap_per_group(groups, y, cap, rng):
    keep = []
    for g in np.unique(groups):
        idx = np.where(groups == g)[0]
        rng.shuffle(idx)
        keep += idx[:cap].tolist()
    return np.array(sorted(keep))


def fit(Xtr, ytr, Xva, yva, seed, hidden=(48, 24), epochs=300, lr=2e-3, wd=2e-3, drop=0.35, patience=25):
    import torch
    from torch import nn
    torch.manual_seed(seed)
    dims = [Xtr.shape[1], *hidden, 1]
    layers: list[nn.Module] = []
    for i in range(len(dims) - 2):
        layers += [nn.Linear(dims[i], dims[i + 1]), nn.ReLU(), nn.Dropout(drop)]
    layers.append(nn.Linear(dims[-2], 1))
    net = nn.Sequential(*layers)
    opt = torch.optim.AdamW(net.parameters(), lr=lr, weight_decay=wd)
    pw = torch.tensor([(ytr == 0).sum() / max((ytr == 1).sum(), 1)], dtype=torch.float32)   # class balance
    loss_fn = nn.BCEWithLogitsLoss(pos_weight=pw)
    xt, yt = torch.tensor(Xtr), torch.tensor(ytr, dtype=torch.float32)
    xv, yv = torch.tensor(Xva), torch.tensor(yva, dtype=torch.float32)
    best, best_state, bad, hist = 9e9, None, 0, []
    g = torch.Generator().manual_seed(seed)
    for ep in range(epochs):
        net.train()
        perm = torch.randperm(len(xt), generator=g)
        for i in range(0, len(perm), 64):
            b = perm[i:i + 64]
            opt.zero_grad()
            loss_fn(net(xt[b])[:, 0], yt[b]).backward()
            opt.step()
        net.eval()
        with torch.no_grad():
            vl = float(nn.BCEWithLogitsLoss()(net(xv)[:, 0], yv))
            tl = float(nn.BCEWithLogitsLoss()(net(xt)[:, 0], yt))
        hist.append((tl, vl))
        if vl < best - 1e-4:
            best, bad = vl, 0
            best_state = {k: v.clone() for k, v in net.state_dict().items()}
        else:
            bad += 1
            if bad >= patience:
                break
    net.load_state_dict(best_state)
    net.eval()
    lin = [m for m in net if isinstance(m, nn.Linear)]
    return [(l.weight.detach().numpy().T.copy(), l.bias.detach().numpy().copy()) for l in lin], len(hist)


def metrics(m, X, y, thr=0.5):
    p = pemodel.predict_matrix(m, X)
    pred = p >= thr
    tp, fp, fn, tn = int(((pred == 1) & (y == 1)).sum()), int(((pred == 1) & (y == 0)).sum()), int(((pred == 0) & (y == 1)).sum()), int(((pred == 0) & (y == 0)).sum())
    from sklearn.metrics import roc_auc_score
    return {"n": int(len(y)), "accuracy": round((tp + tn) / len(y), 4), "precision": round(tp / max(tp + fp, 1), 4), "recall": round(tp / max(tp + fn, 1), 4),
            "false_alarm_rate": round(fp / max(fp + tn, 1), 4), "auc": round(float(roc_auc_score(y, p)), 4), "confusion": {"tp": tp, "fp": fp, "fn": fn, "tn": tn}}


def train_once(X, y, groups, seed, cap, shuffle_labels=False):
    rng = np.random.default_rng(seed)
    keep = cap_per_group(groups, y, cap, rng)
    X, y, groups = X[keep], y[keep].copy(), groups[keep]
    side = group_split(groups, y, rng)
    if shuffle_labels:
        y = rng.permutation(y)
    tr, va, te = side == 0, side == 1, side == 2
    mean, std = X[tr].mean(0), X[tr].std(0) + 1e-6
    sc = lambda a: np.clip((a - mean) / std, -5, 5).astype(np.float32)
    layers, epochs = fit(sc(X[tr]), y[tr], sc(X[va]), y[va], seed)
    m = {"layers": layers, "mean": mean, "std": std}
    return m, {"train": metrics(m, X[tr], y[tr]), "val": metrics(m, X[va], y[va]), "test": metrics(m, X[te], y[te]),
               "epochs": epochs, "sizes": {"train": int(tr.sum()), "val": int(va.sum()), "test": int(te.sum())},
               "families": {"train": int(len(np.unique(groups[tr]))), "val": int(len(np.unique(groups[va]))), "test": int(len(np.unique(groups[te])))}}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=str(HERE / "data" / "pe_dataset.npz"))
    ap.add_argument("--out", default=str(HERE / "models" / pemodel.MODEL_FILE))
    ap.add_argument("--cap", type=int, default=12, help="most programs taken from one family / package")
    ap.add_argument("--seeds", type=int, default=5)
    a = ap.parse_args()
    z = np.load(a.data, allow_pickle=False)
    X, y, groups = z["X"].astype(np.float32), z["y"].astype(np.int64), z["group"]
    assert list(z["names"]) == pefeatures.NAMES, "dataset was built with other features; rebuild it"
    print(f"[train] {len(y)} programs ({int((y == 1).sum())} malware / {int((y == 0).sum())} clean), {len(np.unique(groups))} families+packages")

    runs = [train_once(X, y, groups, 100 + s, a.cap) for s in range(a.seeds)]
    test_acc = [r[1]["test"]["accuracy"] for r in runs]
    ctrl = [train_once(X, y, groups, 900 + s, a.cap, shuffle_labels=True)[1]["test"]["accuracy"] for s in range(3)]
    best = int(np.argsort(test_acc)[len(test_acc) // 2])          # the MEDIAN run is shipped, not the luckiest one
    m, rep = runs[best]
    tr, va, te = rep["train"]["accuracy"], rep["val"]["accuracy"], rep["test"]["accuracy"]
    gap = round(tr - te, 4)
    verdict = ("OVERFIT: train is far above test; add data or lower --cap" if gap > 0.12 else
               "UNDERFIT: even the training part is not learned well" if tr < 0.70 else "balanced: train, validation and test agree")
    report = {
        "trained_on": {"programs": int(len(y)), "malware": int((y == 1).sum()), "clean": int((y == 0).sum()), "families": int(len(np.unique(groups))), "sources": sorted(set(z["source"].tolist()))},
        "cap_per_family": a.cap, "split": "by family (no family in two sides)", "features": pefeatures.N_FEATURES, "scaling": "standardised on train only, clipped at +-5",
        "model": "MLP 99-48-24-1, ReLU, dropout 0.35, AdamW weight-decay, early stopping", **{k: rep[k] for k in ("train", "val", "test", "epochs", "sizes", "families")},
        "train_test_gap": gap, "fit_check": verdict, "threshold": 0.5,
        "repeat_runs_test_accuracy": {"values": test_acc, "mean": round(float(np.mean(test_acc)), 4), "std": round(float(np.std(test_acc)), 4)},
        "label_shuffle_control_accuracy": {"values": ctrl, "mean": round(float(np.mean(ctrl)), 4), "note": "must be near 0.5; if not, the table leaks the answer"},
        "honest_notes": [
            "Static structure only. Packed or brand-new malware can look like clean software, and some clean installers look like malware.",
            "Clean files here come from the data you gave it; results on other kinds of software can differ. Use the Windows folder as clean data for the best model.",
        ],
    }
    pemodel.save_h5(Path(a.out), m["layers"], m["mean"], m["std"], report)
    # prove the file round-trips: reload from disk and compare with the in-memory model
    pemodel._cache.clear()
    loaded = pemodel.load(Path(a.out).parent)
    sample = X[:200]
    assert np.allclose(pemodel.predict_matrix(m, sample), pemodel.predict_matrix(loaded, sample), atol=1e-5), "h5 round trip changed the predictions"
    print(json.dumps({k: report[k] for k in ("train", "val", "test", "train_test_gap", "fit_check", "repeat_runs_test_accuracy", "label_shuffle_control_accuracy")}, indent=1))
    print(f"[train] weights stored in {a.out} ({Path(a.out).stat().st_size // 1024} KB)")


if __name__ == "__main__":
    main()
