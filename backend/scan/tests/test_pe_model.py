"""The PE malware model: HDF5 weights, honest report, same features for training and scanning."""
import glob
import os
import sys

import numpy as np
import pytest

import ai_common
import filescan
import pefeatures
import pemodel

h5py = pytest.importorskip("h5py")


def _real_pe():
    """Some genuine Windows program that ships inside pip (a tiny launcher), so no sample has to live in the repo."""
    import pip
    hits = glob.glob(os.path.join(os.path.dirname(pip.__file__), "_vendor", "distlib", "*.exe"))
    if not hits:
        pytest.skip("no Windows launcher in this pip")
    return open(hits[0], "rb").read()


def test_weights_are_in_an_hdf5_file_that_ships_with_the_app():
    p = pemodel.model_path(ai_common.BUNDLED_DIR)
    assert p.exists() and p.suffix == ".h5"
    with h5py.File(p, "r") as f:
        assert {"scaler", "layer0", "feature_names"} <= set(f.keys())
        assert f["scaler/mean"].shape == (pefeatures.N_FEATURES,) and f["layer0/W"].shape[0] == pefeatures.N_FEATURES
    assert pemodel.status(ai_common.BUNDLED_DIR)["loaded"]


def test_report_claims_a_balanced_fit_and_a_clean_shuffle_control():
    rep = pemodel.load(ai_common.BUNDLED_DIR)["report"]
    assert rep["test"]["accuracy"] >= 0.75, "the project promise: 75-80% or better on families the model never saw"
    assert rep["train_test_gap"] <= 0.12 and rep["train"]["accuracy"] >= 0.70, rep["fit_check"]
    assert rep["label_shuffle_control_accuracy"]["mean"] < 0.70, "shuffled labels must not be learnable"
    assert rep["split"].startswith("by family")


def test_features_are_stable_and_non_pe_is_ignored():
    pe = _real_pe()
    v1, v2 = pefeatures.extract(pe), pefeatures.extract(pe)
    assert v1.shape == (pefeatures.N_FEATURES,) and np.array_equal(v1, v2) and np.isfinite(v1).all()
    assert pefeatures.extract(b"hello" * 500) is None and pefeatures.extract(b"MZ" + b"\x00" * 600) is None
    assert pemodel.score(ai_common.BUNDLED_DIR, b"not a program" * 100) is None


def test_scoring_a_real_clean_program_is_low_and_has_reasons():
    sc = pemodel.score(ai_common.BUNDLED_DIR, _real_pe())
    assert sc and 0.0 <= sc["probability"] <= 1.0 and len(sc["reasons"]) == 3
    assert sc["probability"] < 0.9      # a pip launcher is not malware; must never reach the "high" level


def test_scanner_adds_the_model_result_and_never_alone_critical(tmp_path):
    p = tmp_path / "launcher.exe"
    p.write_bytes(_real_pe())
    res = filescan.analyze(filescan.AnalyzeIn(path=str(p), name="launcher.exe", size=p.stat().st_size, sha256="", kind="pe", allow_vt=False))
    assert res["pe_ai"] is not None
    assert all(f["severity"] != "critical" for f in res["findings"] if f["id"] == "ai-pe-malware")


def test_corrupt_weights_switch_the_model_off_instead_of_crashing(tmp_path):
    (tmp_path / pemodel.MODEL_FILE).write_bytes(b"not hdf5")
    assert pemodel.load(tmp_path) is None and pemodel.score(tmp_path, _real_pe()) is None
