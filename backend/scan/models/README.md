# models/

`script_clf_int8.npz`: the local script classifier used by `../aimodel.py`. It holds int8 weights with one scale per output column (about 0.3 MB). Rebuild it with `uv run python train_ai.py` from `backend/scan`. It was trained on generated sample scripts plus any folders you pass in, so treat it as a second opinion beside the readable rules in `../filescan.py`.
