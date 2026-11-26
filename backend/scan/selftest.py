"""Start-up self-test for the scan service. Used by `npm run dev` (scripts/dev.cjs) and by build.py.

It imports the real service the same way the server does. If anything is missing or broken on this PC
(a package that did not install, a rule file that does not compile) the problem is printed here, in plain
words, instead of the service silently failing to start later.
Exit code 0 = everything is fine.
"""
import sys
import traceback


def main() -> int:
    try:
        import server  # noqa: F401  (loads accounts, YARA, model, Git sync, PDF reader ... exactly like the real service)
        import yara_engine

        ok, errors, count = yara_engine.check_folder(yara_engine.BUNDLED_DIR)
        if not ok:
            print("A YARA rule file is broken: " + "; ".join(errors))
            return 1
        import ai_common
        import netshield
        import sentinel

        if ai_common.available():
            # every shipped model must load and answer once; a missing / broken file fails the BUILD, not the installed app
            import numpy as np

            problems = []
            for f in ai_common.KNOWN_ONNX:
                try:
                    ai_common.check_onnx_generic(ai_common.BUNDLED_DIR / f)
                except Exception as e:
                    problems.append(f"{f}: {e}")
            if problems:
                print("A deep-learning model is missing or broken: " + "; ".join(problems))
                return 1
            netshield.analyze([], [])
            assert sentinel.predict({"key": "HKCU\\Run\\x", "data": "notepad.exe"}) is not None
            print("deep-learning models loaded: sentinel (RF + XGBoost), netshield (GNN)")
        else:
            print("onnxruntime is not installed: the deep-learning modules are off, the rules still work")
        print(f"scan service self-test passed ({count} YARA rules)")
        return 0
    except Exception:
        print("The scan service cannot start on this PC. The reason:\n")
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
