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
        print(f"scan service self-test passed ({count} YARA rules)")
        return 0
    except Exception:
        print("The scan service cannot start on this PC. The reason:\n")
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
