"""Entry point. Run from the Backend/ folder:  uv run main.py"""
from common.config import settings


def main():
    # FYP-1: from fyp1.agent.supervisor import Supervisor
    # FYP-2: from fyp2.agent.extension import register_fyp2_modules
    print("OmniGuard AOCDS starting on", settings["api_host"], settings["api_port"])


if __name__ == "__main__":
    main()
