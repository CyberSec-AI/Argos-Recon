import subprocess
import sys


def run_cmd(cmd: str, desc: str):
    print(f"\n--- {desc} ---")
    try:
        subprocess.check_call(cmd, shell=True)
        print("✅ OK")
    except subprocess.CalledProcessError:
        print("❌ FAIL")
        sys.exit(1)


def main():
    # 1. Formatage
    run_cmd("ruff format .", "Formatting Code")

    # 2. Linting
    run_cmd("ruff check . --fix", "Linting Code")

    # 3. Type Checking
    run_cmd("mypy app", "Checking Types")

    # 4. Tests d'invariants
    run_cmd("pytest app/tests/test_barriers.py", "Running Barrier Tests")

    # 5. Sécurité
    run_cmd("bandit -r app -ll -ii", "Security Scan")

    print("\n✨ Qualité validée ! Prêt pour le commit.")


if __name__ == "__main__":
    main()
