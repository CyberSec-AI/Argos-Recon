import subprocess
import sys


def run_cmd(cmd: str, desc: str):
    """
    Exécute une commande système et affiche le résultat.
    Quitte le script avec un code d'erreur en cas d'échec.
    """
    print(f"\n--- {desc} ---")
    try:
        # shell=True est utilisé pour la compatibilité avec les commandes complexes sous Windows
        subprocess.check_call(cmd, shell=True)
        print("✅ OK")
    except subprocess.CalledProcessError:
        print("❌ FAIL")
        sys.exit(1)


def main():
    # 1. Formatage du code (Ruff Format)
    run_cmd("ruff format .", "Formatting Code")

    # 2. Analyse statique et corrections automatiques (Ruff Lint)
    run_cmd("ruff check . --fix", "Linting Code")

    # 3. Vérification du typage (MyPy)
    run_cmd("mypy app", "Checking Types")

    # 4. Exécution des tests de barrière (Pytest via le module python)
    run_cmd("python -m pytest app/tests/test_barriers.py", "Running Barrier Tests")

    # 5. Scan de sécurité du code source (Bandit)
    # -r app : scan récursif du dossier app
    # -x app/tests : EXCLURE les tests (qui contiennent des asserts normaux)
    # -ll : Niveau de sévérité Low minimum
    # -ii : Niveau de confiance Low minimum
    run_cmd("bandit -r app -x app/tests -ll -ii", "Security Scan")

    print("\n✨ Qualité validée ! Prêt pour le commit.")


if __name__ == "__main__":
    main()
