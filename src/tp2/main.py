import argparse
import glob
import os
import sys

from src.tp2.utils.analyzer import ShellcodeAnalyzer
from src.tp2.utils.config import logger


def analyze_shellcode(filepath: str) -> None:
    """Analyse un fichier shellcode et affiche les résultats."""
    logger.info(f"=== Analyse de {filepath} ===")

    try:
        with open(filepath, "r") as f:
            shellcode_hex = f.read().strip()
    except FileNotFoundError:
        logger.error(f"Fichier non trouvé : {filepath}")
        return
    except Exception as e:
        logger.error(f"Erreur lors de la lecture du fichier : {e}")
        return

    if not shellcode_hex:
        logger.error("Le fichier shellcode est vide.")
        return

    # Analyse
    analyzer = ShellcodeAnalyzer(shellcode_hex)
    logger.info(f"Testing shellcode of size {len(analyzer.shellcode_bytes)}B")

    results = analyzer.full_analysis()
    logger.info("Shellcode analysed !")

    # Chaînes de caractères
    if results["strings"]:
        logger.info("Chaînes de caractères détectées :")
        for s in results["strings"]:
            logger.info(f"  -> {s}")

    # Pylibemu
    if results["pylibemu"]:
        logger.info("Analyse pylibemu :")
        for line in results["pylibemu"].split("\n"):
            if line.strip():
                logger.info(f"  {line}")

    # Capstone (désassemblage)
    logger.info("Instructions désassemblées (capstone) :")
    for addr, mnem, ops in results["capstone"][:30]:
        logger.info(f"  {addr}:\t{mnem}\t{ops}")
    if len(results["capstone"]) > 30:
        logger.info(f"  ... ({len(results['capstone']) - 30} instructions supplémentaires)")

    # LLM
    logger.info("Explication LLM :")
    for line in results["llm"].split("\n"):
        if line.strip():
            logger.info(f"  {line}")

    logger.info("")


def main():
    parser = argparse.ArgumentParser(description="TP2 - Analyse de shellcodes")
    parser.add_argument("-f", "--file", help="Fichier contenant le shellcode en hexadécimal")
    parser.add_argument(
        "-d", "--directory",
        help="Répertoire contenant les fichiers shellcode (analyse tous les .txt)",
        default=None,
    )
    args = parser.parse_args()

    logger.info("Starting TP2 - Analyse de shellcodes")

    if args.file:
        analyze_shellcode(args.file)
    elif args.directory:
        files = sorted(glob.glob(os.path.join(args.directory, "*.txt")))
        if not files:
            logger.error(f"Aucun fichier .txt trouvé dans {args.directory}")
            sys.exit(1)
        for filepath in files:
            analyze_shellcode(filepath)
    else:
        # Par défaut, analyser le dossier shellcodes/ s'il existe
        shellcodes_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "shellcodes")
        if os.path.isdir(shellcodes_dir):
            files = sorted(glob.glob(os.path.join(shellcodes_dir, "*.txt")))
            for filepath in files:
                analyze_shellcode(filepath)
        else:
            parser.print_help()
            sys.exit(1)

    logger.info("TP2 terminé.")


if __name__ == "__main__":
    main()
