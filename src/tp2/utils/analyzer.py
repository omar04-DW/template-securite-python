import os
import re
import string

import requests as http_requests

from src.tp2.utils.config import logger

try:
    import pylibemu
except ImportError:
    pylibemu = None
    logger.warning("pylibemu non disponible. Installez-le avec : pip install pylibemu")

try:
    from capstone import CS_ARCH_X86, CS_MODE_32, Cs
except ImportError:
    Cs = None
    logger.warning("capstone non disponible. Installez-le avec : pip install capstone")


class ShellcodeAnalyzer:
    """
    Classe permettant d'analyser un shellcode via différentes méthodes :
    - Extraction de chaînes de caractères
    - Analyse pylibemu (émulation)
    - Analyse capstone (désassemblage)
    - Analyse LLM (explication textuelle via API)
    """

    def __init__(self, shellcode_hex: str):
        """
        Initialise l'analyseur avec un shellcode en format hexadécimal.

        Args:
            shellcode_hex: Shellcode en format \\x41\\x42... ou brut hex
        """
        self.shellcode_hex = shellcode_hex.strip()
        self.shellcode_bytes = self._parse_shellcode(self.shellcode_hex)
        self.strings = []
        self.pylibemu_result = ""
        self.capstone_result = []
        self.llm_result = ""

    @staticmethod
    def _parse_shellcode(shellcode_hex: str) -> bytes:
        """
        Convertit une chaîne hex en bytes.
        Supporte les formats : \\x41\\x42, 0x41 0x42, 4142
        """
        cleaned = shellcode_hex.strip()

        # Format \x41\x42\x43
        if "\\x" in cleaned:
            hex_str = cleaned.replace("\\x", "")
            hex_str = re.sub(r"[^0-9a-fA-F]", "", hex_str)
            return bytes.fromhex(hex_str)

        # Format 0x41, 0x42
        if "0x" in cleaned.lower():
            parts = re.findall(r"0x([0-9a-fA-F]{1,2})", cleaned, re.IGNORECASE)
            return bytes.fromhex("".join(parts))

        # Format brut hex : 4142434445
        hex_str = re.sub(r"[^0-9a-fA-F]", "", cleaned)
        if len(hex_str) % 2 == 0 and len(hex_str) > 0:
            return bytes.fromhex(hex_str)

        return b""

    def get_shellcode_strings(self, min_length: int = 4) -> list:
        """
        Retourne les chaînes de caractères ASCII présentes dans le shellcode.

        Args:
            min_length: Longueur minimale des chaînes à extraire.

        Returns:
            Liste de chaînes trouvées dans le shellcode.
        """
        printable = set(string.printable) - set("\t\n\r\x0b\x0c")
        current = []
        self.strings = []

        for byte in self.shellcode_bytes:
            char = chr(byte)
            if char in printable:
                current.append(char)
            else:
                if len(current) >= min_length:
                    self.strings.append("".join(current))
                current = []

        if len(current) >= min_length:
            self.strings.append("".join(current))

        logger.info(f"Chaînes extraites ({len(self.strings)}) : {self.strings}")
        return self.strings

    def get_pylibemu_analysis(self) -> str:
        """
        Retourne l'analyse pylibemu du shellcode (émulation).
        Pylibemu émule le shellcode et retourne les appels API Windows détectés.

        Returns:
            Résultat de l'émulation pylibemu.
        """
        if pylibemu is None:
            self.pylibemu_result = "pylibemu non installé. Installez-le avec : pip install pylibemu"
            logger.warning(self.pylibemu_result)
            return self.pylibemu_result

        try:
            emulator = pylibemu.Emulator()
            offset = emulator.shellcode_getpc_test(self.shellcode_bytes)

            if offset < 0:
                self.pylibemu_result = "Shellcode non reconnu par pylibemu (offset négatif)."
                logger.info(self.pylibemu_result)
                return self.pylibemu_result

            emulator.prepare(self.shellcode_bytes, offset)
            emulator.test(steps=10000000)

            profile = emulator.emu_profile_output
            if profile:
                self.pylibemu_result = profile.decode("utf-8", errors="replace")
            else:
                self.pylibemu_result = "Émulation terminée, aucun profil généré."

            logger.info(f"Analyse pylibemu :\n{self.pylibemu_result}")
            return self.pylibemu_result

        except Exception as e:
            self.pylibemu_result = f"Erreur pylibemu : {e}"
            logger.error(self.pylibemu_result)
            return self.pylibemu_result

    def get_capstone_analysis(self) -> list:
        """
        Retourne l'analyse Capstone (désassemblage x86 32 bits) du shellcode.

        Returns:
            Liste de tuples (adresse, mnémonique, opérandes).
        """
        if Cs is None:
            logger.warning("capstone non installé.")
            return [("N/A", "capstone non installé", "")]

        try:
            md = Cs(CS_ARCH_X86, CS_MODE_32)
            self.capstone_result = []

            for instruction in md.disasm(self.shellcode_bytes, 0x0):
                entry = (f"0x{instruction.address:04x}", instruction.mnemonic, instruction.op_str)
                self.capstone_result.append(entry)

            logger.info(f"Désassemblage capstone : {len(self.capstone_result)} instructions")

            for addr, mnem, ops in self.capstone_result:
                logger.debug(f"  {addr}:\t{mnem}\t{ops}")

            return self.capstone_result

        except Exception as e:
            logger.error(f"Erreur capstone : {e}")
            return [("N/A", f"Erreur : {e}", "")]

    def get_llm_analysis(self) -> str:
        """
        Retourne l'analyse LLM du shellcode.
        Utilise une API LLM (OpenAI ou compatible) pour expliquer le shellcode.
        Nécessite la variable d'environnement LLM_API_KEY.
        Fallback sur analyse heuristique si aucune clé API.

        Returns:
            Explication textuelle du shellcode.
        """
        # Construire le contexte d'analyse
        context = self._build_analysis_context()

        # Tenter l'appel LLM
        api_key = os.environ.get("LLM_API_KEY") or os.environ.get("OPENAI_API_KEY")
        api_url = os.environ.get("LLM_API_URL", "https://api.openai.com/v1/chat/completions")
        model = os.environ.get("LLM_MODEL", "gpt-3.5-turbo")

        if api_key:
            try:
                self.llm_result = self._call_llm_api(api_key, api_url, model, context)
                logger.info(f"Explication LLM : {self.llm_result}")
                return self.llm_result
            except Exception as e:
                logger.warning(f"Appel LLM échoué ({e}), fallback sur analyse heuristique")

        # Fallback : analyse heuristique détaillée
        self.llm_result = self._heuristic_analysis_detailed(context)
        logger.info(f"Explication (heuristique) : {self.llm_result}")
        return self.llm_result

    def _build_analysis_context(self) -> str:
        """
        Construit le contexte textuel pour l'analyse LLM.
        """
        parts = []
        parts.append(f"Shellcode de {len(self.shellcode_bytes)} octets.")

        if self.strings:
            parts.append(f"Chaînes ASCII trouvées : {', '.join(self.strings)}")

        if self.pylibemu_result and "non installé" not in self.pylibemu_result:
            parts.append(f"Résultat émulation pylibemu :\n{self.pylibemu_result[:1000]}")

        if self.capstone_result:
            key_instructions = []
            for addr, mnem, ops in self.capstone_result:
                if mnem in ("int", "syscall", "call", "push", "jmp"):
                    key_instructions.append(f"{addr}: {mnem} {ops}")
            if key_instructions:
                parts.append(f"Instructions clés (capstone) :\n" + "\n".join(key_instructions[:30]))

        return "\n".join(parts)

    def _call_llm_api(self, api_key: str, api_url: str, model: str, context: str) -> str:
        """
        Appelle l'API LLM pour obtenir une explication du shellcode.
        Compatible OpenAI et APIs compatibles (Mistral, etc).
        """
        prompt = (
            "Tu es un expert en analyse de malware et sécurité informatique. "
            "Analyse le shellcode suivant et explique précisément ce qu'il fait, "
            "quelles sont ses intentions malveillantes, et quels systèmes il cible.\n\n"
            f"Données d'analyse :\n{context}\n\n"
            f"Shellcode hex :\n{self.shellcode_hex[:500]}\n\n"
            "Donne une explication détaillée en français."
        )

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }

        payload = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 1000,
            "temperature": 0.3,
        }

        response = http_requests.post(api_url, headers=headers, json=payload, timeout=30)
        response.raise_for_status()

        data = response.json()
        return data["choices"][0]["message"]["content"]

    def _heuristic_analysis_detailed(self, context: str) -> str:
        """
        Analyse heuristique détaillée quand le LLM n'est pas disponible.
        """
        indicators = []
        strings_lower = [s.lower() for s in self.strings]
        all_strings = " ".join(strings_lower)

        # Détection par chaînes
        if any(s in all_strings for s in ["/bin/sh", "/bin/bash", "cmd.exe", "cmd."]):
            indicators.append("Ce shellcode exécute un shell système (cmd.exe ou /bin/sh)")

        if any(s in all_strings for s in ["urlmon", "urlmon.dll"]):
            indicators.append(
                "Ce shellcode charge la bibliothèque urlmon.dll pour télécharger "
                "un fichier depuis Internet (URLDownloadToFile)"
            )

        if any(s in all_strings for s in ["ws2_32", "wsock", "ws2_"]):
            indicators.append(
                "Ce shellcode utilise Winsock (ws2_32.dll) pour établir une connexion "
                "réseau, probablement un reverse shell ou un staged payload"
            )

        if any(s in all_strings for s in ["loadlibrary", "getprocaddress"]):
            indicators.append("Ce shellcode charge dynamiquement des DLL Windows")

        if any(s in all_strings for s in ["net user", "net localgroup", "/add"]):
            indicators.append(
                "Ce shellcode crée un utilisateur système et l'ajoute au groupe "
                "Administrateurs pour maintenir un accès persistant"
            )

        if any(s in all_strings for s in ["whoami"]):
            indicators.append("Ce shellcode exécute 'whoami' pour identifier l'utilisateur courant")

        if ".exe" in all_strings:
            exe_names = [s for s in self.strings if ".exe" in s.lower()]
            indicators.append(f"Fichier exécutable référencé : {', '.join(exe_names)}")

        if ".dll" in all_strings:
            dll_names = [s for s in self.strings if ".dll" in s.lower()]
            indicators.append(f"DLL chargée dynamiquement : {', '.join(dll_names)}")

        # Détection par instructions capstone
        if self.capstone_result:
            mnemonics = [m for _, m, _ in self.capstone_result]
            if "int" in mnemonics:
                indicators.append("Utilise des interruptions système (int 0x80) - shellcode Linux x86")
            if mnemonics.count("push") > 10:
                indicators.append("Nombreux push : construction de chaînes sur la pile (technique classique de shellcode)")

        # Classification globale
        if not indicators:
            indicators.append(
                "Shellcode de type inconnu. L'analyse manuelle du désassemblage "
                "capstone est recommandée pour comprendre son fonctionnement."
            )

        # Résumé
        summary = "Explication LLM : " + " | ".join(indicators)
        summary += f"\n\nContexte technique :\n{context}"
        return summary

    def _heuristic_analysis(self) -> str:
        """
        Analyse heuristique courte pour compatibilité.
        """
        indicators = []
        strings_lower = [s.lower() for s in self.strings]
        all_strings = " ".join(strings_lower)

        if any(s in all_strings for s in ["/bin/sh", "/bin/bash", "cmd.exe", "cmd."]):
            indicators.append("Exécution d'un shell système")
        if any(s in all_strings for s in ["urlmon", "http://", "https://", "ftp://"]):
            indicators.append("Téléchargement de fichier distant")
        if any(s in all_strings for s in ["ws2_32", "wsock", "socket"]):
            indicators.append("Communication réseau (socket)")
        if any(s in all_strings for s in ["net user", "net localgroup", "/add"]):
            indicators.append("Création d'un utilisateur système")
        if any(s in all_strings for s in ["whoami"]):
            indicators.append("Reconnaissance système (whoami)")

        if self.capstone_result:
            mnemonics = [m for _, m, _ in self.capstone_result]
            if "int" in mnemonics:
                indicators.append("Appel système via interruption (int 0x80)")

        if not indicators:
            indicators.append("Shellcode de type inconnu - analyse manuelle recommandée")

        return " ; ".join(indicators)

    def full_analysis(self) -> dict:
        """
        Lance toutes les analyses et retourne un résumé complet.
        """
        logger.info(f"Analyse complète du shellcode ({len(self.shellcode_bytes)} octets)")

        results = {
            "taille": len(self.shellcode_bytes),
            "strings": self.get_shellcode_strings(),
            "pylibemu": self.get_pylibemu_analysis(),
            "capstone": self.get_capstone_analysis(),
            "llm": self.get_llm_analysis(),
        }

        return results
