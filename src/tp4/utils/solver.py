import re

from src.tp4.utils.config import logger
from src.tp4.utils.decoder import Decoder

try:
    from pwn import context, remote
except ImportError:
    remote = None
    context = None
    logger.warning("pwntools non installé. Installez-le avec : pip install pwntools")


class Solver:
    """
    Se connecte au serveur de challenge et résout les épreuves de décodage
    en temps réel avec pwntools.
    """

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.decoder = Decoder()
        self.connection = None
        self.flag = ""

    def connect(self):
        """
        Établit la connexion TCP avec le serveur.
        """
        if remote is None:
            logger.error("pwntools non disponible.")
            return False

        try:
            context.log_level = "warn"
            self.connection = remote(self.host, self.port)
            logger.info(f"Connecté à {self.host}:{self.port}")
            return True
        except Exception as e:
            logger.error(f"Erreur de connexion à {self.host}:{self.port} : {e}")
            return False

    def solve(self):
        """
        Boucle principale de résolution :
        1. Reçoit le challenge du serveur
        2. Décode le message
        3. Envoie la réponse
        4. Répète jusqu'à obtenir le flag
        """
        if self.connection is None:
            logger.error("Non connecté au serveur.")
            return

        try:
            round_num = 0
            while True:
                round_num += 1

                # Recevoir le challenge
                try:
                    data = self.connection.recvuntil(b"\n", timeout=10)
                    if not data:
                        data = self.connection.recv(4096, timeout=5)
                except Exception:
                    # Essayer de tout recevoir
                    try:
                        data = self.connection.recv(4096, timeout=5)
                    except Exception:
                        break

                if not data:
                    logger.info("Connexion terminée par le serveur.")
                    break

                message = data.decode("utf-8", errors="replace").strip()
                logger.info(f"[Round {round_num}] Reçu : '{message[:80]}...'")

                # Vérifier si c'est le flag
                flag_match = re.search(r"(flag\{[^}]+\}|FLAG\{[^}]+\})", message, re.IGNORECASE)
                if flag_match:
                    self.flag = flag_match.group(0)
                    logger.info(f"FLAG OBTENU : {self.flag}")
                    break

                # Vérifier si le message contient "bravo", "congrat", etc.
                if any(word in message.lower() for word in ["bravo", "congratulations", "you win", "gg"]):
                    logger.info(f"Challenge réussi ! Message : {message}")
                    # Essayer de recevoir le flag
                    try:
                        remaining = self.connection.recv(4096, timeout=3)
                        remaining_text = remaining.decode("utf-8", errors="replace")
                        flag_match = re.search(r"(flag\{[^}]+\})", remaining_text, re.IGNORECASE)
                        if flag_match:
                            self.flag = flag_match.group(0)
                    except Exception:
                        pass
                    break

                # Extraire la donnée à décoder
                encoded_data = self._extract_challenge(message)
                if not encoded_data:
                    logger.debug(f"Pas de données à décoder dans : {message[:50]}")
                    continue

                # Décoder
                decoded = self.decoder.decode(encoded_data)
                logger.info(f"[Round {round_num}] Décodé : '{decoded[:80]}'")

                # Envoyer la réponse
                self.connection.sendline(decoded.encode())
                logger.info(f"[Round {round_num}] Envoyé : '{decoded[:80]}'")

        except EOFError:
            logger.info("Connexion fermée par le serveur.")
        except Exception as e:
            logger.error(f"Erreur pendant la résolution : {e}")
        finally:
            self.close()

    def _extract_challenge(self, message: str) -> str:
        """
        Extrait les données à décoder depuis le message du serveur.
        Gère plusieurs formats possibles :
        - "Decode: <data>"
        - "Challenge: <data>"
        - Données brutes après un prompt
        """
        # Patterns courants
        patterns = [
            r"[Dd]ecode\s*[:=]\s*(.+)",
            r"[Cc]hallenge\s*[:=]\s*(.+)",
            r"[Dd]ata\s*[:=]\s*(.+)",
            r"[Ee]ncode[d]?\s*[:=]\s*(.+)",
            r">\s*(.+)",
            r":\s*(.+)",
        ]

        for pattern in patterns:
            match = re.search(pattern, message)
            if match:
                extracted = match.group(1).strip()
                if len(extracted) > 2:
                    return extracted

        # Si aucun pattern, retourner la dernière ligne non vide
        lines = [line.strip() for line in message.split("\n") if line.strip()]
        if lines:
            return lines[-1]

        return message

    def get_flag(self) -> str:
        return self.flag

    def close(self):
        """Ferme la connexion."""
        if self.connection:
            try:
                self.connection.close()
            except Exception:
                pass
            logger.info("Connexion fermée.")
