import base64
import binascii
import codecs
import re

from src.tp4.utils.config import logger


class Decoder:
    """
    Décodeur multi-format capable de décoder rapidement différents encodages.
    Supporte : base64, base32, hex, rot13, binaire, URL encoding, etc.
    """

    def __init__(self):
        self.history = []

    def decode(self, data: str) -> str:
        """
        Tente de décoder automatiquement les données en testant différents encodages.

        Args:
            data: Données encodées à décoder.

        Returns:
            Données décodées.
        """
        data = data.strip()
        if not data:
            return data

        result = data

        # Tenter le décodage automatique (plusieurs passes)
        for _ in range(10):
            decoded = self._try_decode(result)
            if decoded == result:
                break
            self.history.append({"input": result[:50], "output": decoded[:50]})
            result = decoded

        logger.debug(f"Décodé : '{data[:30]}...' -> '{result[:30]}...'")
        return result

    def _try_decode(self, data: str) -> str:
        """
        Essaie de décoder avec chaque méthode disponible.
        """
        decoders = [
            self.decode_base64,
            self.decode_base32,
            self.decode_hex,
            self.decode_binary,
            self.decode_url,
            self.decode_decimal,
        ]

        for decoder in decoders:
            try:
                result = decoder(data)
                if result and result != data and self._is_readable(result):
                    logger.debug(f"Décodé avec {decoder.__name__}: '{data[:20]}' -> '{result[:20]}'")
                    return result
            except Exception:
                continue

        return data

    @staticmethod
    def decode_base64(data: str) -> str:
        """Décode du base64."""
        # Vérifier que c'est bien du base64 valide
        cleaned = data.strip()
        if not re.match(r"^[A-Za-z0-9+/=\n\r]+$", cleaned):
            return data
        if len(cleaned) < 4:
            return data

        # Ajouter le padding si nécessaire
        padding = 4 - (len(cleaned) % 4)
        if padding != 4:
            cleaned += "=" * padding

        try:
            decoded = base64.b64decode(cleaned)
            return decoded.decode("utf-8", errors="strict")
        except Exception:
            return data

    @staticmethod
    def decode_base32(data: str) -> str:
        """Décode du base32."""
        cleaned = data.strip().upper()
        if not re.match(r"^[A-Z2-7=]+$", cleaned):
            return data
        if len(cleaned) < 8:
            return data

        try:
            decoded = base64.b32decode(cleaned)
            return decoded.decode("utf-8", errors="strict")
        except Exception:
            return data

    @staticmethod
    def decode_hex(data: str) -> str:
        """Décode de l'hexadécimal."""
        cleaned = data.strip()

        # Format avec 0x ou espaces entre octets
        if cleaned.startswith("0x"):
            cleaned = cleaned[2:]
        cleaned = cleaned.replace(" ", "").replace("\\x", "").replace("0x", "")

        if not re.match(r"^[0-9a-fA-F]+$", cleaned):
            return data
        if len(cleaned) % 2 != 0:
            return data
        if len(cleaned) < 4:
            return data

        try:
            decoded = binascii.unhexlify(cleaned)
            return decoded.decode("utf-8", errors="strict")
        except Exception:
            return data

    @staticmethod
    def decode_rot13(data: str) -> str:
        """Décode du ROT13."""
        decoded = codecs.decode(data, "rot_13")
        return decoded

    @staticmethod
    def decode_binary(data: str) -> str:
        """Décode du binaire (suites de 0 et 1)."""
        cleaned = data.strip().replace(" ", "")
        if not re.match(r"^[01]+$", cleaned):
            return data
        if len(cleaned) % 8 != 0:
            return data
        if len(cleaned) < 8:
            return data

        try:
            chars = []
            for i in range(0, len(cleaned), 8):
                byte = cleaned[i : i + 8]
                chars.append(chr(int(byte, 2)))
            return "".join(chars)
        except Exception:
            return data

    @staticmethod
    def decode_url(data: str) -> str:
        """Décode de l'URL encoding."""
        if "%" not in data:
            return data
        try:
            from urllib.parse import unquote

            decoded = unquote(data)
            return decoded
        except Exception:
            return data

    @staticmethod
    def decode_decimal(data: str) -> str:
        """Décode des nombres décimaux (codes ASCII)."""
        cleaned = data.strip()
        parts = re.split(r"[\s,;]+", cleaned)

        if len(parts) < 2:
            return data

        try:
            chars = []
            for part in parts:
                num = int(part)
                if 0 <= num <= 127:
                    chars.append(chr(num))
                else:
                    return data
            return "".join(chars)
        except Exception:
            return data

    @staticmethod
    def decode_reverse(data: str) -> str:
        """Inverse la chaîne."""
        return data[::-1]

    @staticmethod
    def _is_readable(text: str) -> bool:
        """
        Vérifie si le texte est principalement composé de caractères imprimables.
        """
        if not text:
            return False
        printable_count = sum(1 for c in text if c.isprintable() or c in "\n\r\t")
        return printable_count / len(text) > 0.8

    def decode_specific(self, data: str, encoding: str) -> str:
        """
        Décode avec un encodage spécifique.

        Args:
            data: Données encodées.
            encoding: Type d'encodage (base64, base32, hex, rot13, binary, url, decimal).
        """
        decoders = {
            "base64": self.decode_base64,
            "base32": self.decode_base32,
            "hex": self.decode_hex,
            "rot13": self.decode_rot13,
            "binary": self.decode_binary,
            "url": self.decode_url,
            "decimal": self.decode_decimal,
            "reverse": self.decode_reverse,
        }

        decoder = decoders.get(encoding.lower())
        if decoder:
            return decoder(data)

        logger.warning(f"Encodage inconnu : {encoding}")
        return data
