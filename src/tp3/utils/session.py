import re

import requests

from src.tp3.utils.captcha import Captcha
from src.tp3.utils.config import logger


class Session:
    """
    Classe représentant une session pour résoudre un captcha et soumettre le flag.

    Attributes:
        url (str): L'URL du challenge captcha.
        captcha_value (str): La valeur du captcha résolu.
        flag_value (str): La valeur du flag à soumettre.
        valid_flag (str): Le flag validé obtenu après traitement de la réponse.
    """

    def __init__(self, url):
        self.url = url
        self.captcha_value = ""
        self.flag_value = ""
        self.valid_flag = ""
        self.session = requests.Session()
        self.response = None
        self.max_retries = 50
        self.form_data = {}

    def prepare_request(self):
        """
        Prépare la requête en :
        1. Récupérant la page du challenge
        2. Extrayant les champs du formulaire (hidden fields, tokens, etc.)
        3. Capturant et résolvant le captcha
        """
        # Récupérer la page
        try:
            page = self.session.get(self.url, timeout=10)
            html = page.text

            # Extraire tous les champs du formulaire
            self.form_data = {}
            inputs = re.findall(
                r'<input[^>]+name=["\']([^"\']+)["\'](?:[^>]+value=["\']([^"\']*)["\'])?',
                html,
            )
            for name, value in inputs:
                if name.lower() not in ("submit", "captcha", "captcha_value"):
                    self.form_data[name] = value

            # Trouver le nom du champ captcha
            captcha_field = "captcha"
            for name, _ in inputs:
                if "captcha" in name.lower():
                    captcha_field = name
                    break

        except Exception as e:
            logger.error(f"Erreur lors de la récupération de la page : {e}")
            captcha_field = "captcha"

        # Capturer et résoudre le captcha
        captcha = Captcha(self.url)
        captcha.capture(session=self.session)
        captcha.solve()

        self.captcha_value = captcha.get_value()
        self.form_data[captcha_field] = self.captcha_value

        logger.info(f"Captcha résolu : '{self.captcha_value}'")

    def submit_request(self):
        """
        Envoie le formulaire avec le captcha résolu.
        """
        try:
            self.response = self.session.post(
                self.url,
                data=self.form_data,
                timeout=10,
                allow_redirects=True,
            )
            logger.debug(f"POST {self.url} -> HTTP {self.response.status_code}")

        except Exception as e:
            logger.error(f"Erreur lors de la soumission : {e}")
            self.response = None

    def process_response(self) -> bool:
        """
        Traite la réponse du serveur.

        Returns:
            True si le flag est validé, False sinon.
        """
        if self.response is None:
            logger.error("Aucune réponse à traiter.")
            return False

        try:
            content = self.response.text

            # Chercher un flag dans la réponse
            flag_patterns = [
                r"(flag\{[^}]+\})",
                r"(FLAG\{[^}]+\})",
                r"[Ff]lag\s*[:=]\s*([^\s<\"']+)",
                r"[Bb]ravo[^<]*",
                r"[Cc]orrect[^<]*",
                r"[Ss]uccess[^<]*",
                r"[Cc]ongratulations?[^<]*",
                r"[Gg]agn[eé][^<]*",
            ]

            for pattern in flag_patterns:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    self.valid_flag = match.group(0).strip()
                    logger.info(f"Résultat trouvé : {self.valid_flag}")
                    return True

            # Vérifier les erreurs explicites
            error_patterns = ["incorrect", "wrong", "invalid", "erreur", "failed", "mauvais", "faux"]
            if any(word in content.lower() for word in error_patterns):
                logger.debug("Captcha incorrect, nouvelle tentative...")
                return False

            # Suivre les redirections
            if self.response.history:
                final_url = self.response.url
                if final_url != self.url:
                    logger.debug(f"Redirection vers {final_url}")
                    for pattern in flag_patterns:
                        match = re.search(pattern, content, re.IGNORECASE)
                        if match:
                            self.valid_flag = match.group(0).strip()
                            return True

            logger.debug("Réponse non concluante, nouvelle tentative...")
            return False

        except Exception as e:
            logger.error(f"Erreur lors du traitement de la réponse : {e}")
            return False

    def get_flag(self):
        """
        Retourne le flag validé.
        """
        return self.valid_flag
