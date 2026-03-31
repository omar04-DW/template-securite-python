import io
import re

import requests

from src.tp3.utils.config import logger

try:
    from PIL import Image, ImageFilter, ImageOps
except ImportError:
    Image = None
    ImageFilter = None
    ImageOps = None
    logger.warning("Pillow non installé. Installez-le avec : pip install Pillow")

try:
    import pytesseract
except ImportError:
    pytesseract = None
    logger.warning("pytesseract non installé. Installez-le avec : pip install pytesseract")


class Captcha:
    def __init__(self, url):
        self.url = url
        self.image = None
        self.image_raw = None
        self.value = ""

    def capture(self, session=None):
        """
        Capture l'image du captcha depuis l'URL.
        Tente plusieurs stratégies :
        1. URL directe vers l'image (/captcha, /captcha.png, etc.)
        2. Extraction depuis le HTML de la page
        """
        requester = session if session else requests

        # Stratégie 1 : Récupérer la page HTML et extraire l'image
        try:
            response = requester.get(self.url, timeout=10)
            if response.status_code == 200:
                content_type = response.headers.get("Content-Type", "")

                # Si la réponse est directement une image
                if "image" in content_type:
                    self._load_image(response.content)
                    return

                # Sinon, chercher l'image dans le HTML
                html = response.text
                self._extract_image_from_html(html, requester)

        except Exception as e:
            logger.error(f"Erreur lors de la capture du captcha : {e}")

        # Stratégie 2 : Tenter des URLs classiques
        if self.image is None:
            classic_paths = ["/captcha", "/captcha.png", "/captcha.jpg", "/image"]
            base_url = self.url.rstrip("/")
            for path in classic_paths:
                try:
                    resp = requester.get(base_url + path, timeout=10)
                    if resp.status_code == 200 and "image" in resp.headers.get("Content-Type", ""):
                        self._load_image(resp.content)
                        return
                except Exception:
                    continue

    def _load_image(self, content):
        """Charge une image depuis des bytes."""
        try:
            self.image_raw = content
            self.image = Image.open(io.BytesIO(content))
            logger.info(f"Image captcha chargée ({self.image.size})")
        except Exception as e:
            logger.error(f"Erreur chargement image : {e}")

    def _extract_image_from_html(self, html, requester):
        """
        Extrait l'image du captcha depuis le contenu HTML.
        Gère les images en base64 et les URLs classiques.
        """
        from urllib.parse import urljoin

        # Chercher les images base64 inline
        base64_pattern = r'src=["\']data:image/[^;]+;base64,([^"\']+)["\']'
        b64_match = re.search(base64_pattern, html)
        if b64_match:
            import base64
            try:
                img_data = base64.b64decode(b64_match.group(1))
                self._load_image(img_data)
                logger.info("Captcha extrait (base64 inline)")
                return
            except Exception as e:
                logger.debug(f"Erreur décodage base64 : {e}")

        # Chercher les <img> tags
        img_pattern = re.findall(r'<img[^>]+src=["\']([^"\']+)["\']', html)
        for img_src in img_pattern:
            if img_src.startswith("data:"):
                continue
            img_url = urljoin(self.url, img_src)
            try:
                resp = requester.get(img_url, timeout=10)
                if resp.status_code == 200 and "image" in resp.headers.get("Content-Type", ""):
                    self._load_image(resp.content)
                    logger.info(f"Captcha extrait depuis {img_url}")
                    return
            except Exception as e:
                logger.debug(f"Erreur image {img_url}: {e}")

        logger.warning("Aucune image captcha trouvée dans le HTML.")

    def _preprocess_image(self):
        """
        Prétraite l'image pour améliorer la reconnaissance OCR.
        """
        if self.image is None:
            return None

        img = self.image.copy()

        # Conversion en niveaux de gris
        img = img.convert("L")

        # Agrandissement x3 pour améliorer l'OCR
        width, height = img.size
        img = img.resize((width * 3, height * 3), Image.LANCZOS)

        # Augmenter le contraste
        img = ImageOps.autocontrast(img, cutoff=5)

        # Suppression du bruit
        img = img.filter(ImageFilter.MedianFilter(size=3))

        # Binarisation (seuil)
        threshold = 128
        img = img.point(lambda x: 255 if x > threshold else 0)

        # Nettoyage final
        img = img.filter(ImageFilter.MedianFilter(size=3))

        return img

    def solve(self):
        """
        Résout le captcha en utilisant pytesseract pour l'OCR.
        Teste plusieurs configurations pour maximiser la précision.
        """
        if pytesseract is None:
            logger.error("pytesseract non disponible.")
            self.value = ""
            return

        if self.image is None:
            logger.error("Aucune image captcha à résoudre.")
            self.value = ""
            return

        try:
            processed = self._preprocess_image()
            if processed is None:
                self.value = ""
                return

            # Tester plusieurs configs PSM (Page Segmentation Mode)
            configs = [
                r"--oem 3 --psm 7 -c tessedit_char_whitelist=0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
                r"--oem 3 --psm 8 -c tessedit_char_whitelist=0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
                r"--oem 3 --psm 13",
                r"--oem 3 --psm 6",
            ]

            best_result = ""
            for config in configs:
                try:
                    result = pytesseract.image_to_string(processed, config=config)
                    cleaned = result.strip().replace(" ", "").replace("\n", "")
                    if len(cleaned) > len(best_result):
                        best_result = cleaned
                except Exception:
                    continue

            self.value = best_result
            logger.info(f"Captcha résolu : '{self.value}'")

        except Exception as e:
            logger.error(f"Erreur lors de la résolution du captcha : {e}")
            self.value = ""

    def get_value(self):
        """
        Retourne la valeur du captcha résolu.
        """
        return self.value
