# Template code Sécurité Python

## Description

Projet contenant les TPs pour le cours de sécurité Python de 4e année de l'ESGI.

- **TP1** : IDS/IPS maison - Capture et analyse de trafic réseau avec Scapy
- **TP2** : Analyse de shellcodes - Pylibemu, Capstone, analyse heuristique
- **TP3** : Captcha Solver - Automatisation de résolution de CAPTCHA
- **TP4** : Crazy Decoder - Décodage multi-format avec Pwntools

## Installation

```bash
git clone git@github.com:<VotreNom>/template-securite-python.git
cd template-securite-python
poetry lock
poetry install --no-root
```

### Prérequis système

```bash
# Pour TP3 (OCR des captchas)
sudo apt install tesseract-ocr
```

## Utilisation

```bash
# TP1 - IDS/IPS (nécessite sudo)
sudo poetry run tp1

# TP2 - Analyse shellcode
poetry run tp2 -f shellcode.txt

# TP3 - Captcha solver
poetry run tp3

# TP4 - Crazy decoder
poetry run tp4
```

## Tests

```bash
poetry run pytest
```
By : OMAR
