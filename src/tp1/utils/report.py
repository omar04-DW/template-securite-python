import os
import tempfile

import pygal
from fpdf import FPDF

from src.tp1.utils.config import logger


class Report:
    def __init__(self, capture, filename, summary):
        self.capture = capture
        self.filename = filename
        self.title = "Rapport IDS/IPS - Analyse de trafic réseau"
        self.summary = summary
        self.array = ""
        self.graph_path = ""
        self.pdf = FPDF()

    def _generate_graph(self) -> str:
        """
        Génère un graphique SVG/PNG des protocoles détectés avec pygal.
        Retourne le chemin du fichier image généré.
        """
        protocols = self.capture.sort_network_protocols()
        if not protocols:
            logger.warning("Aucun protocole à afficher dans le graphique.")
            return ""

        chart = pygal.Bar(
            title="Répartition des protocoles réseau",
            x_title="Protocoles",
            y_title="Nombre de paquets",
            show_legend=False,
            style=pygal.style.CleanStyle,
        )

        for proto, count in protocols.items():
            chart.add(proto, count)

        # Sauvegarder en PNG pour l'intégrer dans le PDF
        tmp_path = os.path.join(tempfile.gettempdir(), "tp1_graph.png")
        try:
            chart.render_to_png(tmp_path)
            logger.info(f"Graphique généré : {tmp_path}")
            return tmp_path
        except Exception:
            # Si cairosvg n'est pas dispo, on sauvegarde en SVG
            svg_path = os.path.join(tempfile.gettempdir(), "tp1_graph.svg")
            chart.render_to_file(svg_path)
            logger.info(f"Graphique SVG généré : {svg_path}")
            return svg_path

    def _generate_array(self) -> list:
        """
        Génère les données du tableau des protocoles.
        Retourne une liste de tuples (protocole, nombre_de_paquets).
        """
        protocols = self.capture.sort_network_protocols()
        rows = [(proto, str(count)) for proto, count in protocols.items()]
        return rows

    def generate(self, param: str) -> None:
        """
        Génère le graphique ou le tableau selon le paramètre.
        """
        if param == "graph":
            self.graph_path = self._generate_graph()
            logger.info("Graphique généré avec succès.")
        elif param == "array":
            self.array = self._generate_array()
            logger.info("Tableau généré avec succès.")

    def save(self, filename: str) -> None:
        """
        Sauvegarde le rapport complet en PDF.
        """
        self.filename = filename
        pdf = self.pdf
        pdf.set_auto_page_break(auto=True, margin=15)

        # Page de titre
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 24)
        pdf.cell(0, 60, "", ln=True)
        pdf.cell(0, 15, self.title, ln=True, align="C")
        pdf.set_font("Helvetica", "", 14)
        pdf.cell(0, 10, f"Interface : {self.capture.interface}", ln=True, align="C")
        pdf.cell(0, 10, f"Paquets capturés : {len(self.capture.packets)}", ln=True, align="C")

        # Page résumé
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 16)
        pdf.cell(0, 12, "Résumé de l'analyse", ln=True)
        pdf.set_font("Helvetica", "", 10)
        for line in self.summary.split("\n"):
            pdf.cell(0, 6, line, ln=True)

        # Page graphique
        if self.graph_path and os.path.exists(self.graph_path):
            pdf.add_page()
            pdf.set_font("Helvetica", "B", 16)
            pdf.cell(0, 12, "Graphique des protocoles", ln=True)
            if self.graph_path.endswith(".png"):
                pdf.image(self.graph_path, x=10, y=40, w=190)
            else:
                pdf.set_font("Helvetica", "", 10)
                pdf.cell(0, 10, f"Graphique SVG disponible : {self.graph_path}", ln=True)

        # Page tableau
        if self.array:
            pdf.add_page()
            pdf.set_font("Helvetica", "B", 16)
            pdf.cell(0, 12, "Tableau des protocoles", ln=True)
            pdf.ln(5)

            # En-têtes du tableau
            pdf.set_font("Helvetica", "B", 11)
            pdf.set_fill_color(200, 200, 200)
            pdf.cell(100, 10, "Protocole", border=1, fill=True)
            pdf.cell(60, 10, "Nombre de paquets", border=1, fill=True)
            pdf.ln()

            # Lignes du tableau
            pdf.set_font("Helvetica", "", 10)
            for proto, count in self.array:
                pdf.cell(100, 8, proto, border=1)
                pdf.cell(60, 8, count, border=1, align="C")
                pdf.ln()

        # Page alertes
        alerts = self.capture.get_alerts()
        if alerts:
            pdf.add_page()
            pdf.set_font("Helvetica", "B", 16)
            pdf.cell(0, 12, f"Alertes de sécurité ({len(alerts)})", ln=True)
            pdf.ln(5)

            # En-têtes
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_fill_color(255, 180, 180)
            pdf.cell(35, 8, "Type", border=1, fill=True)
            pdf.cell(25, 8, "Protocole", border=1, fill=True)
            pdf.cell(30, 8, "IP Attaquant", border=1, fill=True)
            pdf.cell(100, 8, "Détail", border=1, fill=True)
            pdf.ln()

            pdf.set_font("Helvetica", "", 8)
            for alert in alerts:
                pdf.cell(35, 8, alert["type"], border=1)
                pdf.cell(25, 8, alert["protocole"], border=1)
                pdf.cell(30, 8, alert.get("adresse_ip", "N/A"), border=1)
                detail = alert["detail"][:55] + "..." if len(alert["detail"]) > 55 else alert["detail"]
                pdf.cell(100, 8, detail, border=1)
                pdf.ln()
        else:
            pdf.add_page()
            pdf.set_font("Helvetica", "B", 16)
            pdf.cell(0, 12, "Alertes de sécurité", ln=True)
            pdf.set_font("Helvetica", "", 12)
            pdf.set_text_color(0, 150, 0)
            pdf.cell(0, 10, "Aucune menace détectée. Le trafic est légitime.", ln=True)
            pdf.set_text_color(0, 0, 0)

        pdf.output(self.filename)
        logger.info(f"Rapport sauvegardé : {self.filename}")
