from collections import Counter

from scapy.all import ARP, DNS, IP, TCP, UDP, sniff

from src.tp1.utils.lib import choose_interface
from src.tp1.utils.config import logger


class Capture:
    def __init__(self) -> None:
        self.interface = choose_interface()
        self.packets = []
        self.protocols = Counter()
        self.alerts = []
        self.summary = ""

    def capture_traffic(self, count=100, timeout=30) -> None:
        """
        Capture le trafic réseau depuis l'interface sélectionnée.
        """
        logger.info(f"Capture du trafic sur l'interface {self.interface} ({count} paquets max, {timeout}s)")
        try:
            captured = sniff(iface=self.interface, count=count, timeout=timeout, store=True)
            self.packets = list(captured)
            logger.info(f"{len(self.packets)} paquets capturés")
        except PermissionError:
            logger.error("Permission refusée. Lancez le programme avec sudo.")
        except Exception as e:
            logger.error(f"Erreur lors de la capture : {e}")

    def sort_network_protocols(self) -> dict:
        """
        Trie et retourne tous les protocoles capturés, classés par nombre de paquets décroissant.
        """
        sorted_protocols = dict(self.protocols.most_common())
        return sorted_protocols

    def get_all_protocols(self) -> dict:
        """
        Parcourt les paquets capturés et compte chaque protocole.
        Retourne un dictionnaire {protocole: nombre_de_paquets}.
        """
        self.protocols.clear()
        for pkt in self.packets:
            layer = pkt
            while layer:
                proto_name = layer.__class__.__name__
                if proto_name not in ("Raw", "Padding", "NoPayload"):
                    self.protocols[proto_name] += 1
                layer = layer.payload if layer.payload and layer.payload.__class__.__name__ != "NoPayload" else None

        return dict(self.protocols)

    def _detect_arp_spoofing(self, pkt) -> None:
        """
        Détecte les tentatives d'ARP spoofing :
        - ARP reply non sollicité
        - Adresse source/destination incohérente
        """
        if pkt.haslayer(ARP) and pkt[ARP].op == 2:
            src_ip = pkt[ARP].psrc
            src_mac = pkt[ARP].hwsrc
            self.alerts.append({
                "type": "ARP Spoofing",
                "protocole": "ARP",
                "adresse_mac": src_mac,
                "adresse_ip": src_ip,
                "detail": f"ARP Reply suspect de {src_mac} prétendant être {src_ip}",
            })
            logger.warning(f"[ALERTE] ARP Spoofing détecté : {src_mac} -> {src_ip}")

    def _detect_sql_injection(self, pkt) -> None:
        """
        Détecte les tentatives d'injection SQL dans le payload HTTP.
        """
        sql_patterns = [
            "' OR '1'='1",
            "' OR 1=1",
            "UNION SELECT",
            "DROP TABLE",
            "'; --",
            "' OR ''='",
            "1=1",
            "SELECT * FROM",
            "INSERT INTO",
            "DELETE FROM",
            "UPDATE SET",
        ]
        if pkt.haslayer(TCP) and pkt.haslayer("Raw"):
            try:
                payload = pkt["Raw"].load.decode("utf-8", errors="ignore").upper()
                for pattern in sql_patterns:
                    if pattern.upper() in payload:
                        src_ip = pkt[IP].src if pkt.haslayer(IP) else "inconnu"
                        self.alerts.append({
                            "type": "Injection SQL",
                            "protocole": "TCP/HTTP",
                            "adresse_ip": src_ip,
                            "adresse_mac": pkt.src if hasattr(pkt, "src") else "inconnu",
                            "detail": f"Pattern SQL suspect '{pattern}' détecté depuis {src_ip}",
                        })
                        logger.warning(f"[ALERTE] Injection SQL détectée depuis {src_ip}")
                        break
            except Exception:
                pass

    def _detect_port_scan(self, pkt) -> None:
        """
        Détecte les scans de ports (SYN scan).
        """
        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            flags = pkt[TCP].flags
            if flags == "S":
                src_ip = pkt[IP].src
                dst_port = pkt[TCP].dport
                # On ne déclenche pas d'alerte pour chaque SYN, on le note pour analyse
                # L'analyse groupée se fait dans analyse()
                return (src_ip, dst_port)
        return None

    def _detect_dns_spoofing(self, pkt) -> None:
        """
        Détecte les réponses DNS suspectes (multiples réponses pour une même requête).
        """
        if pkt.haslayer(DNS) and pkt.haslayer(IP):
            dns_layer = pkt[DNS]
            if dns_layer.qr == 1 and dns_layer.ancount and dns_layer.ancount > 5:
                src_ip = pkt[IP].src
                self.alerts.append({
                    "type": "DNS Spoofing suspect",
                    "protocole": "DNS",
                    "adresse_ip": src_ip,
                    "adresse_mac": pkt.src if hasattr(pkt, "src") else "inconnu",
                    "detail": f"Réponse DNS anormale ({dns_layer.ancount} réponses) depuis {src_ip}",
                })
                logger.warning(f"[ALERTE] DNS suspect détecté depuis {src_ip}")

    def analyse(self, protocols: str = "all") -> None:
        """
        Analyse les paquets capturés pour détecter les attaques :
        - ARP Spoofing
        - Injection SQL
        - Port Scan
        - DNS Spoofing
        """
        self.alerts.clear()
        all_protocols = self.get_all_protocols()
        sort = self.sort_network_protocols()
        logger.info(f"Protocoles détectés : {all_protocols}")
        logger.info(f"Protocoles triés : {sort}")

        # Détection d'attaques pour chaque paquet
        syn_tracker = Counter()
        for pkt in self.packets:
            self._detect_arp_spoofing(pkt)
            self._detect_sql_injection(pkt)
            self._detect_dns_spoofing(pkt)

            scan_result = self._detect_port_scan(pkt)
            if scan_result:
                src_ip, _ = scan_result
                syn_tracker[src_ip] += 1

        # Détection de scan de ports : si une IP envoie plus de 10 SYN vers des ports différents
        for ip, count in syn_tracker.items():
            if count > 10:
                self.alerts.append({
                    "type": "Port Scan",
                    "protocole": "TCP",
                    "adresse_ip": ip,
                    "adresse_mac": "N/A",
                    "detail": f"Scan de ports détecté depuis {ip} ({count} SYN envoyés)",
                })
                logger.warning(f"[ALERTE] Port Scan détecté depuis {ip} ({count} SYN)")

        if not self.alerts:
            logger.info("Aucune menace détectée. Tout va bien !")

        self.summary = self.gen_summary()

    def get_summary(self) -> str:
        return self.summary

    def get_alerts(self) -> list:
        return self.alerts

    def gen_summary(self) -> str:
        """
        Génère un résumé textuel de l'analyse.
        """
        lines = []
        lines.append(f"Nombre total de paquets capturés : {len(self.packets)}")
        lines.append(f"Interface : {self.interface}")
        lines.append("")
        lines.append("Protocoles détectés :")
        for proto, count in self.sort_network_protocols().items():
            lines.append(f"  - {proto} : {count} paquets")

        lines.append("")
        if self.alerts:
            lines.append(f"ALERTES ({len(self.alerts)}) :")
            for alert in self.alerts:
                lines.append(f"  [{alert['type']}] {alert['detail']}")
                lines.append(f"    Protocole : {alert['protocole']}")
                if "adresse_ip" in alert:
                    lines.append(f"    IP attaquant : {alert['adresse_ip']}")
                if "adresse_mac" in alert:
                    lines.append(f"    MAC attaquant : {alert['adresse_mac']}")
        else:
            lines.append("Aucune menace détectée. Trafic légitime.")

        return "\n".join(lines)
