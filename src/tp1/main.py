from src.tp1.utils.capture import Capture
from src.tp1.utils.config import logger
from src.tp1.utils.report import Report


def main():
    logger.info("Starting TP1 - IDS/IPS Maison")

    capture = Capture()
    capture.capture_traffic(count=100, timeout=30)
    capture.analyse("all")
    summary = capture.get_summary()

    filename = "report.pdf"
    report = Report(capture, filename, summary)
    report.generate("graph")
    report.generate("array")
    report.save(filename)

    logger.info("TP1 terminé.")


if __name__ == "__main__":
    main()
