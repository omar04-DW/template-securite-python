from src.tp3.utils.config import logger
from src.tp3.utils.session import Session


def main():
    logger.info("Starting TP3 - Captcha Solver")

    ip = "31.220.95.27:9002"
    challenges = {
        "1": f"http://{ip}/captcha1/",
        "2": f"http://{ip}/captcha2/",
        "3": f"http://{ip}/captcha3/",
        "4": f"http://{ip}/captcha4/",
        "5": f"http://{ip}/captcha5/",
    }

    for i, url in challenges.items():
        logger.info(f"=== Challenge {i} : {url} ===")

        session = Session(url)
        attempts = 0
        max_attempts = session.max_retries

        while attempts < max_attempts:
            attempts += 1
            logger.info(f"Tentative {attempts}/{max_attempts}")

            session.prepare_request()
            session.submit_request()

            if session.process_response():
                logger.info(f"Challenge {i} réussi !")
                logger.info(f"Flag pour {url} : {session.get_flag()}")
                break
        else:
            logger.warning(f"Challenge {i} échoué après {max_attempts} tentatives.")

    logger.info("TP3 terminé.")


if __name__ == "__main__":
    main()
