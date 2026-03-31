from src.tp4.utils.config import logger
from src.tp4.utils.solver import Solver


def main():
    logger.info("Starting TP4 - Crazy Decoder")

    # Serveur du challenge
    host = "31.220.95.27"
    port = 9004

    solver = Solver(host, port)

    if solver.connect():
        solver.solve()
        flag = solver.get_flag()
        if flag:
            logger.info(f"Flag obtenu : {flag}")
        else:
            logger.warning("Aucun flag obtenu. Vérifiez la connexion et le serveur.")
    else:
        logger.error("Impossible de se connecter au serveur.")

    logger.info("TP4 terminé.")


if __name__ == "__main__":
    main()
