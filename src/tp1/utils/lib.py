from scapy.all import get_if_list


def hello_world() -> str:
    """
    Hello world function
    """
    return "hello world"


def choose_interface() -> str:
    """
    Affiche les interfaces réseau disponibles et demande à l'utilisateur de choisir.
    Retourne le nom de l'interface sélectionnée.
    """
    interfaces = get_if_list()
    if not interfaces:
        print("Aucune interface réseau trouvée.")
        return ""

    print("Interfaces réseau disponibles :")
    for i, iface in enumerate(interfaces):
        print(f"  {i + 1}. {iface}")

    while True:
        try:
            choix = int(input("\nChoisissez une interface (numéro) : "))
            if 1 <= choix <= len(interfaces):
                return interfaces[choix - 1]
            print(f"Veuillez entrer un nombre entre 1 et {len(interfaces)}.")
        except ValueError:
            print("Entrée invalide, veuillez entrer un nombre.")
        except (EOFError, KeyboardInterrupt):
            print("\nAucune interface sélectionnée.")
            return interfaces[0] if interfaces else ""
