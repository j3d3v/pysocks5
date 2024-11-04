import os

# Configuraciones
MAX_THREADS = 200
BUFSIZE = 2048
TIMEOUT_SOCKET = 5
LOCAL_ADDR = "0.0.0.0"
# Puerto de escucha
# LOCAL_PORT = 14820


def clear():
    if os.name == "nt":
        os.system("cls")
    else:
        os.system("clear")
