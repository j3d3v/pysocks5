from proxy.secure_proxy import SecureProxy
from proxy.open_proxy import run_open_proxy
import socket
from proxy.config import clear 
from colorama import Fore, init
init()

print('Create by @j1485d')
def main():

    print('''

█▀▀█ █░░█ █▀▀ █▀▀█ █▀▀ █░█ █▀▀ █▀▀
█░░█ █▄▄█ ▀▀█ █░░█ █░░ █▀▄ ▀▀█ ▀▀▄
█▀▀▀ ▄▄▄█ ▀▀▀ ▀▀▀▀ ▀▀▀ ▀░▀ ▀▀▀ ▄▄▀

─────█─▄▀█──█▀▄─█─────
────▐▌──────────▐▌────
────█▌▀▄──▄▄──▄▀▐█────
───▐██──▀▀──▀▀──██▌───
──▄████▄──▐▌──▄████▄──
''')
    
    print(Fore.MAGENTA +"Telegram Channel: https://t.me/j3d3v")
    print('GitHub: https://github.com/j3d3v')
    print("\nOptions:\n1- Secure Proxy\n2- Open Proxy\n3- Exit")
    answer = int(input("-"))

    if answer == 1:
        secure_proxy()
    elif answer == 2:
        open_proxy()
    elif answer == 3:
        exit()


def exit():
    clear()
    input('\nEnter...')


def open_proxy():
    clear()
    port = int(input("Port: "))
    run_open_proxy(port)


def secure_proxy():
    clear()
    username = input("Username: ")
    password = input("Password: ")
    ip = socket.gethostbyname(socket.gethostname())
    port = int(input("Port: "))
    proxy = SecureProxy(username, password)
    proxy.run(ip, port)



if __name__ == "__main__":
    main()
