import logging
import socket
import subprocess
import sys
import threading
import time

from socket import socket, AF_INET, SOCK_STREAM

# в драйвере:       TLS-PSK-WITH-AES-128-GCM-SHA256
# IANA name: 		TLS_PSK_WITH_AES_128_GCM_SHA256
# OpenSSL name: 	PSK-AES128-GCM-SHA256
# GnuTLS name: 	    TLS_PSK_AES_128_GCM_SHA256
# Hex code: 		0x00, 0xA8
# TLS Version(s):   TLS1.2, TLS1.3
#
# {0x00, 0xA8} TLS_PSK_WITH_AES_128_GCM_SHA256


# server
# openssl s_server -port 4433 -tls1_2 -cipher PSK-AES128-GCM-SHA256 -psk 0000000000000000000000000000000000000000000000000000000000000000 -nocert -trace -msg -debug

# client
# openssl s_client -port 4433 -tls1_2 -cipher PSK-AES128-GCM-SHA256 -psk 0000000000000000000000000000000000000000000000000000000000000000 -trace -msg -debug

# -psk_identity ??
# -quiet

# tcpdump (нужно запускать с sudo и до запуска клиента/сервера):
# sudo pacman -S tcpdump
# sudo tcpdump -i lo -X -s0 port 4433

# CLIENT_HELLO_HEX="160303002f0100002b03032df45158cf8cb14046f6b54b29310347045b7030b45dfd20787f8b1ad859295000000400a800ff0100"
# (printf "%s" "$CLIENT_HELLO_HEX" | xxd -r -p | nc localhost 4433) | hexdump -C


logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')


def log_output(pipe, level):
    for line in iter(pipe.readline, ''):
        if line:
            logging.log(level, line.rstrip())
    pipe.close()


def to_send(client_socket):
    print("enter hex string")
    hex_string = input()
    data = bytes.fromhex(hex_string)
    print("send: ", hex_string)
    client_socket.sendall(data)
    print("data sent!")


def to_recv(client_socket):
    print("enter count of bytes")
    count = int(input())
    print(f"receiving {count} bytes...")
    response = client_socket.recv(int(count))
    print("received", response.hex())


def interaction(client_socket):
    while True:
        print("1 - send data")
        print("2 - recv data")
        print("3 - exit")
        input_str = input()
        match input_str:
            case "1":
                to_send(client_socket)
            case "2":
                to_recv(client_socket)
            case "3":
                break


# client_hello  : 160303002F0100002B03032DF45158CF8CB14046F6B54B29310347045B7030B45DFD20787F8B1AD859295000000400A800FF0100
# client_key    : 160303001510000011000f436c69656e745f6964656e74697479

def main():
    psk = '0000000000000000000000000000000000000000000000000000000000000000'
    cmd = f'openssl s_server -port 4433 -tls1_2 -cipher PSK-AES128-GCM-SHA256 -psk {psk} -nocert -trace -msg -debug'

    # start TLS server
    server_proc = subprocess.Popen(cmd.split(" "), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    # Запуск потоков для чтения вывода сервера
    mon_thread_1 = threading.Thread(target=log_output, args=(server_proc.stdout, logging.INFO))
    mon_thread_2 = threading.Thread(target=log_output, args=(server_proc.stderr, logging.ERROR))
    mon_thread_1.start()
    mon_thread_2.start()

    time.sleep(0.5)

    error = None
    client_socket = None

    try:
        # создаем клиента и подключаем
        client_socket = socket(AF_INET, SOCK_STREAM)
        client_socket.connect(("localhost", 4433))
        interaction(client_socket)

    except BaseException as ex:
        error = ex

    # Закрытие клиента
    client_socket.close()

    # Завершение сервера
    server_proc.terminate()
    server_proc.wait()

    mon_thread_1.join()
    mon_thread_2.join()

    if error:
        raise error

    print("Done.")


if __name__ == "__main__":
    try:
        main()
    except BaseException as err:
        logging.error(err)
        sys.exit(1)
