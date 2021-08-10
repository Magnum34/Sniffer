from config_socket import ConfigSocket


if __name__ == "__main__":

    try:
        eth = ConfigSocket()
        print(eth.raw_packet)
    except socket.error():
        print(socket.error())