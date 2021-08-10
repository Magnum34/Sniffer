import socket
import sys


class ConfigMetaClass(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            instance = super().__call__(*args, **kwargs)
            cls._instances[cls] = instance
        return cls._instances[cls]


class ConfigSocket(metaclass=ConfigMetaClass):

    def __init__(self):
        try:
            self.connect = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            packet, addr = self.connect.recvfrom(65565)
            self.raw_packet = packet
            self.addr = addr 
        except socket.error():
            print(socket.error())
