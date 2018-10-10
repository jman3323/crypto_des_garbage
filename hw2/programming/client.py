import socket, os
from util import *
from hashlib import sha256

BOB_HOST = "localhost"
BOB_PORT = 5001

class KDC_Client():
    def __init__(self, client_id, kdc_host, kdc_port, key):
        self.id = client_id
        self.kdc = (kdc_host, kdc_port)
        self.key = key

    # does diffie hellman
    # returns an AES key
    def setupDH(self, sock):
        g = bytes_to_long(recvmsg(sock))
        p = bytes_to_long(recvmsg(sock))
        sendmsg(sock, "y")

        b = bytes_to_long(os.urandom(2048/8))
        g_b = pow(g, b, p)
        sendmsg(sock, long_to_bytes(g_b))
        g_a = bytes_to_long(recvmsg(sock))
        k = pow(g_a, b, p)

        return sha256(long_to_bytes(k)).digest()

    # attempts to register key with kdc server
    def register(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(self.kdc)

        # indicate we want to register, then setup diffie hellman
        sendmsg(sock, "R")

        key = self.setupDH(sock)

        sendenc(sock, self.id, key)
        sendenc(sock, self.key, key)
        err = recvenc(sock, key)
        sock.close()
        if err != "ok":
            raise Exception("KDC registration failed: %s"%err)

    # send a message to dst_host:dst_port which has id dst_id
    # uses needham-schroeder protocol with added nonces to prevent replay attacks (see wikipedia)
    def send(self, msg, dst_id, dst_host, dst_port):
        # initiate contact with destination
        dst = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        dst.connect((dst_host, dst_port))
        sendmsg(dst, self.id)
        enc_id = recvmsg(dst)
        enc_nonce = recvmsg(dst)

        # connect to kdc and send session info
        kdc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        kdc.connect(self.kdc)
        sendmsg(kdc, "S")
        sendmsg(kdc, self.id)
        sendmsg(kdc, dst_id)
        nonce = os.urandom(64)
        sendmsg(kdc, nonce)
        sendmsg(kdc, enc_id)
        sendmsg(kdc, enc_nonce)

        # receive kdc response with session key
        err = recvmsg(kdc)
        if err != "ok":
            raise Exception("KDC session creation failed: %s"%err)

        nonce_echo = recvenc(kdc, self.key)
        key = recvenc(kdc, self.key)
        dst_id_echo = recvenc(kdc, self.key)
        enc_key = recvenc(kdc, self.key)
        enc_id = recvenc(kdc, self.key)
        enc_nonce = recvenc(kdc, self.key)
        kdc.close()
        if nonce_echo != nonce:
            raise Exception("nonce mismatch from server")
        if dst_id_echo != dst_id:
            raise Exception("id mismatch from server: expected %s got %s"%(dst_id,dst_id_echo))

        # send destination encrypted session key and id/nonce
        sendmsg(dst, enc_key)
        sendmsg(dst, enc_id)
        sendmsg(dst, enc_nonce)

        # send the actual message
        sendenc(dst, msg, key)
        dst.close()

    # listen for a message on a port
    def listen(self, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("localhost", port))
        sock.listen(1)
        client, addr = sock.accept()
        
        # receive senders id, send it back encrypted and with nonce
        client_id = recvmsg(client)
        sendenc(client, client_id, self.key)
        nonce = os.urandom(64)
        sendenc(client, nonce, self.key)

        # recv session key and verify id and nonce
        key = recvenc(client, self.key)
        client_id_echo = recvenc(client, self.key)
        nonce_echo = recvenc(client, self.key)
        if client_id_echo != client_id:
            raise Exception("id mismatch from client: expected %s got %s"%(client_id,client_id_echo))
        if nonce_echo != nonce:
            raise Exception("nonce mismatch from client")

        # receive actual message
        msg = recvenc(client, key)
        client.close()
        sock.close()
        return client_id, msg

