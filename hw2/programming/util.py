import struct
from Crypto.Cipher import AES
from Crypto.Util.number import *

KDC_HOST = "localhost"
KDC_PORT = 5000
AES_IV = "\0"*16

# pkcs7 padding functions
def pad(msg):
    b = 16 - len(msg)%16
    return msg + chr(b)*b
def unpad(msg):
    b = ord(msg[-1])
    return msg[:-b]

def encrypt(msg, key):
    return AES.new(key, AES.MODE_CBC, "\0"*16).encrypt(pad(msg))
def decrypt(msg, key):
    return unpad(AES.new(key, AES.MODE_CBC, "\0"*16).decrypt(msg))

# helper functions to send/recv data or encrypted data
# data is sent as [len of msg][msg]
def sendmsg(client, msg):
    client.sendall(struct.pack("<I", len(msg))+msg)
def sendenc(client, msg, key):
    sendmsg(client, encrypt(msg, key))
def recvall(client, msglen):
    msg = ""
    while len(msg) < msglen:
        msg += client.recv(msglen-len(msg))
    return msg
def recvmsg(client):
    msglen = struct.unpack("<I", client.recv(4))[0]
    return recvall(client, msglen)
def recvenc(client, key):
    return decrypt(recvmsg(client), key)
