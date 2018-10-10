import socket, os, threading
from hashlib import sha256
from util import *

# diffie hellman parameters
# generated with `openssl dhparam 2048`
KDC_G = 2
KDC_P = 26604441737398340621212024314847776371683741308898517941375216243148059190118031845280455068906083188980908390923473312794617403255525250166232944896446745042769773935370868484016608267399891439233568411508252775257250239075449815077462108090733888471894583127099949516704602084605626136077030396318127196944351169890439846892857326397156604252340843016779865613561935387213520987502622710964134768002698026782873728816299067738852189760792919234782261645602506770852557987613255368762669663954696273742127899028549289753986035821460383220269689053354698706928922069689930198145645270676976208252487587518141409040443

class KDC():
    def __init__(self, port, g, p):
        self.keys = {}
        self.keylock = threading.RLock()
        self.g = g
        self.p = p
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("localhost", port))
    def serve(self):
        self.sock.listen(32)
        while True:
            client, addr = self.sock.accept()
            threading.Thread(target=self.handleClient, args=(client,)).start()

    def handleClient(self, client):
        # simple initial protocol, R for register, S to ask for session key
        op = recvmsg(client)
        if op == 'R':
            self.register(client)
        elif op == 'S':
            self.createSession(client)
        client.close()

    # does diffie hellman
    # returns None if client doesnt agree to parameters
    # otherwise returns an AES key
    def setupDH(self, client):
        sendmsg(client, long_to_bytes(self.g))
        sendmsg(client, long_to_bytes(self.p))
        resp = recvmsg(client)
        if resp != "y":
            return None

        a = bytes_to_long(os.urandom(2048/8))
        g_a = pow(self.g, a, self.p)
        sendmsg(client, long_to_bytes(g_a))
        g_b = bytes_to_long(recvmsg(client))
        k = pow(g_b, a, self.p)

        return sha256(long_to_bytes(k)).digest()

    def register(self, client):
        key = self.setupDH(client)
        if key is None:
            return

        # receive their id and aes key
        client_id = recvenc(client, key)
        client_key = recvenc(client, key)

        # check that the key is valid
        # also disallow re-registrations
        # otherwise store key in databse
        err = "ok"
        try:
            AES.new(client_key, AES.MODE_CBC, "\0"*16)
        except:
            err = "invalid key"
        else:
            self.keylock.acquire()
            if client_id in self.keys:
                err = "already registered"
            else:
                self.keys[client_id] = client_key
            self.keylock.release()
        sendenc(client, err, key)

    # create session key
    # use needham-schroeder resistant to replay attacks using added nonces (see wikipedia)
    def createSession(self, client):
        # receive session info
        src_id = recvmsg(client)
        dst_id = recvmsg(client)
        nonce = recvmsg(client)
        dst_enc_src_id = recvmsg(client)
        dst_enc_nonce = recvmsg(client)

        # reject if either id is not registered
        err = None
        src_key = None
        dst_key = None
        self.keylock.acquire()
        if src_id not in self.keys:
            err = "source id not registered"
        else:
            src_key = self.keys[src_id]
            if dst_id not in self.keys:
                err = "destination id not registered"
            else:
                dst_key = self.keys[dst_id]
        self.keylock.release()
        if err is not None:
            sendmsg(client, err)
            return
        
        # check that the source and destination agree on the source id
        if decrypt(dst_enc_src_id, dst_key) != src_id:
            sendmsg(client, "source id mismatch")
            return
        sendmsg(client, "ok")

        # generate and send session key
        session_key = os.urandom(256/8)
        sendenc(client, nonce, src_key)
        sendenc(client, session_key, src_key)
        sendenc(client, dst_id, src_key)
        sendenc(client, encrypt(session_key, dst_key), src_key)
        sendenc(client, dst_enc_src_id, src_key)
        sendenc(client, dst_enc_nonce, src_key)

KDC(KDC_PORT, KDC_G, KDC_P).serve()
