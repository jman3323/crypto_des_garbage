from client import *

alice = KDC_Client("alice", KDC_HOST, KDC_PORT, os.urandom(256/8))
alice.register()

msg = "hi bob"
alice.send(msg, "bob", BOB_HOST, BOB_PORT)
print "sent to bob: %s"%msg
