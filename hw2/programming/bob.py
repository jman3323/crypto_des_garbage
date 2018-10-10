from client import *

bob = KDC_Client("bob", KDC_HOST, KDC_PORT, os.urandom(256/8))
bob.register()

sender, msg = bob.listen(BOB_PORT)
print "message from %s: %s"%(sender, msg)
