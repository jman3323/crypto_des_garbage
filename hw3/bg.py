import math

p = 499
q = 547
N = p*q
a = -57
b = 52
x0 = 159201

# encrypt an integer m using Blum Goldwasser
# N is public key, x0 is chosen quadratic residue
# returns list of ciphertext as integers (with least significant encrypted bits first)
def encrypt(m, N, x0):
    h = int(math.floor(math.log(math.floor(math.log(N, 2)), 2)))
    mask = 2**h-1
    cc = []
    while m > 0:
        x0 = x0*x0 % N
        cc.append((x0&mask) ^ (m&mask))
        m >>= h
    x0 = x0*x0 % N
    cc.append(x0)
    return cc

# decrypt list of ciphertext integers using Blum Goldwasser
# integers should be least significant first
# last integer should be the final unused quadratic residue during encryption
# returns the plaintext as an integer
def decrypt(c, p, q, a, b):
    N = p*q
    h = int(math.floor(math.log(math.floor(math.log(N, 2)), 2)))
    mask = 2**h-1
    t = len(c)-1
    d1 = pow((p+1)/4, t+1, p-1)
    d2 = pow((q+1)/4, t+1, q-1)
    u = pow(c[-1], d1, p)
    v = pow(c[-1], d2, q)
    x0 = (v*a*p + u*b*q) % N
    m = 0
    for i in xrange(len(c)-1):
        x0 = x0*x0 % N
        mm = c[i] ^ (x0&mask)
        m = m | (mm<<(h*i))
    return m

m = int("10011100000100001100", 2)
print "MESSAGE: %d"%m
enc = encrypt(m, N, x0)
print "CIPHERTEXT: %s"%enc
dec = decrypt(enc, p, q, a, b)
print "DECRYPTION: %d"%dec
if dec == m:
    print "it worked"
else:
    print "it didnt work..."
