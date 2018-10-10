### Usage
you will need three terminals (or background processes)  
have kdc server running: `python kdc.py`  
have bob listening: `python bob.py`  
have alice send: `python alice.py`  
(python2 by the way)

### Dependencies
pycrypto: `pip install pycrypto`

### Writeup
The KDC server is implemented in `kdc.py`. Communicating with it requires abiding a simple protocol.
Each payload sent to the server is preceded by a 32bit integer (packed as 4 bytes) giving the size
of the payload. The KDC serves two operations: creating a session key for the secure communication of
two parties using the Needham-Schroeder protocol, and registering a key to be associated with a user.

I will start with the registration part of the KDC. To initiate this, an "R" is sent to the server.
Registering a key involves sending a user id, just a string, and the user's secret key.
As the KDC, we have to assume all traffic we send or receive is public 
(as in eavesdroppers could be present). To avoid simply having the user send their secret key
in plaintext, a Diffie Hellman key exchange is done first to establish a shared secret.

This is done as follows, call the server S and the client C:
* S -> C : the public parameters `g` and prime `p`
* C -> S : a "y" to acknowledge the parameters
* S -> C : `g^a % p` using a random `a`
* C -> S : `g^b % p` using a random `b`
* S computes `(g^b)^a % p = g^(ab) % p`
* C computes `(g^a)^b % p = g^(ab) % p`  
Now both parties have the shared value `g^(ab) % p`. The only values an eavesdropper can
get are: `g`,`p`,`g^a % p`, and `g^b % p`. The values of `a` or `b` can not be easily determined
because that would involve solving a discrete log, which is considered computationally hard,
as long as the numbers are big enough. I chose a public modulus `p` of 2048 bits, and likewise
the random values for `a` are 2048 bits long.

Using the shared secret, call it `k`, each party computes the sha256 hash of `k` to produce
a key usable with AES (the hash function serves to turn `k` into a string of fixed length).
Any symmetric cipher can be used at this point, however I chose AES for its security.
The toy DES we implemented previously is extremely insecure. No matter how secure your Diffie Hellman
parameters are, a 10 bit key will take less than a second to break.
I also felt the focus was Diffie-Hellman and Needer-Schroeder, so thought using
a different cipher wasn't super important to the assignment.

Now the client can send the server its key encrypted using the shared secret key just exchanged,
and any eavesdropper will know nothing about the client's key.

I will note that the server does not allow registering a key for an already registered user. This
brings up a problem if an impersonator tries to re-register a key. If a client wishes to make a new key,
they can generate a new user id and register the new key with the new id.

The other function of the server is to create session keys for clients. Requesting a session key
is done by sending an "S" to the server.
Again we have to assume all traffic is public. To maintain security, a modified version
of the Needham-Schroeder protocol is used. The modification involves an extra nonce that
prevents replay attacks.

Let S be the server, A Alice with id A\_id and key Ka, B Bob with id B\_id and key Kb,
and E\_K a symmetric encryption function (AES again).
If Alice wants to send a message to Bob:
* A -> B : `A_id`
* B -> A : `E_Kb(A_id | Nb)` where `Nb` is a random nonce
* A -> S : `A_id | B_id | Na | E_Kb(A_id | Nb)` where `Na` is a random nonce
* S knows `Kb`, and checks that `A_id` matches in both places
* S -> A : `E_Ka(Na | K | B_id | E_Kb(K | A_id | Nb))`
* A checks that `Na` and `B_id` match what it sent previously
* A -> B : `E_Kb(K | A_id | Nb)`
* B checks that `A_id` and `Nb` match what it sent previously  
Now both parties have a shared secret `K`. This value was never sent in plaintext, it was sent
encrypted with `Ka` or `Kb`, which, assuming they remained secret, are unknown to an eavesdropper.

The nonce `Nb` mitigates replay attacks, since if an attacker simply retransmits
`E_Kb(K | A_id | Nb)` from an earlier exchange, the nonce will (with very high probability)
have changed.

Alice can now send Bob a message encrypted with AES using the key `K`.
