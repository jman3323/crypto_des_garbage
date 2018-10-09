#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <unistd.h>

typedef unsigned int uint;
typedef unsigned char u8;
#define GET_BIT(i, a) (((a)>>(i))&1)
#define SET_BIT(i, a) ((a) |= 1<<(i))
#define ROL(x) ((((x)<<1) | (((x)>>4)&1))&0x1f)

/*
 * permutes a of nbits bits
 * bitpos[i] holds source bit location of bit i
 */
uint permute(uint a, u8* bitpos, uint nbits) {
    uint res = 0;
    for (int i = 0; i < nbits; i++)
        if (GET_BIT(bitpos[i], a))
            SET_BIT(i, res);
    return res;
}

void gen_subkeys(uint key, uint* subkeys) {
    u8 p10[] = {2,4,1,6,3,9,0,8,7,5};
    key = permute(key, p10, 10); // initial key permutation

    uint lo5 = key&0x1f, hi5 = key>>5; // split into 5bit chunks

    // left shift each chunk
    lo5 = ROL(lo5);
    hi5 = ROL(hi5);

    // permute to get round key 1
    u8 p8[] = {5,2,6,3,7,4,9,8};
    subkeys[0] = permute(lo5|(hi5<<5), p8, 8);

    // left shift each chunk again
    lo5 = ROL(lo5);
    hi5 = ROL(hi5);

    // permute to get round key 2
    subkeys[1] = permute(lo5|(hi5<<5), p8, 8);
}

u8 s0box[4][4] = {
    {1,0,3,2},
    {3,2,1,0},
    {0,2,1,0},
    {3,1,3,2},
};
u8 s1box[4][4] = {
    {0,1,2,3},
    {2,0,1,3},
    {3,0,1,0},
    {2,1,0,3},
};

u8 fbox(u8 a, u8 k) {
    u8 expand_perm[] = {3,0,1,2,1,2,3,0};
    a = permute(a, expand_perm, 8); // expand/permute
    a ^= k; // add round key

    u8 lo4 = a&0xf, hi4 = a>>4; // split into 4bit chunks

    u8 lo_row = ((lo4>>2)&2)|(lo4&1); // compute sbox row
    u8 lo_col = (lo4>>1)&3;           // and column
    u8 lo2 = s1box[lo_row][lo_col]; // sbox substitution into 2bits

    u8 hi_row = ((hi4>>2)&2)|(hi4&1); // compute sbox row
    u8 hi_col = (hi4>>1)&3;           // and column
    u8 hi2 = s0box[hi_row][hi_col]; // sbox substitution into 2bits

    u8 out = lo2|(hi2<<2); // recombine into 4bits

    u8 p4[] = {1,3,2,0};
    out = permute(out, p4, 4); // fbox permutation
    return out;
}

/*
 * encrypts a single 8bit block (character)
 * using 2 subkeys
 */
u8 enc_block(u8 p, uint* subkeys) {
    u8 iperm[] = {1,5,2,0,3,7,4,6};
    p = permute(p, iperm, 8); // initial permutation

    u8 l0 = p>>4, r0 = p&0xf; // split into 4bit chunks

    u8 r1 = l0 ^ fbox(r0, subkeys[0]); // first round

    u8 l1 = r0 ^ fbox(r1, subkeys[1]); // second round

    u8 out = (l1<<4) | r1; // recombine into 8bit

    u8 invperm[] = {3,0,2,4,6,1,7,5};
    out = permute(out, invperm, 8); // inverse initial permutation
    return out;
}

/*
 * encrypt/decrypt plaintext p of len plen using key
 * c is expected to be of at least plen bytes
 * if c is NULL it is enciphered in-place
 */
void encipher(u8* p, uint plen, uint key, u8* c, u8 decrypt) {
    key &= 0x3ff; // ensure key is 10bit
    if (!c) // encipher in-place
        c = p;

    uint subkeys[2];
    gen_subkeys(key, subkeys);
    if (decrypt) { // decrypt is same operation with reversed subkeys
        uint tmp = subkeys[0];
        subkeys[0] = subkeys[1];
        subkeys[1] = tmp;
    }

    /*
     * blocks are 8bit, so just iterate over every character
     */
    for (int i = 0; i < plen; i++)
        c[i] = enc_block(p[i], subkeys);
}

void encrypt(u8* p, uint plen, uint key, u8* c) {
    encipher(p, plen, key, c, 0);
}
void decrypt(u8* c, uint plen, uint key, u8* p) {
    encipher(c, plen, key, p, 1);
}

void usage(char* a) {
    printf("Usage: encrypt: %s e file key host port\n"
           "       decrypt: %s d key port\n", a, a);
    exit(1);
}

int do_decrypt(uint key, uint port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        printf("ERROR: couldn't create socket (%s)\n", strerror(errno));
        return 1;
    }

    int optval = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval , sizeof(optval));

    struct sockaddr_in serv;
    memset(&serv, 0, sizeof(serv));
    serv.sin_family = AF_INET;
    serv.sin_port = htons(port);

    if (bind(sock, (struct sockaddr*)&serv, sizeof(serv)) == -1) {
        printf("ERROR: couldn't bind to port %d (%s)\n", port, strerror(errno));
        return 1;
    }

    listen(sock, 1);

    int cfd = accept(sock, 0, 0);
    if (cfd == -1) {
        printf("ERROR: couldn't accept client (%s)\n", strerror(errno));
        return 1;
    }

    u8* buf = malloc(0x1000);
    while (1) {
        uint nread = read(cfd, buf, 0x1000);
        if (nread <= 0)
            break;
        decrypt(buf, nread, key, 0);
        write(1, buf, nread);
    }
    free(buf);
    return 0;
}

int do_encrypt(char* file, uint key, char* host, uint port) {
    int fd = open(file, O_RDONLY);
    if (fd == -1) {
        printf("ERROR: couldn't open file %s (%s)\n", file, strerror(errno));
        return 1;
    }

    struct stat st = {0};
    if (fstat(fd, &st)) {
        printf("ERROR: couldn't stat file %s (%s)\n", file, strerror(errno));
        return 1;
    }

    uint plen = st.st_size;
    u8* ptxt = mmap(0, plen, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (ptxt == MAP_FAILED) {
        printf("ERROR: couldn't mmap plaintext file %s (%s)\n", file, strerror(errno));
        return 1;
    }
    
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        printf("ERROR: couldn't create socket (%s)\n", strerror(errno));
        return 1;
    }

    struct hostent* he = gethostbyname(host);
    if (!he) {
        printf("ERROR: couldn't get hostname info for %s\n", host);
        return 1;
    }
    struct sockaddr_in serv;
    memcpy(&serv.sin_addr, he->h_addr_list[0], he->h_length);
    serv.sin_family = AF_INET;
    serv.sin_port = htons(port);
    if (connect(sock, (struct sockaddr*)&serv, sizeof(serv))) {
        printf("ERROR: couldn't connect to %s:%d (%s)\n", host, port, strerror(errno));
        return 1;
    }

    encrypt(ptxt, plen, key, 0);
    long n_written = write(sock, ptxt, plen);
    printf("sent %ld encrypted bytes\n", n_written);

    close(sock);
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 2)
        usage(argv[0]);
    uint decrypt = !strcmp(argv[1], "d");
    if (!decrypt && strcmp(argv[1], "e"))
        usage(argv[0]);
    if ((decrypt && argc < 4) || (!decrypt && argc < 6))
        usage(argv[0]);

    if (decrypt)
        return do_decrypt(atoi(argv[2]), atoi(argv[3]));
    else
        return do_encrypt(argv[2], atoi(argv[3]), argv[4], atoi(argv[5]));
}
