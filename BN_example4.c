/* bn_sample.c */
#include <stdio.h>
#include <openssl/bn.h>
#define NBITS 256
void printBN(char *msg, BIGNUM *a)
{
    /* Use BN_bn2hex(a) for hex string
* Use BN_bn2dec(a) for decimal string */
    char *number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}
int main()
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *n = BN_new();
    BIGNUM *M1 = BN_new();
    BIGNUM *M = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *res = BN_new();
    BIGNUM *res1 = BN_new();

    // Initialize a, b, n
    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BN_hex2bn(&M, "49206f776520796f752024323030302e");
    BN_hex2bn(&M1, "49206f776520796f752024333030302e");
    BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");

    printBN("n = ", n);
    printBN("M = ", M);
    printBN("M1 = ", M1);
    printBN("d = ", d);

    // Private key
    BN_mod_exp(res, M, d, n, ctx);
    BN_mod_exp(res1, M1, d, n, ctx);

    printBN("Digital Signature for message (I owe you $2000) = ", res);
    printBN("Digital Signature for message (I owe you $3000) = ", res1);
    return 0;
}
