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
    BIGNUM *e = BN_new();
    BIGNUM *S = BN_new();
    BIGNUM *S1 = BN_new();
    BIGNUM *res = BN_new();
    BIGNUM *res1 = BN_new();

    // Initialize a, b, n
    BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");
    BN_hex2bn(&e, "010001");
    BN_hex2bn(&S, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");
    BN_hex2bn(&S1, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F");
    
    printBN("n = ", n);
    printBN("e = ", e);
    printBN("S = ", S);
    printBN("S1 = ", S1);

    // Public key
    BN_mod_exp(res, S, e, n, ctx);
    BN_mod_exp(res1, S1, e, n, ctx);

    printBN("Message hexa with 2F = ", res);
    printBN("Message hexa with 3F = ", res1);


    return 0;
}
