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
    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *p1 = BN_new();
    BIGNUM *q1 = BN_new();
    BIGNUM *pn = BN_new();
    BIGNUM *d= BN_new();
    // Initialize a, b, n
    BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
    BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
    BN_hex2bn(&e,"0D88C3");
    printBN("p = ", p);
    printBN("q = ", q);
    printBN("e = ", e);

    BN_sub(p1,p,BN_value_one()); // p1 =p - BN_value_one (1)
    BN_sub(q1,q,BN_value_one());

    BN_mul(pn,p1,q1,ctx);   // pn = p1*q1
    BN_mod_inverse(d,e,pn,ctx);  // d*e mod pn =1

    printBN("pn = ", pn);
    printBN("d = ", d);

    BN_CTX_free(ctx);
    return 0;
}
