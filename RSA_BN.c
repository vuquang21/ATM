#include <stdio.h>
#include <openssl/bn.h>
#include <string.h>
#include <stdlib.h>
#define NBITS 128
void printBN(char *msg, BIGNUM *a)
{
    char *number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}
int main()
{
    int choice;
    FILE *fptr, *fptr1, *plain_cipher, *N, *plain_cipher1, *E, *D;

    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *p1 = BN_new(); // p1 = p-1
    BIGNUM *q1 = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *pn = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *C = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *res = BN_new();
    BIGNUM *res1 = BN_new();

    // Random

    BN_generate_prime_ex(p, 128, 1, NULL, NULL, NULL);
    BN_generate_prime_ex(q, 128, 1, NULL, NULL, NULL);
    BN_mul(n, p, q, ctx);
    BN_generate_prime_ex(e, 64, 1, NULL, NULL, NULL);
    BN_sub(p1, p, BN_value_one());
    BN_sub(q1, q, BN_value_one());
    BN_mul(pn, p1, q1, ctx);
    BN_mod_inverse(d, e, pn, ctx);
    //-------------------------------

    E = fopen("read_Publickey.txt", "w");
    char *str1 = BN_bn2hex(e);
    fprintf(E, "%s", str1);
    fclose(E);

    D = fopen("read_Privatekey.txt", "w");
    char *str2 = BN_bn2hex(d);
    fprintf(D, "%s", str2);
    fclose(D);

    N = fopen("read_N.txt", "w");
    char *str3 = BN_bn2hex(n);
    fprintf(N, "%s", str3);
    fclose(N);

    int flag = 1;
    while (flag)
    {
        printf("1. Encode\n");
        printf("2. Decode\n");
        printf("0. Exit\n");
        printf("Choice 0 or 1 or 2 : ");
        scanf("%d", &choice);

        switch (choice)
        {
        case 1: // Encode
        {
            int choice;
            printf("\n1. Enter plaintext \n");
            printf("2. Read from file \n");
            printf("Choice 1 or 2 : ");
            scanf("%d", &choice);

            switch (choice)
            {
            case 1: // Enter plaintext
            {
                char text[1000];
                char hex[1000];
                char temp;
                printf("Input plaintext: ");
                scanf("%c", &temp); // Xu ly xuong dong
                scanf("%[^\n]", text);
                int len = strlen(text);
                for (int i = 0, j = 0; i < len; ++i, j += 2)
                    sprintf(hex + j, "%02x", text[i] & 0xff);
                printf("%s", hex);
                int sel;
                printf("\n1. Random key. \n");
                printf("2. Read from file. \n");
                printf("Choice 1 or 2 : ");
                scanf("%d", &sel);

                switch (sel)
                {
                case 1: // Random key
                {
                    fptr = fopen("Publickey_random.txt", "w");

                    char *number_str = BN_bn2hex(e); // Chuyen BIGNUM thanh kieu du lieu character.
                    fprintf(fptr, "%s", number_str);
                    fclose(fptr);

                    BIGNUM *a = BN_new();
                    BN_hex2bn(&a, hex);
                    BN_mod_exp(res, a, e, n, ctx);

                    plain_cipher1 = fopen("Ciphertext_RSA.txt", "w");
                    char *num_res = BN_bn2hex(res);
                    fprintf(plain_cipher1, "%s", num_res);
                    fclose(plain_cipher1);

                    printBN("Ciphetext (use Publice key) = ", res);

                    break;
                }

                case 2: // Read from file
                {
                    char key[64];
                    fptr = fopen("read_Publickey.txt", "r");
                    fgets(key, 64, fptr);

                    BN_hex2bn(&e, key);
                    BIGNUM *a = BN_new();
                    BN_hex2bn(&a, hex);
                    BN_mod_exp(res, a, e, n, ctx);

                    plain_cipher1 = fopen("Ciphertext_RSA.txt", "w");
                    char *num_res = BN_bn2hex(res);
                    fprintf(plain_cipher1, "%s", num_res);
                    fclose(plain_cipher1);

                    printBN("Ciphetext (use Publice key) = ", res);

                    break;
                }
                }
                break;
            }

            case 2: // Read from file
            {
                char hex[1000];
                char plaintext[1000];
                plain_cipher = fopen("Plaintext_RSA.txt", "r");
                fgets(plaintext, 1000, plain_cipher);

                int len = strlen(plaintext);
                for (int i = 0, j = 0; i < len; ++i, j += 2)
                    sprintf(hex + j, "%02x", plaintext[i] & 0xff);
                printf("%s", hex);

                int sel;
                printf("\n1. Random key. \n");
                printf("2. Read from file. \n");
                printf("Choice 1 or 2 : ");
                scanf("%d", &sel);

                switch (sel)
                {
                case 1: // Random key
                {
                    fptr = fopen("Publickey_random.txt", "w");

                    char *number_str = BN_bn2hex(e);
                    fprintf(fptr, "%s", number_str);
                    fclose(fptr);

                    BIGNUM *a = BN_new();
                    BN_hex2bn(&a, hex);
                    BN_mod_exp(res, a, e, n, ctx);

                    plain_cipher1 = fopen("Ciphertext_RSA.txt", "w");
                    char *num_res = BN_bn2hex(res);
                    fprintf(plain_cipher1, "%s", num_res);
                    fclose(plain_cipher1);

                    printBN("Ciphetext (use Publice key) = ", res);

                    break;
                }

                case 2: // Read from file
                {
                    char key[64];
                    fptr = fopen("read_Publickey.txt", "r");
                    fgets(key, 64, fptr);

                    BN_hex2bn(&e, key);
                    BIGNUM *a = BN_new();
                    BN_hex2bn(&a, hex);
                    BN_mod_exp(res, a, e, n, ctx);

                    plain_cipher1 = fopen("Ciphertext_RSA.txt", "w");
                    char *num_res = BN_bn2hex(res);
                    fprintf(plain_cipher1, "%s", num_res);
                    fclose(plain_cipher1);

                    printBN("Ciphetext (use Publice key) = ", res);

                    break;
                }
                }

                break;
            }
            }

            break;
        }

        case 2: // Decode
        {
            int choice;
            printf("\n1. Enter ciphertext \n");
            printf("2. Read from file \n");
            printf("Choice 1 or 2 : ");
            scanf("%d", &choice);
            switch (choice)
            {
            case 1:
            {
                char text[1000];
                char temp;
                printf("Input ciphertext(hexa): ");
                scanf("%c", &temp);
                scanf("%[^\n]", text);

                int sel;
                printf("\n1. Random key. \n");
                printf("2. Read from file. \n");
                printf("Choice 1 or 2 : ");
                scanf("%d", &sel);

                switch (sel)
                {
                case 1: //  Random key
                {
                    fptr1 = fopen("Privatekey_random.txt", "w");

                    char *number_str1 = BN_bn2hex(d);
                    fprintf(fptr1, "%s", number_str1);
                    fclose(fptr1);
                    BIGNUM *a = BN_new();
                    BN_hex2bn(&a, text);
                    BN_mod_exp(res1, a, d, n, ctx);

                    printBN("Plaintext (use Private key) = ", res1);

                    break;
                }

                case 2: // Read from file
                {
                    BIGNUM *t = BN_new();
                    BIGNUM *d1 = BN_new();

                    char key[128];
                    char n1[128];

                    N = fopen("read_N.txt", "r");
                    fgets(n1, 128, N);
                    fptr1 = fopen("read_Privatekey.txt", "r");
                    fgets(key, 128, fptr1);

                    BN_hex2bn(&t, n1);
                    BN_hex2bn(&d1, key);

                    BIGNUM *a = BN_new();
                    BN_hex2bn(&a, text);
                    BN_mod_exp(res1, a, d1, t, ctx);

                    printBN("n = ", t);
                    printBN("d = ", d1);

                    printBN("Plaintext (use Private key) = ", res1);

                    break;
                }
                }

                break;
            }
            case 2:
            {
                plain_cipher1 = fopen("Ciphertext_RSA.txt", "r");
                char text[1000];
                fgets(text, 1000, plain_cipher1);

                int sel;
                printf("\n1. Random key. \n");
                printf("2. Read from file. \n");
                printf("Choice 1 or 2 : ");
                scanf("%d", &sel);

                switch (sel)
                {
                case 1: //  Random key
                {
                    fptr1 = fopen("Privatekey_random.txt", "w");

                    char *number_str1 = BN_bn2hex(d);
                    fprintf(fptr1, "%s", number_str1);
                    fclose(fptr1);
                    BIGNUM *a = BN_new();
                    BN_hex2bn(&a, text);
                    BN_mod_exp(res1, a, d, n, ctx);

                    printBN("Plaintext (use Publice key) = ", res1);

                    break;
                }

                case 2: // Read from file
                {
                    BIGNUM *t = BN_new();
                    BIGNUM *d1 = BN_new();
                    char key[128];
                    char n1[128];
                    N = fopen("read_N.txt", "r");
                    fgets(n1, 128, N);
                    fptr1 = fopen("read_Privatekey.txt", "r");
                    fgets(key, 128, fptr1);
                    BN_hex2bn(&t, n1);
                    BN_hex2bn(&d1, key);
                    BIGNUM *a = BN_new();
                    BN_hex2bn(&a, text);
                    BN_mod_exp(res1, a, d1, t, ctx);
                    printBN("n = ", t);
                    printBN("d = ", d1);

                    printBN("Plaintext (use Private key) = ", res1);

                    break;
                }
                }

                break;
            }
            }
        }
        case 0:
            flag = 0;
            break;
        }
    }

    return 0;
}