#include <string.h>
#include "openssl/ec.h"
#include "openssl/ecdsa.h"
#include "openssl/bn.h"
#include "openssl/obj_mac.h"
#include "openssl/sha.h"

int main()
{
    EC_KEY *key_pair_obj = nullptr;
    EC_KEY *test_key_pair_obj = nullptr;

    int ret_error;
    BIGNUM *priv_key;
    EC_POINT *pub_key;
    EC_GROUP *secp256k1_group;
    char *pub_key_char, *priv_key_char;

    const char *message = "test msg11111";
    unsigned char buffer_digest[SHA256_DIGEST_LENGTH];
    uint8_t *digest;
    uint8_t *signature;
    uint32_t signature_len;
    int verification;

    // initiate
    test_key_pair_obj = EC_KEY_new();

    // create EC_KEY curve object
    key_pair_obj = EC_KEY_new_by_curve_name(NID_secp256k1);
    // generate public key pair and set domain params of secp256k1
    ret_error = EC_KEY_generate_key(key_pair_obj);    

    // get private key(BIGNUM(it is encoded in hex values))
    priv_key = (BIGNUM *)EC_KEY_get0_private_key(key_pair_obj);
    // convert BIGNUM to hexdecimal
    priv_key_char = BN_bn2hex(priv_key);

    // get public key(is extracted from the key object)
    pub_key = (EC_POINT *)EC_KEY_get0_public_key(key_pair_obj);

    // get secp256k1 EC_GROUP
    secp256k1_group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    // pubkey: (prefix | x | y)
    // prefix
        // POINT_CONVERSION_COMPRESSED = 2(compressed type: 0x02)
        // POINT_CONVERSION_UNCOMPRESSED = 4(uncompressed type: 0x04)
    
    pub_key_char = EC_POINT_point2hex(secp256k1_group, pub_key, POINT_CONVERSION_COMPRESSED, nullptr);

    EC_GROUP_free(secp256k1_group);

    printf("Pivate key: %s\n", priv_key_char);
    printf("Public key: %s\n", pub_key_char);

    // check the length and structure of signature (DER 포맷에서의 r와 s)
    signature_len = ECDSA_size(key_pair_obj);

    signature = (uint8_t *)OPENSSL_malloc(signature_len);

    // hash of message
    digest = SHA256((const unsigned char *)message, strlen(message), buffer_digest);
    // sign
    ret_error = ECDSA_sign(0, (const uint8_t *)digest, SHA256_DIGEST_LENGTH, signature, &signature_len, key_pair_obj);

    // print hash of message and signature
    printf("Hash of Msg: ");
    for (uint32_t i = 0; i < SHA256_DIGEST_LENGTH; i++)
        printf("%02x", digest[i]);
    printf("\n");
    printf("Signature     : ");
    for (uint32_t i = 0; i < signature_len; i++)
        // print hexstring
        printf("%02x", signature[i]);
    printf("\n");

    // verify
    verification = ECDSA_verify(0, digest, SHA256_DIGEST_LENGTH, signature, signature_len, key_pair_obj);
    if (verification == 1)
        printf("Verification    successful\n");
    else
        printf("Verification    NOT successful\n");

    EC_KEY_free(key_pair_obj);

    OPENSSL_free(signature);

    return 0;
}
