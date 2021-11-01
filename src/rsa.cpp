#include <stdlib.h>
#include <string.h>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/md.h>
#include <mbedtls/rsa.h>
#include <mbedtls/x509.h>

#include <mkbktr.hpp>
#include <mkbktr/rsa.hpp>
#include <mkbktr/util/log.hpp>

// Use the same private key as hacpack
const char rsa_acid_private_key[] =
    "-----BEGIN RSA PRIVATE KEY-----\r\n"
    "MIIEowIBAAKCAQEAvVRzt+8mE7oE4RkmSh3ws4CGlBj7uhHkfwCpPFsn4TNVdLRo\r\n"
    "YYY17jQYWTtcOYPMcHxwUpgJyspGN8QGXEkJqY8jILv2eO0jBGtg7Br2afUBp6/x\r\n"
    "BOMT2RlYVX6H4a1UA19Hzmcn+T1hdDwS6oBYpi8rJSm0+q+yB34dueNkVsk4eKbj\r\n"
    "CNNKFi+XgyNBi41d57SPCrkcm/9tkagRorE8vLcFPcXcYOjdXH3L4XTXq7sxxytA\r\n"
    "I66erfSc4XunkoLifcbfMOB3gjGCoQs6GfaiAU3TwxewQ7hdoqvj5Gm9VyHqzeDF\r\n"
    "5mUTlmed2I6m4ELxbV1b0lUguR5ZEzwXwiVWxwIDAQABAoIBADvLYkijFOmCBGx7\r\n"
    "HualkhF+9AHt6gKYCAw8Tzaqq2uqZMDZAWZblsjGVzJHVxcrEvQruOW88srDG24d\r\n"
    "UMzwnEaa2ENMWclTS43nw9KNqWlJYd5t6LbcaLZWFNnbflq9/RybiPgdCDjlM9Qb\r\n"
    "7PV214iUuRGhnHDX8GgBYq4ErPnjQ7+Gv1ducpMYjZencLWCl4fFX86U0/MU0+Qf\r\n"
    "jKGegQTnk52aaeScbDOjjx5h+m0hkDNSfsmXTlvJt2c8wy/Yx+leVgCPjMC1nbft\r\n"
    "Ob1TlpjuEAKBOGt4+DkWwVmIlxilmx9wCTZnwvPKd7A0e0FGsdHnQienPrMqlgbl\r\n"
    "JPYwJuECgYEA6yLZHTfX3ebpzcdQQqmuHZtbOcs+EGRy24gAzd+9vCGKf0VtKSl9\r\n"
    "3oA3XBOe2C2TgSgbWFZ7v/2efWRjgwJta0BQlpkzkh6NUQa2LI2M3zgZwHCZ7Ihr\r\n"
    "skG73qZsMHOOv7VQz/wDp6AZNasfz21Mcyh4uFzpkb3NKLXqsJ9LeG8CgYEAziEb\r\n"
    "yBCuhCKq7YZt/cHlbCbi7HbCYbub0isOCUtV0qPsX+kVZdPS+oGLPq1905JKdAe9\r\n"
    "O+4SltCw6qn9RgYnCCVQ47SGHg7KO8Z5vdcNUiDvsQ+jNFlmM5QBuf1UV/Y+DV/Q\r\n"
    "fZdA06OeYxkfPuBMtjdS9qMKwm3OsCkiQasWQykCgYAqALieAoq6JfSgALmyntLu\r\n"
    "kQDzyv2UOg1Wb+4M2KnxAGDYKVO9pZ7Jb0f0V8DpRwLxcHOqDRDgE/MK3TL1hSp8\r\n"
    "nSmILWfL8081KSjDvqlqeoAHI1YrrZbnadyggkQTR6E5V69O5+rTN8MpFh+Bkzmz\r\n"
    "3IfsDxTeJvSOECkTUfFOWwKBgQDG/id3yMLxRRaGH5TnuNvmwNOpPC0DdL5E8tOm\r\n"
    "HVhI9X8oSDgkCY5Pz+fBJnOmYEAIK8B/rqG7ftSMdnbPtvjPYFbqvEgNlHGfq0e0\r\n"
    "AXwWoT1ETbhcvUFw4Z2ZE/rswAe/mZQI6o/mwLoTKRmE9byY3Gf3OgcVFDTI060C\r\n"
    "gEwJoQKBgHpOmtGum3JuLpPc+PTXZOe29tdWndkFWktjPoow60d+NO2jpTFuEpmW\r\n"
    "XRW35vXI8PqMCmHOQ8YU59aMN9juAnsJmPUxbAW5fZfvVwWUo0cTOenfT6syrEYO\r\n"
    "n5NEG+mY4WZaOFRNiZu8+4aJI1yycXMyA22iKcU8+nN/sMAJs3Nx\r\n"
    "-----END RSA PRIVATE KEY-----\r\n";

void rsa_sign(void *input, size_t input_size, unsigned char *output,
              size_t output_size) {
  unsigned char hash[32];
  unsigned char buf[MBEDTLS_MPI_MAX_SIZE];
  const char *pers = "rsa_sign_pss";
  size_t olen = 0;

  mbedtls_pk_context pk;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;

  mbedtls_entropy_init(&entropy);
  mbedtls_pk_init(&pk);
  mbedtls_ctr_drbg_init(&ctr_drbg);

  // Parse private key and sign input
  mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                        (const unsigned char *)pers, strlen(pers));
  mbedtls_pk_parse_key(&pk, (unsigned char *)rsa_acid_private_key,
                       strlen(rsa_acid_private_key) + 1, NULL, 0);
  mbedtls_rsa_set_padding(mbedtls_pk_rsa(pk), MBEDTLS_RSA_PKCS_V21,
                          MBEDTLS_MD_SHA256);
  mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
             (unsigned char *)input, input_size, hash);
  mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256, hash, 0, buf, &olen,
                  mbedtls_ctr_drbg_random, &ctr_drbg);

  // Copy signature to output
  memcpy(output, buf, output_size);

  mbedtls_pk_free(&pk);
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
}
