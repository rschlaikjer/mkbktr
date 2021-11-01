#pragma once

#include <stdint.h>

void rsa_sign(void *input, size_t input_size, unsigned char *output,
              size_t output_size);
