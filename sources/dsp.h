/**
 * Copyright (C) AlexandrinKS
 * https://akscf.me/
 **/
#include <switch.h>

#define I16_MAX 32768
#define U16_MAX 65536

static inline int mix_smp(int a, int b) {
    int smp = 0;
    a += I16_MAX; b += I16_MAX;
    if ((a < I16_MAX) || (b < I16_MAX)) { smp = a * b / I16_MAX;
    } else { smp = (2 * (a + b) - (a * b) / I16_MAX) - U16_MAX; }
    if (smp == U16_MAX) smp = (U16_MAX - 1);
    return (smp - I16_MAX);
}

static inline void mix_buf(switch_byte_t *dst, switch_byte_t *src, uint32_t len) {
    uint32_t i = 0;
    for(i = 0; i < len; i++) {
        dst[i] = mix_smp(dst[i], src[i]);
    }
}

