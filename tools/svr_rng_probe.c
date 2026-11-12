/* Offline check of the retail game's byte-at-a-time Park-Miller generator.
 * Input: public auth IV seeds, as eight hex digits each (u32 little endian).
 * Output contains candidate counts and stream relationships, never passwords.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <time.h>

static uint32_t step(uint32_t s) {
    return (uint64_t)s * 16807 % 2147483647;
}

unsigned recover(uint32_t word, uint32_t *out, unsigned capacity) {
    unsigned count = 0;
    for (uint32_t first = word & 255; first < 2147483647; first += 256) {
        if (!first) continue;
        uint32_t s = first;
        int match = 1;
        for (int i = 1; i < 4; ++i) {
            s = step(s);
            if ((s & 255) != ((word >> (8*i)) & 255)) { match = 0; break; }
        }
        if (match) {
            if (count < capacity) out[count] = first;
            ++count;
        }
    }
    return count;
}

int main(int argc, char **argv) {
    for (int arg = 1; arg < argc; ++arg) {
        uint32_t word = (uint32_t)strtoul(argv[arg], NULL, 16);
        unsigned count = 0, linked = 0;
        clock_t start = clock();
        for (uint32_t first = word & 255; first < 2147483647; first += 256) {
            if (!first) continue;
            uint32_t s = first;
            int match = 1;
            for (int i = 1; i < 4; ++i) {
                s = step(s);
                if ((s & 255) != ((word >> (8*i)) & 255)) { match = 0; break; }
            }
            if (!match) continue;
            ++count;
            if (arg + 1 < argc) {
                uint32_t next = (uint32_t)strtoul(argv[arg+1], NULL, 16);
                uint32_t window = 0;
                for (unsigned gap = 0; gap < 65536 + 4; ++gap) {
                    s = step(s);
                    window = (window >> 8) | ((s & 255) << 24);
                    if (gap >= 3 && window == next) {
                        ++linked;
                        printf("seed[%d] -> seed[%d]: matching stream, %u intervening bytes\n",
                               arg-1, arg, gap-3);
                    }
                }
            }
        }
        printf("seed[%d]: %u candidate states, %u next-seed links (%.3fs)\n",
               arg-1, count, linked, (double)(clock()-start)/CLOCKS_PER_SEC);
    }
    return 0;
}
