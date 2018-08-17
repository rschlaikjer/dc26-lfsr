#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct bruteforce_thread_args {
    const uint8_t *input;
    size_t input_len;
    uint64_t initial_value;
    uint64_t start_taps;
    uint64_t end_taps;
    uint64_t taps_checked;
    uint8_t thread_done;
};

uint8_t is_printable_str(uint8_t *s, size_t len);
uint8_t is_printable_chr(uint8_t c);

void bruteforce_8(const uint8_t *input, size_t input_len);
void bruteforce_64(const uint8_t *input, size_t input_len);

void bruteforce_64_parallel(const uint8_t *input, size_t input_len, uint64_t initial_value);
void *bruteforce_64_worker(void *args_v);

void decrypt_8(const uint8_t *source, size_t source_len, uint8_t *dest,
               uint8_t initial, uint8_t taps);

uint8_t decrypt_64(const uint8_t *source, size_t source_len, uint8_t *dest,
                   uint64_t initial, uint64_t taps);

static inline void shift_8(uint8_t *reg, uint8_t taps);
static inline void shift_64(uint64_t *reg, uint64_t taps);

static inline uint8_t xor_8(uint8_t reg, uint8_t taps);
static inline uint64_t xor_64(uint64_t reg, uint64_t taps);

const uint8_t crypt_lfsr_8_len = 31;
const uint8_t crypt_lfsr_8[] = {
    0x2B, 0xFC, 0x8E, 0x2B, 0x35, 0x61, 0xC0, 0x4F,
    0xBB, 0xC7, 0x3F, 0xA4, 0x3D, 0x5D, 0x96, 0x54,
    0x0D, 0x0A, 0xA0, 0x08, 0xB3, 0x09, 0x24, 0xCE,
    0x47, 0xDA, 0x0E, 0xC6, 0x75, 0x30, 0xD3
};

const size_t crypt_lfsr_64_len = 23;
const uint8_t crypt_lfsr_64[] = {
    0x9E, 0x1C, 0xE2, 0xC2, 0xF6, 0xFB, 0xFE, 0x19,
    0x86, 0x37, 0xE6, 0xF1, 0x0B, 0x95, 0x7D, 0xDD,
    0x50, 0xA7, 0x87, 0x41, 0x77, 0xA5, 0x1E,
};

const uint8_t taps_8 = (
    1 |
    1 << 2 |
    1 << 3 |
    1 << 4
);

int main() {
    // uint8_t dest[32];
    // decrypt_8(crypt_lfsr_8, crypt_lfsr_8_len, dest, 0x42, taps_8);
    // fprintf(stderr, "Out: %s\n", dest);
    // bruteforce_8(crypt_lfsr_8, crypt_lfsr_8_len);
    // bruteforce_64(crypt_lfsr_64, crypt_lfsr_64_len);

    // const uint64_t initial_state = 0x8000000000000000;
    // const uint64_t initial_state = 0x0000000000000080;
    const uint64_t initial_state = 0x8080808080808080;
    bruteforce_64_parallel(crypt_lfsr_64, crypt_lfsr_64_len, initial_state);
}

void bruteforce_64_parallel(const uint8_t *input, size_t input_len, uint64_t initial_value) {
    // Get the CPU count
    const long cpu_count = sysconf(_SC_NPROCESSORS_ONLN);

    // Figure out how much work for each thread
    // If the work doesn't divide perfectly, ensure some overlap
    pthread_t threads[cpu_count];
    struct bruteforce_thread_args* thread_state[cpu_count];
    const uint64_t max = 0xFFFFFFFFFFFFFFFF;
    uint64_t taps_per_thread = (max/cpu_count) + (max % cpu_count > 0 ? 1 : 0);
    uint64_t start_taps = 0x0;
    uint64_t end_taps = taps_per_thread;

    // Print some details
    fprintf(stderr, "Input ciphertext: ");
    for (size_t i = 0; i < input_len; i++) {
        fprintf(stderr, "%02x", input[i]);
    }
    fprintf(stderr, "\nStarting register value: 0x%016lx\n", initial_value);
    fprintf(stderr, "Worker thread count: %ld\n", cpu_count);

    // Spawn a worker thread for each core, partitioning the search space
    for (long i = 0; i < cpu_count; i++) {
        thread_state[i] = malloc(sizeof(struct bruteforce_thread_args));
        thread_state[i]->input = input;
        thread_state[i]->input_len = input_len;
        thread_state[i]->initial_value = initial_value;
        thread_state[i]->start_taps = start_taps;
        thread_state[i]->end_taps = end_taps;
        thread_state[i]->taps_checked = 0;
        thread_state[i]->thread_done = 0;
        if(pthread_create(&threads[i], NULL, bruteforce_64_worker, thread_state[i])) {
            fprintf(stderr, "Error creating thread\n");
            return;
        }
        start_taps = end_taps;
        end_taps += taps_per_thread;
        if (end_taps < start_taps)
            end_taps = max;
    }

    // Read progress from the workers in a loop til all are done
    struct timespec start_time;
    clock_gettime(CLOCK_MONOTONIC, &start_time);
    struct timespec now;
    for (;;) {
        // Gather stats from the threads
        uint64_t taps_checked = 0;
        uint8_t all_workers_done = 1;
        for (long i = 0; i < cpu_count; i++) {
            taps_checked += thread_state[i]->taps_checked;
            all_workers_done &= thread_state[i]->thread_done;
        }

        clock_gettime(CLOCK_MONOTONIC, &now);
        const time_t seconds_elapsed = now.tv_sec - start_time.tv_sec;
        const time_t minutes_elapsed = (seconds_elapsed / 60) % 60;
        const time_t hours_elapsed  = minutes_elapsed / 60;

        const double percent_complete = ((((double) taps_checked) * 100) / ((double) 0xFFFFFFFFFFFFFFFF));
        const double seconds_per_percent = seconds_elapsed / percent_complete;
        const double seconds_remaining = seconds_per_percent * 100;
        const time_t minutes_remaining = ((time_t) (seconds_remaining / 60)) % 60;
        const time_t hours_remaining = (seconds_remaining / 3600);
        fprintf(
            stderr,
            "Test progress: %016lx/%016lx (%.1f%%); Elapsed: %02lu:%02lu Remaining: %02lu:%02lu\r",
            taps_checked, 0xFFFFFFFFFFFFFFFF,
            percent_complete,
            hours_elapsed, minutes_elapsed,
            hours_remaining, minutes_remaining
        );

        // If we finished, break out
        if (all_workers_done) {
            fprintf(stderr, "\nAll workers done!\n");
            break;
        }

        // Sleep between printouts
        sleep(10);
    }

    // Await termination of all workers
    for (long i = 0; i < cpu_count; i++) {
        if (pthread_join(threads[i], NULL)) {
            fprintf(stderr, "Error creating thread\n");
        }
    }
}

void bruteforce_8(const uint8_t *input, size_t input_len) {
    uint8_t taps = 0;
    uint8_t output[input_len + 1];
    do {
        decrypt_8(input, input_len, output, 0x42, taps);
        if (is_printable_str(output, input_len + 1)) {
            fprintf(stderr, "Tap config 0x%x: %s\n", taps, output);
        }
        taps++;
    } while (taps > 0);
}

void *bruteforce_64_worker(void *args_v) {
    struct bruteforce_thread_args *args = args_v;

    uint64_t taps = args->start_taps;
    const uint64_t initial_state = args->initial_value;
    uint8_t output[args->input_len + 1];
    do {
        if (decrypt_64(args->input, args->input_len, output, initial_state, taps)) {
        // if (is_printable_str(output, args->input_len + 1)) {
            fprintf(stderr, "\nTap config 0x%0lx: %s\n", taps, output);
        }
        taps++;
        args->taps_checked++;
    } while (taps < args->end_taps);
    args->thread_done = 1;
    return NULL;
}

void bruteforce_64(const uint8_t *input, size_t input_len) {
    uint64_t taps = 0;
    // const uint64_t initial_state = 0x8000000000000000;
    // const uint64_t initial_state = 0x0000000000000080;
    const uint64_t initial_state = 0x8080808080808080;
    uint8_t output[input_len + 1];
    do {
        decrypt_64(input, input_len, output, initial_state, taps);
        if (is_printable_str(output, input_len + 1)) {
            fprintf(stderr, "Tap config 0x%0lx: %s\n", taps, output);
        }
        taps++;
        if (taps % 100000 == 0) {
            fprintf(
                stderr,
                "Test progress: %0lx/%0lx (%.1f%%)\r",
                taps, 0xFFFFFFFFFFFFFFFF,
                ((((double) taps) * 100) / ((double) 0xFFFFFFFFFFFFFFFF))
            );
        }
    } while (taps > 0);
}

uint8_t is_printable_str(uint8_t* text, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (!is_printable_chr(text[i])) {
            return 0;
        }
    }
    return 1;
}

uint8_t is_printable_chr(uint8_t c) {
    // Anything higher than space, but still 7 bit, probably good
    if (c >= ' ' && c < 0x80)
        return 1;

    // The only things below space that _might_ be ok are CR/LF
    if (c == '\r' || c == '\n' || c == 0)
        return 1;

    return 0;
}

uint8_t decrypt_64(const uint8_t *source, size_t source_len, uint8_t *dest,
                   uint64_t initial, uint64_t taps) {
    // Shift register state
    uint64_t reg = initial;

    // Clear the destination array
    // Extra byte for null terminator
    memset(dest, 0x0, source_len + 1);

    // Return value - 1 if string is printable
    uint8_t ret = 1;

    for (size_t by = 0; by < source_len; by++) {
        for (uint8_t bi = 0; bi < 64; bi++) {
            // Shift
            shift_64(&reg, taps);

            // Start at the high bit (all ops MSBfirst here)
            const uint64_t offset = 7 - bi;
            const uint64_t test = 1 << offset;
            // Get the MSB of the shift register state
            const uint64_t reg_xor_bit = (reg & ((uint64_t) 1 << 63)) >> 7;
            // Get the current bit of the ciphertext
            const uint64_t data_xor_bit = (source[by] & test) >> offset;
            // Xor them
            const uint64_t xor_result = reg_xor_bit ^ data_xor_bit;
            // Stick that bit back into the output
            dest[by] |= (xor_result << offset);
        }
        // Bail fast if the string starts looking bad
        if (!is_printable_chr(dest[by])) {
            ret = 0;
            goto exit;
        }
    }
exit:
    // Terminate the string
    dest[source_len] = 0x0;
    return ret;
}

void decrypt_8(const uint8_t *source, size_t source_len, uint8_t *dest,
               uint8_t initial, uint8_t taps) {
    // Shift register state
    uint8_t reg = initial;

    // Clear the destination array
    // Extra byte for null terminator
    memset(dest, 0x0, source_len + 1);

    for (size_t by = 0; by < source_len; by++) {
        for (uint8_t bi = 0; bi < 8; bi++) {
            // Shift
            shift_8(&reg, taps);
            // Start at the high bit (all ops MSBfirst here)
            const uint8_t offset = 7 - bi;
            const uint8_t test = 1 << offset;
            // Get the MSB of the shift register state
            const uint8_t reg_xor_bit = (reg & (1 << 7)) >> 7;
            // Get the current bit of the ciphertext
            const uint8_t data_xor_bit = (source[by] & test) >> offset;
            // Xor them
            const uint8_t xor_result = reg_xor_bit ^ data_xor_bit;
            // Stick that bit back into the output
            dest[by] |= (xor_result << offset);
        }
    }

    // Terminate the string
    dest[source_len] = 0x0;
}

static inline void shift_64(uint64_t *reg, uint64_t taps) {
    uint64_t xor = xor_64(*reg, taps);
    *reg = *reg >> 1;
    *reg |= xor << 63;
}

static inline void shift_8(uint8_t *reg, uint8_t taps) {
    uint8_t xor = xor_8(*reg, taps);
    *reg = *reg >> 1;
    *reg |= xor << 7;
}

static inline uint64_t xor_64(uint64_t reg, uint64_t taps) {
    uint8_t state = 0;
    for (int i = 0; i < 64 && taps; i++) {
        if (0x1 & taps) {
            state = state ^ (reg & 1);
        }
        reg = reg >> 1;
        taps = taps >> 1;
    }
    return state;
}

static inline uint8_t xor_8(uint8_t reg, uint8_t taps) {
    uint8_t state = 0;
    for (int i = 0; i < 8 && taps; i++) {
        if (0x1 & taps) {
            state = state ^ (reg & 1);
        }
        reg = reg >> 1;
        taps = taps >> 1;
    }
    return state;
}
