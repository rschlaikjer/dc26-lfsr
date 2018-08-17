#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define USE_POPCNT

// Set 8 or 64 bit mode
#define BIT_SIZE 64

#if BIT_SIZE == 64
typedef uint64_t lfsr_reg;
const lfsr_reg lfsr_max = 0xFFFFFFFFFFFFFFFF;
#else  // BIT_SIZE != 64
typedef uint8_t lfsr_reg;
const lfsr_reg lfsr_max = 0xFF;
#endif // BIT_SIZE == 64

struct bruteforce_thread_args {
    const uint8_t *input;
    size_t input_len;
    lfsr_reg initial_value;
    lfsr_reg start_taps;
    lfsr_reg end_taps;
    size_t taps_checked;
    uint8_t thread_done;
};

uint8_t is_printable_str(uint8_t *s, size_t len);
uint8_t is_printable_chr(uint8_t c);

void bruteforce(const uint8_t *input, size_t input_len);

void bruteforce_parallel(const uint8_t *input, size_t input_len, lfsr_reg initial_value);
void *bruteforce_worker(void *args_v);

uint8_t decrypt(const uint8_t *source, size_t source_len, uint8_t *dest,
                lfsr_reg initial, lfsr_reg taps);

static void shift(lfsr_reg *reg, lfsr_reg taps);

static uint8_t xor_taps(lfsr_reg reg, lfsr_reg taps);

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

int main() {
    fprintf(stderr, "Running in %d-bit mode\n", BIT_SIZE);

#if BIT_SIZE == 64
    lfsr_reg initial_state = 0x8080808080808080;
    bruteforce_parallel(crypt_lfsr_64, crypt_lfsr_64_len, initial_state);
#else
    lfsr_reg initial_state = 0x42;
    bruteforce_parallel(crypt_lfsr_8, crypt_lfsr_8_len, initial_state);
#endif
}

void bruteforce_parallel(const uint8_t *input, size_t input_len, lfsr_reg initial_value) {
    // Get the CPU count
    const long cpu_count = sysconf(_SC_NPROCESSORS_ONLN);

    // Figure out how much work for each thread
    // If the work doesn't divide perfectly, ensure some overlap
    pthread_t threads[cpu_count];
    struct bruteforce_thread_args* thread_state[cpu_count];
    const lfsr_reg max = lfsr_max;
    lfsr_reg taps_per_thread = (max/cpu_count) + (max % cpu_count > 0 ? 1 : 0);
    lfsr_reg start_taps = 0x0;
    lfsr_reg end_taps = taps_per_thread;

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
        if(pthread_create(&threads[i], NULL, bruteforce_worker, thread_state[i])) {
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
        size_t taps_checked = 0;
        uint8_t all_workers_done = 1;
        for (long i = 0; i < cpu_count; i++) {
            taps_checked += thread_state[i]->taps_checked;
            all_workers_done &= thread_state[i]->thread_done;
        }

        clock_gettime(CLOCK_MONOTONIC, &now);
        const time_t seconds_elapsed = now.tv_sec - start_time.tv_sec;
        const time_t minutes_elapsed = (seconds_elapsed / 60) % 60;
        const time_t hours_elapsed  = minutes_elapsed / 60;

        const double percent_complete = ((((double) taps_checked) * 100) / ((double) lfsr_max));
        const double seconds_per_percent = seconds_elapsed / percent_complete;
        const double seconds_remaining = seconds_per_percent * 100;
        const time_t minutes_remaining = ((time_t) (seconds_remaining / 60)) % 60;
        const time_t hours_remaining = (seconds_remaining / 3600);
        fprintf(
            stderr,
            "Test progress: %016lx/%016lx (%.1f%%); Elapsed: %02lu:%02lu Remaining: %02lu:%02lu\r",
            taps_checked, lfsr_max,
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
        sleep(1);
    }

    // Await termination of all workers
    for (long i = 0; i < cpu_count; i++) {
        if (pthread_join(threads[i], NULL)) {
            fprintf(stderr, "Error creating thread\n");
        }
    }
}

void *bruteforce_worker(void *args_v) {
    struct bruteforce_thread_args *args = args_v;

    lfsr_reg taps = args->start_taps;
    const lfsr_reg initial_state = args->initial_value;
    uint8_t output[args->input_len + 1];
    do {
        if (decrypt(args->input, args->input_len, output, initial_state, taps)) {
        // if (is_printable_str(output, args->input_len + 1)) {
            fprintf(stderr, "\nTap config 0x%0lx: %s\n", taps, output);
        }
        taps++;
        args->taps_checked++;
    } while (taps < args->end_taps);
    args->thread_done = 1;
    return NULL;
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

uint8_t decrypt(const uint8_t *source, size_t source_len, uint8_t *dest,
                lfsr_reg initial, lfsr_reg taps) {
    // Shift register state
    lfsr_reg reg = initial;

    // Clear the destination array
    // Extra byte for null terminator
    memset(dest, 0x0, source_len + 1);

    // Return value - 1 if string is printable
    uint8_t ret = 1;

    for (size_t by = 0; by < source_len; by++) {
        lfsr_reg test = ((lfsr_reg) 1) << (BIT_SIZE - 1);
        for (uint8_t bi = 0; bi < BIT_SIZE; bi++) {
            // Shift
            shift(&reg, taps);

            // Start at the high bit (all ops MSBfirst here)
            const lfsr_reg offset = (BIT_SIZE - 1) - bi;

            // Get the MSB of the shift register state
            const lfsr_reg reg_xor_bit = (reg & ((lfsr_reg ) 1 << (BIT_SIZE - 1))) >> (BIT_SIZE - 1);
            // Get the current bit of the ciphertext
            const lfsr_reg data_xor_bit = (source[by] & test) >> offset;
            // Xor them
            const lfsr_reg xor_result = reg_xor_bit ^ data_xor_bit;
            // Stick that bit back into the output
            dest[by] |= (xor_result << offset);

            test = test >> 1;
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

static void shift(lfsr_reg *reg, lfsr_reg taps) {
    lfsr_reg xor = xor_taps(*reg, taps);
    *reg = *reg >> 1;
    *reg |= xor << (BIT_SIZE - 1);
}

static uint8_t xor_taps(lfsr_reg reg, lfsr_reg taps) {
#ifdef USE_POPCNT
    const uint8_t popcnt_taps = __builtin_popcountll(taps);
    const uint8_t popcnt_taps_reg = __builtin_popcountll(taps & reg);
    return (popcnt_taps - popcnt_taps_reg) % 2;
#else // USE_POPCNT
    uint8_t state = 0;
    for (int i = 0; i < BIT_SIZE && taps; i++) {
        if (0x1 & taps) {
            state = state ^ (reg & 1);
        }
        reg = reg >> 1;
        taps = taps >> 1;
    }
    return state;
#endif
}
