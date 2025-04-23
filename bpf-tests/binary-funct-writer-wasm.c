#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
// #include <sys/times.h>
#include <sys/mman.h>
#include <dis-asm.h>
#include <elf.h>

// SECTION NAME STRING
#define SECTION ".text"

#define SECONDS      1000000000
#define MILLISECONDS 1000000
#define MICROSECONDS 1000
#define NANOSECONDS  1

typedef struct {
    char *insn_buffer;
    bool reenter;
} stream_state;

// definition for inside the wasm executable
typedef uint32_t __u32;
static __u32 ar[256] = { 0 };

// timer helper function for TSC (time stamp counter)
// https://stackoverflow.com/questions/14017894/time-calculation-with-tsc-time-stamp-counter
// and
// https://stackoverflow.com/questions/13772567/how-to-get-the-cpu-cycle-count-in-x86-64-from-c/64898073#64898073
unsigned long long rdtscl(void)
{
    unsigned int lo, hi;
    __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
    return ( (unsigned long long)lo)|( ((unsigned long long)hi)<<32 );
}

// volatile unsigned long current_time;

// static void *clock_handler() {
// 	static time_t monotonic_start;
// 	struct timeval t = {.tv_sec = 1, .tv_usec = 0};
// 	struct timespec ts;

// 	clock_gettime(CLOCK_MONOTONIC, &ts);
// 	monotonic_start = ts.tv_sec - 2;

// 	for (;;) {
// 		clock_gettime(CLOCK_MONOTONIC, &ts);
// 		current_time = ts.tv_sec - monotonic_start;
// 		usleep(1 * MICROSECONDS);
// 	}
// }

static int dis_fprintf(void *stream, const char *fmt, ...) {
    // stream_state *ss = (stream_state *)stream;
    // va_list arg;
    // va_start(arg, fmt);
    // if (!ss->reenter) {
    //     vasprintf(&ss->insn_buffer, fmt, arg);
    //     ss->reenter = true;
    // } else {
    //     char *tmp;
    //     vasprintf(&tmp, fmt, arg);
    //     char *tmp2;
    //     asprintf(&tmp2, "%s%s", ss->insn_buffer, tmp);
    //     free(ss->insn_buffer);
    //     free(tmp);
    //     ss->insn_buffer = tmp2;
    // }
    // va_end(arg);
    return 0;
}

static int dis_fprintf_styled(void *stream, enum disassembler_style style,
    const char *fmt, ...) {
    // stream_state *ss = (stream_state *)stream;
    // va_list arg;
    // va_start(arg, fmt);
    // if (!ss->reenter) {
    //     vasprintf(&ss->insn_buffer, fmt, arg);
    //     ss->reenter = true;
    // } else {
    //     char *tmp;
    //     vasprintf(&tmp, fmt, arg);
    //     char *tmp2;
    //     asprintf(&tmp2, "%s%s", ss->insn_buffer, tmp);
    //     free(ss->insn_buffer);
    //     free(tmp);
    //     ss->insn_buffer = tmp2;
    // }
    // va_end(arg);
    return 0;
}

/* Utility function to get file size. */
int fileSize(int fd) {
    struct stat s;
    if (fstat(fd, &s) == -1) {
        return -1;
    }
    return s.st_size;
}

/*
 * patch_binary:
 *
 *   Reads the input ELF file (the relocatable wasm binary), extracts only the code
 *   for aot_func#1 (which is in .text, starting at file offset 0x50 for 305 bytes),
 *   disassembles and patches it instruction-by-instruction (patching direct calls and
 *   absolute movabs instructions to fix pointers), and then appends a stub function.
 *
 *   The stub function returns the address of the global array 'ar'.
 */
int patch_binary(const char *input_file, const char *output_file) {
    int fd = open(input_file, O_RDONLY);
    if (fd < 0) {
        perror("open input file");
        return 1;
    }

    // Read ELF header
    Elf64_Ehdr ehdr;
    if (lseek(fd, 0, SEEK_SET) < 0 ||
        read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) {
        perror("read ELF header"); close(fd); return 1;
    }
    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "Not an ELF file\n"); close(fd); return 1;
    }

    // Read section header string table header
    off_t shoff      = ehdr.e_shoff;
    uint16_t shentsz = ehdr.e_shentsize;
    uint16_t shnum   = ehdr.e_shnum;
    uint16_t strndx  = ehdr.e_shstrndx;

    Elf64_Shdr shstr_sh;
    if (lseek(fd, shoff + (off_t)strndx * shentsz, SEEK_SET) < 0 ||
        read(fd, &shstr_sh, sizeof(shstr_sh)) != sizeof(shstr_sh)) {
        perror("read shstrtab header"); close(fd); return 1;
    }

    // Load section header string table
    char *shstrtab = malloc(shstr_sh.sh_size);
    if (!shstrtab) { perror("malloc shstrtab"); close(fd); return 1; }
    if (lseek(fd, shstr_sh.sh_offset, SEEK_SET) < 0 ||
        read(fd, shstrtab, shstr_sh.sh_size) != (ssize_t)shstr_sh.sh_size) {
        perror("read shstrtab"); free(shstrtab); close(fd); return 1;
    }

    // Locate section specified by SECTION string
    off_t text_off = 0;
    size_t text_size = 0;
    for (int i = 0; i < shnum; i++) {
        Elf64_Shdr sh;
        if (lseek(fd, shoff + (off_t)i * shentsz, SEEK_SET) < 0 ||
            read(fd, &sh, sizeof(sh)) != sizeof(sh)) {
            perror("read section header"); free(shstrtab); close(fd); return 1;
        }
        const char *name = shstrtab + sh.sh_name;
        if (strcmp(name, SECTION) == 0) {
            text_off  = sh.sh_offset;
            text_size = sh.sh_size;
            break;
        }
    }
    free(shstrtab);

    if (text_size == 0) {
        fprintf(stderr, SECTION " section not found\n");
        close(fd);
        return 1;
    }

    // Read .text section
    uint8_t *buffer = malloc(text_size);
    if (!buffer) { perror("malloc text buffer"); close(fd); return 1; }
    if (lseek(fd, text_off, SEEK_SET) < 0 ||
        read(fd, buffer, text_size) != (ssize_t)text_size) {
        perror("read "SECTION" failed"); free(buffer); close(fd); return 1;
    }
    close(fd);

    // printf("Extracted function (aot_func#1) bytes:\n");
    // for (size_t i = 0; i < func_size; i++) {
    //     printf("0x%02X ", buffer[i]);
    //     if ((i + 1) % 16 == 0)
    //         printf("\n");
    // }
    // printf("\n");

    /* Define the stub function machine code that returns the address of the global array 'ar'.
     * This stub will execute:
     *    movabs rax, <address of ar>  (opcode: 48 B8 <imm64>)
     *    ret                        (opcode: C3)
     */
    uint8_t stub_code[11] = {
        0x48, 0xB8,       // movabs rax, imm64
        0, 0, 0, 0, 0, 0, 0, 0, // placeholder for the 8-byte address of 'ar'
        0xC3              // ret
    };
    // Fill in the immediate field with the address of the global array variable 'ar'
    uint64_t ptr = (uint64_t)&ar;
    memcpy(stub_code + 2, &ptr, sizeof(ptr));
    size_t stub_size = sizeof(stub_code);

    // Prepare output buffer
    size_t func_size = text_size;
    size_t new_size  = func_size + stub_size;
    uint8_t *new_buffer = malloc(new_size);
    if (!new_buffer) { perror("malloc new_buffer"); free(buffer); return 1; }

    /* The new binary will contain the extracted function (patched) plus the stub appended at the end. */
    // size_t new_size = func_size + stub_size;
    // uint8_t *new_buffer = malloc(new_size);
    // if (!new_buffer) {
    //     perror("malloc new_buffer");
    //     free(buffer);
    //     return 1;
    // }

    /* Set up the disassembler info to process instructions in the function. */
    size_t pc = 0;      /* offset into the function buffer */
    size_t out_pc = 0;  /* offset into the new (output) buffer */

    stream_state ss = {0};
    ss.insn_buffer = NULL;
    ss.reenter = false;

    disassemble_info disasm_info;
    memset(&disasm_info, 0, sizeof(disasm_info));
    init_disassemble_info(&disasm_info, &ss, dis_fprintf, dis_fprintf_styled);
    disasm_info.arch = bfd_arch_i386;
    disasm_info.mach = bfd_mach_x86_64;
    disasm_info.read_memory_func = buffer_read_memory;
    disasm_info.buffer = buffer;
    disasm_info.buffer_vma = 0;      // treat offset 0 as beginning of function code
    disasm_info.buffer_length = func_size;
    disassemble_init_for_target(&disasm_info);

    disassembler_ftype disasm;
    disasm = disassembler(bfd_arch_i386, false, bfd_mach_x86_64, NULL);

    /* Process the function code instruction by instruction. */
    while (pc < func_size) {
        size_t insn_size = disasm(pc, &disasm_info);
        if (insn_size == 0) {
            /* On disassembly failure, copy the remaining bytes as-is and break. */
            while (pc < func_size) {
                new_buffer[out_pc++] = buffer[pc++];
            }
            break;
        }
        /* Patch direct calls: if the opcode is 0xE8 and length >= 5,
         * compute a new relative offset so that the call reaches our stub.
         */
        if (buffer[pc] == 0xE8 && insn_size >= 5) {
            int32_t new_offset = (int32_t)(func_size - (pc + insn_size));
            new_buffer[out_pc++] = 0xE8;
            new_buffer[out_pc++] = (uint8_t)(new_offset & 0xFF);
            new_buffer[out_pc++] = (uint8_t)((new_offset >> 8) & 0xFF);
            new_buffer[out_pc++] = (uint8_t)((new_offset >> 16) & 0xFF);
            new_buffer[out_pc++] = (uint8_t)((new_offset >> 24) & 0xFF);
        }
        else {
            // For all other instructions, copy the bytes unchanged.
            for (size_t i = 0; i < insn_size; i++) {
                new_buffer[out_pc++] = buffer[pc + i];
            }
        }
        pc += insn_size;
        /* Reset the stream state for the next instruction. */
        if (ss.insn_buffer) {
            free(ss.insn_buffer);
            ss.insn_buffer = NULL;
            ss.reenter = false;
        }
    }

    /* Append the stub function code at the end of the new binary. */
    memcpy(new_buffer + out_pc, stub_code, stub_size);
    out_pc += stub_size;

    printf("Patched binary bytes:\n");
    for (size_t i = 0; i < out_pc; i++) {
        printf("0x%02X ", new_buffer[i]);
        if ((i + 1) % 16 == 0)
            printf("\n");
    }
    printf("\n");

    /* Write out the new binary (which consists solely of the patched function + stub). */
    int out_fd = open(output_file, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (out_fd < 0) {
        perror("open output file");
        free(buffer);
        free(new_buffer);
        return 1;
    }
    if (write(out_fd, new_buffer, out_pc) != (ssize_t)out_pc) {
        perror("write output file");
        free(buffer);
        free(new_buffer);
        close(out_fd);
        return 1;
    }
    close(out_fd);
    free(buffer);
    free(new_buffer);
    return 0;
}

int run_timing_loop(const char *patched_file, int num_runs) {
    int fd = open(patched_file, O_RDONLY);
    if (fd < 0) {
        perror("open patched binary");
        return 1;
    }

    int size = fileSize(fd);
    if (size < 0) {
        perror("fileSize");
        close(fd);
        return 1;
    }

    void *pointer = mmap(NULL, size, PROT_EXEC, MAP_SHARED, fd, 0);
    if (pointer == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return 1;
    }
    close(fd);

    // The patched binary now consists solely of aot_func#1 (with patches) plus our stub.
    // Its function signature is assumed to be: void f(void *arg)
    void (*fptr)(void *) = (void (*)(void *)) pointer;

    // Build an argument buffer containing pointers expected by the raw assembly.
    uint8_t argbuf[0x40] = { 0 };
    // At offset 0x10, 0x30, and 0x38 place the address of global 'ar'
    *(uint64_t*)(argbuf + 0x10) = (uint64_t) ar;
    *(uint64_t*)(argbuf + 0x30) = (uint64_t) ar;
    *(uint64_t*)(argbuf + 0x38) = (uint64_t) ar;

    /* set up timer thread to avoid measuring overhead */
    // pthread_t tid;
    unsigned long long start, end = 0;
    unsigned long long elapsed = 0;

    // init
    start = rdtscl();

    for (int i = 0; i < num_runs; i++) {
        // Call the executable function, passing our argument buffer.
        fptr(argbuf);
    }

    end = rdtscl();
    elapsed += end - start;

    double average_cycle_count = (double) elapsed/num_runs;
    printf("EBPF execution time:\n");
    printf("Executed %d time(s), Average cycles: %f\n",
        num_runs, average_cycle_count);

    munmap(pointer, size);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <input_elf> <num_runs>\n", argv[0]);
        return 1;
    }

    const char *input_file = argv[1];
    int num_runs = atoi(argv[2]);
    if (num_runs <= 0) {
        fprintf(stderr, "Number of runs must be positive.\n");
        return 1;
    }

    const char *patched_file = "bpf-binary-patched.o";

    /* Patch the input ELF by extracting and patching aot_func#1. */
    if (patch_binary(input_file, patched_file) != 0) {
        fprintf(stderr, "Error patching the binary.\n");
        return 1;
    }

    /* Run the patched binary in a timing loop. */
    if (run_timing_loop(patched_file, num_runs) != 0) {
        fprintf(stderr, "Error running the timing loop.\n");
        return 1;
    }

    return 0;
}
