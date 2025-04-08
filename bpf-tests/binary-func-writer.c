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
#include <sys/mman.h>
#include <dis-asm.h>

typedef struct {
    char *insn_buffer;
    bool reenter;
} stream_state;

static int dis_fprintf(void *stream, const char *fmt, ...) {
    stream_state *ss = (stream_state *)stream;
    va_list arg;
    va_start(arg, fmt);
    if (!ss->reenter) {
        vasprintf(&ss->insn_buffer, fmt, arg);
        ss->reenter = true;
    } else {
        char *tmp;
        vasprintf(&tmp, fmt, arg);
        char *tmp2;
        asprintf(&tmp2, "%s%s", ss->insn_buffer, tmp);
        free(ss->insn_buffer);
        free(tmp);
        ss->insn_buffer = tmp2;
    }
    va_end(arg);
    return 0;
}

static int dis_fprintf_styled(void *stream, enum disassembler_style style, const char *fmt, ...) {
    stream_state *ss = (stream_state *)stream;
    va_list arg;
    va_start(arg, fmt);
    if (!ss->reenter) {
        vasprintf(&ss->insn_buffer, fmt, arg);
        ss->reenter = true;
    } else {
        char *tmp;
        vasprintf(&tmp, fmt, arg);
        char *tmp2;
        asprintf(&tmp2, "%s%s", ss->insn_buffer, tmp);
        free(ss->insn_buffer);
        free(tmp);
        ss->insn_buffer = tmp2;
    }
    va_end(arg);
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
 *   Reads the input file (binary to patch), disassembles it instruction-by-instruction,
 *   and patches any direct call (opcode 0xE8) by computing a new relative offset 
 *   so that the call targets our stub function. It then appends the stub (a minimal function)
 *   to the end and writes the new binary to output_file.
 */
int patch_binary(const char *input_file, const char *output_file) {
    int fd = open(input_file, O_RDONLY);
    if (fd < 0) {
        perror("open input file");
        return 1;
    }
    int size = fileSize(fd);
    if (size < 0) {
        perror("fileSize");
        close(fd);
        return 1;
    }
    
    uint8_t *buffer = malloc(size);
    if (!buffer) {
        perror("malloc");
        close(fd);
        return 1;
    }
    
    ssize_t bytesRead = read(fd, buffer, size);
    if (bytesRead != size) {
        perror("read");
        free(buffer);
        close(fd);
        return 1;
    }
    close(fd);

    /* Define the stub function machine code.
     * stub_call:
     *   push rbp         (0x55)
     *   mov rbp, rsp     (0x48 0x89 0xe5)
     *   pop rbp          (0x5d)
     *   ret              (0xc3)
     */
    uint8_t stub_code[] = {0x55, 0x48, 0x89, 0xe5, 0x5d, 0xc3};
    size_t stub_size = sizeof(stub_code);

    /* The new binary will contain the original code (possibly patched)
     * plus the stub function appended at the end.
     */
    size_t new_size = size + stub_size;
    uint8_t *new_buffer = malloc(new_size);
    if (!new_buffer) {
        perror("malloc new_buffer");
        free(buffer);
        return 1;
    }
    
    /* Set up the disassembler info so we can process instructions. */
    size_t pc = 0;      /* offset into the input buffer */
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
    disasm_info.buffer_vma = 0;
    disasm_info.buffer_length = size;
    disassemble_init_for_target(&disasm_info);
    
    disassembler_ftype disasm;
    disasm = disassembler(bfd_arch_i386, false, bfd_mach_x86_64, NULL);
    
    /* Process the binary instruction by instruction. */
    while (pc < size) {
        size_t insn_size = disasm(pc, &disasm_info);
        if (insn_size == 0) {
            /* If disassembly fails, copy the rest of the bytes as is and break. */
            while (pc < size) {
                new_buffer[out_pc++] = buffer[pc++];
            }
            break;
        }
        
        /* Check if this instruction is a direct call (opcode 0xE8) and has a length of at least 5. */
        if (buffer[pc] == 0xE8 && insn_size >= 5) {
            /* Compute new relative offset so that the call goes to our stub.
             * The call instruction computes its target relative to (pc + insn_size).
             * Our stub is appended at offset "size" of the new binary.
             */
            int32_t new_offset = (int32_t)(size - (pc + insn_size));
            new_buffer[out_pc++] = 0xE8;
            new_buffer[out_pc++] = (uint8_t)(new_offset & 0xFF);
            new_buffer[out_pc++] = (uint8_t)((new_offset >> 8) & 0xFF);
            new_buffer[out_pc++] = (uint8_t)((new_offset >> 16) & 0xFF);
            new_buffer[out_pc++] = (uint8_t)((new_offset >> 24) & 0xFF);
        } else {
            /* For all other instructions, copy the bytes unchanged. */
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
    
    /* Write out the new binary. */
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
    
    void (*fptr)() = (void (*)()) pointer;
    
    struct timespec start, end;
    if (clock_gettime(CLOCK_REALTIME, &start) != 0) {
        perror("clock_gettime start");
        munmap(pointer, size);
        return 1;
    }
    
    for (int i = 0; i < num_runs; i++) {
        fptr();
    }
    
    if (clock_gettime(CLOCK_REALTIME, &end) != 0) {
        perror("clock_gettime end");
        munmap(pointer, size);
        return 1;
    }
    
    long long start_ns = start.tv_sec * 1000000000LL + start.tv_nsec;
    long long end_ns = end.tv_sec * 1000000000LL + end.tv_nsec;
    long long elapsed_ns = end_ns - start_ns;
    double average_ns = (double) elapsed_ns / num_runs;
    
    printf("Executed patched binary %d times\n", num_runs);
    printf("Total elapsed time: %lld ns\n", elapsed_ns);
    printf("Average time per execution: %.2f ns\n", average_ns);
    
    munmap(pointer, size);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <input_binary> <num_runs>\n", argv[0]);
        return 1;
    }
    
    const char *input_file = argv[1];
    int num_runs = atoi(argv[2]);
    if (num_runs <= 0) {
        fprintf(stderr, "Number of runs must be positive.\n");
        return 1;
    }
    
    const char *patched_file = "bpf-binary-patched.o";
    
    /* Patch the input binary. */
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
