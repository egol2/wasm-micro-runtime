#define _GNU_SOURCE /* asprintf, vasprintf */

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <dis-asm.h>

static const char BPF_FILE[] = "non-inlined-bpf-array.o";

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

int fileSize(int fd) {
    struct stat s;
    if (fstat(fd, &s) == -1) {
        return -1;
    }
    return s.st_size;
}

/*
 * This modified main() reads a flat binary file, uses the disassembler
 * to iterate over instructions, and for each direct call (opcode 0xE8)
 * it computes a new relative offset so that the call instead goes to our stub.
 * The stub function’s machine code is appended to the end of the new binary.
 */
int main(int argc, char const *argv[]) {
    int fd = open(BPF_FILE, O_RDONLY);
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
    
    /* Set up the disassembler info so we can step through instructions. */
    size_t pc = 0;      /* offset into the input buffer */
    size_t out_pc = 0;  /* offset into the new (output) buffer */
    
    stream_state ss = {0};
    disassemble_info disasm_info = {0};
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
        
        /* Check if this instruction is a direct call.
         * (Direct calls use opcode 0xE8 and are 5 bytes long.)
         */
        if (buffer[pc] == 0xE8 && insn_size >= 5) {
            /* Compute new relative offset so that the call goes to our stub.
             * Our stub will be appended at offset "size" in the new binary.
             * The call instruction computes its target relative to (pc + insn_size).
             */
            int32_t new_offset = (int32_t)((size) - (pc + insn_size));
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
    
    /* Append the stub function code to the end of the new binary. */
    memcpy(new_buffer + out_pc, stub_code, stub_size);
    out_pc += stub_size;
    
    /* Write out the new binary (with .o extension). */
    int out_fd = open("bpf-binary-patched.o", O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (out_fd < 0) {
        perror("open output file");
        free(buffer);
        free(new_buffer);
        return 1;
    }
    if (write(out_fd, new_buffer, out_pc) != out_pc) {
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
