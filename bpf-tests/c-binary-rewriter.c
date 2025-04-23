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
#include <elf.h>

// Stream state for capturing disassembler output
typedef struct {
    char *insn_buffer;
    bool reenter;
} stream_state;

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

// Guest array definition
typedef uint32_t __u32;
static __u32 ar[256] = { 0 };

// Custom fprintf for disassembler
static int dis_fprintf(void *stream, const char *fmt, ...) {
    // stream_state *ss = (stream_state *)stream;
    // va_list args;
    // va_start(args, fmt);
    // if (!ss->reenter) {
    //     vasprintf(&ss->insn_buffer, fmt, args);
    //     ss->reenter = true;
    // } else {
    //     char *tmp;
    //     vasprintf(&tmp, fmt, args);
    //     char *tmp2;
    //     asprintf(&tmp2, "%s%s", ss->insn_buffer, tmp);
    //     free(ss->insn_buffer);
    //     free(tmp);
    //     ss->insn_buffer = tmp2;
    // }
    // va_end(args);
    return 0;
}

// Styled fprintf - identical behavior, ignore style parameter
static int dis_fprintf_styled(void *stream, enum disassembler_style style,
    const char *fmt, ...) {
    // (void)style;
    // stream_state *ss = (stream_state *)stream;
    // va_list args;
    // va_start(args, fmt);
    // if (!ss->reenter) {
    //     vasprintf(&ss->insn_buffer, fmt, args);
    //     ss->reenter = true;
    // } else {
    //     char *tmp;
    //     vasprintf(&tmp, fmt, args);
    //     char *tmp2;
    //     asprintf(&tmp2, "%s%s", ss->insn_buffer, tmp);
    //     free(ss->insn_buffer);
    //     free(tmp);
    //     ss->insn_buffer = tmp2;
    // }
    // va_end(args);
    return 0;
}

// Get file size (used in run_timing_loop)
int fileSize(int fd) {
    struct stat s;
    if (fstat(fd, &s) == -1)
        return -1;
    return (int)s.st_size;
}

// Patch the input ELF: extract .text, fix calls & lea, append stub
int patch_binary(const char *input_file, const char *output_file) {
    int fd = open(input_file, O_RDONLY);
    if (fd < 0) { perror("open input file"); return 1; }

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

    // Locate .text section
    off_t text_off = 0;
    size_t text_size = 0;
    for (int i = 0; i < shnum; i++) {
        Elf64_Shdr sh;
        if (lseek(fd, shoff + (off_t)i * shentsz, SEEK_SET) < 0 ||
            read(fd, &sh, sizeof(sh)) != sizeof(sh)) {
            perror("read section header"); free(shstrtab); close(fd); return 1;
        }
        const char *name = shstrtab + sh.sh_name;
        if (strcmp(name, ".text") == 0) {
            text_off  = sh.sh_offset;
            text_size = sh.sh_size;
            break;
        }
    }
    free(shstrtab);

    if (text_size == 0) {
        fprintf(stderr, ".text section not found\n");
        close(fd);
        return 1;
    }

    // Read .text section
    uint8_t *buffer = malloc(text_size);
    if (!buffer) { perror("malloc text buffer"); close(fd); return 1; }
    if (lseek(fd, text_off, SEEK_SET) < 0 ||
        read(fd, buffer, text_size) != (ssize_t)text_size) {
        perror("read .text"); free(buffer); close(fd); return 1;
    }
    close(fd);

    // Build stub: movabs rax, &ar; ret
    uint8_t stub_code[11] = { 0x48, 0xB8, 0,0,0,0,0,0,0,0, 0xC3 };
    uint64_t ar_addr = (uint64_t)&ar;
    memcpy(stub_code + 2, &ar_addr, sizeof(ar_addr));
    size_t stub_size = sizeof(stub_code);

    // Prepare output buffer
    size_t func_size = text_size;
    size_t new_size  = func_size + stub_size;
    uint8_t *new_buffer = malloc(new_size);
    if (!new_buffer) { perror("malloc new_buffer"); free(buffer); return 1; }

    // Initialize disassembler
    stream_state ss = { .insn_buffer = NULL, .reenter = false };
    disassemble_info di;
    memset(&di, 0, sizeof(di));
    init_disassemble_info(&di, &ss, dis_fprintf, dis_fprintf_styled);
    di.arch             = bfd_arch_i386;
    di.mach             = bfd_mach_x86_64;
    di.read_memory_func = buffer_read_memory;
    di.buffer           = buffer;
    di.buffer_vma       = 0;
    di.buffer_length    = func_size;
    disassemble_init_for_target(&di);
    disassembler_ftype disasm = disassembler(bfd_arch_i386, false, bfd_mach_x86_64, NULL);

    // Patch instructions
    size_t pc = 0, out_pc = 0;
    while (pc < func_size) {
        size_t insn_sz = disasm(pc, &di);
        if (insn_sz == 0) {
            while (pc < func_size)
                new_buffer[out_pc++] = buffer[pc++];
            break;
        }
        // RIP-relative LEA: 48 8D 3D disp32
        if (insn_sz >= 7 &&
            buffer[pc]   == 0x48 &&
            buffer[pc+1] == 0x8D &&
            buffer[pc+2] == 0x3D) {
            int32_t disp = (int32_t)((uint64_t)&ar - (uint64_t)(pc + insn_sz));
            new_buffer[out_pc++] = 0x48;
            new_buffer[out_pc++] = 0x8D;
            new_buffer[out_pc++] = 0x3D;
            memcpy(new_buffer + out_pc, &disp, sizeof(disp));
            out_pc += sizeof(disp);
        }
        // Direct CALL: E8 disp32
        else if (buffer[pc] == 0xE8 && insn_sz >= 5) {
            int32_t off = (int32_t)(func_size - (pc + insn_sz));
            new_buffer[out_pc++] = 0xE8;
            memcpy(new_buffer + out_pc, &off, sizeof(off));
            out_pc += sizeof(off);
        } else {
            memcpy(new_buffer + out_pc, buffer + pc, insn_sz);
            out_pc += insn_sz;
        }
        pc += insn_sz;
        if (ss.insn_buffer) {
            free(ss.insn_buffer);
            ss.insn_buffer = NULL;
            ss.reenter = false;
        }
    }

    // Append stub
    memcpy(new_buffer + out_pc, stub_code, stub_size);
    out_pc += stub_size;

    printf("Patched binary bytes:\n");
    for (size_t i = 0; i < out_pc; i++) {
        printf("0x%02X ", new_buffer[i]);
        if ((i + 1) % 16 == 0)
            printf("\n");
    }
    printf("\n");

    // Write patched binary
    int out_fd = open(output_file, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (out_fd < 0) { perror("open output file"); free(buffer); free(new_buffer); return 1; }
    if (write(out_fd, new_buffer, out_pc) != (ssize_t)out_pc) {
        perror("write output file"); free(buffer); free(new_buffer); close(out_fd); return 1;
    }
    close(out_fd);
    free(buffer);
    free(new_buffer);
    return 0;
}

// Run timing loop on patched binary
typedef long long ll;
int run_timing_loop(const char *patched_file, int num_runs) {
    int fd = open(patched_file, O_RDONLY);
    if (fd < 0) { perror("open patched binary"); return 1; }
    int size = fileSize(fd);
    if (size < 0) { perror("fileSize"); close(fd); return 1; }
    void *ptr = mmap(NULL, size, PROT_EXEC, MAP_SHARED, fd, 0);
    if (ptr == MAP_FAILED) { perror("mmap"); close(fd); return 1; }
    close(fd);

    void (*f)(void *) = (void (*)(void *))ptr;
    uint8_t arg[0x40] = {0};
    *(uint64_t*)(arg+0x10) = (uint64_t)ar;
    *(uint64_t*)(arg+0x30) = (uint64_t)ar;
    *(uint64_t*)(arg+0x38) = (uint64_t)ar;

    // ll start_ns, end_ns;
    // struct timespec s, e;
    // clock_gettime(CLOCK_REALTIME, &s);
    // for (int i = 0; i < num_runs; i++) {
    //     f(arg);
    // }
    // pthread_t tid;
    unsigned long long start, end = 0;
    unsigned long long elapsed = 0;

    // init
    start = rdtscl();

    for (int i = 0; i < num_runs; i++) {
        // Call the executable function, passing our argument buffer.
        f(arg);
    }

    end = rdtscl();
    elapsed += end - start;

    double average_cycle_count = (double) elapsed/num_runs;
    printf("EBPF execution time:\n");
    printf("Executed %d time(s), Average cycles: %f\n",
        num_runs, average_cycle_count);
    // clock_gettime(CLOCK_REALTIME, &e);
    // start_ns = s.tv_sec * 1000000000LL + s.tv_nsec;
    // end_ns   = e.tv_sec * 1000000000LL + e.tv_nsec;
    // ll total = end_ns - start_ns;
    // printf("C execution: %d runs, %lld ns total, %.2f ns avg\n", num_runs, total, (double)total/num_runs);
    munmap(ptr, size);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <input_elf> <num_runs>\n", argv[0]);
        return 1;
    }
    const char *infile = argv[1];
    int runs = atoi(argv[2]);
    if (runs <= 0) {
        fprintf(stderr, "Runs>0 required\n");
        return 1;
    }
    const char *out = "bpf-binary-patched.o";
    if (patch_binary(infile, out) != 0) {
        return 1;
    }
    if (run_timing_loop(out, runs) != 0) {
        return 1;
    }
    return 0;
}
