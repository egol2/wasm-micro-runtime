// binary_rewriter.c – single tool that can patch & benchmark WASM, C or eBPF
// blobs.
// -----------------------------------------------------------------------------
// Build:
//      gcc -O2 -Wall -Wextra -o binary_rewriter binary_rewriter.c -lbfd
//      -lopcodes
// Usage:
//      ./binary_rewriter <mode> <input_file> <num_runs>
//          <mode> ∈ { wasm | c | ebpf }
// -----------------------------------------------------------------------------
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
#include <sys/mman.h>
#include <time.h>
#include <dis-asm.h>
#include <elf.h>

// ----------------------------------------------------------------------------
// Shared helpers
// ----------------------------------------------------------------------------

typedef uint32_t __u32;
static __u32 ar[256] = { 0 }; // buffer returned by the stub in every mode

static bool g_insn_hexdump = false;

// for wasm starting function
#define HOTPATCH_SKIP 0x10

static unsigned long long
rdtscl(void)
{
    unsigned int lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((unsigned long long)lo) | (((unsigned long long)hi) << 32);
}

typedef struct {
    char *insn_buffer;
    bool reenter;
} stream_state;

static int
dis_fprintf(void *s, const char *f, ...)
{
    (void)s;
    (void)f;
    return 0;
}
static int
dis_fprintf_styled(void *s, enum disassembler_style st, const char *f, ...)
{
    (void)s;
    (void)st;
    (void)f;
    return 0;
}
static int
file_size(int fd)
{
    struct stat st;
    return fstat(fd, &st) == -1 ? -1 : (int)st.st_size;
}

/* Stub = movabs rax,&ar ; ret */
static void
build_stub(uint8_t out[11])
{
    uint64_t ptr = (uint64_t)&ar;
    out[0] = 0x48;            // movabs
    out[1] = 0xB8;            // rax
    memcpy(out + 2, &ptr, 8); // address of ar
    out[10] = 0xC3;           // ret
}

//-------------------------------- ELF loader ---------------------------------
/* Loads the .text section of an ELF64 file into memory.
 * On success returns 0 and sets *buf / *len (caller must free).
 */
static int
load_elf_text(const char *path, uint8_t **buf_out, size_t *len_out)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    Elf64_Ehdr eh;
    if (pread(fd, &eh, sizeof eh, 0) != sizeof eh
        || memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "%s: not ELF\n", path);
        close(fd);
        return 1;
    }

    off_t shstr_off = eh.e_shoff + (off_t)eh.e_shstrndx * eh.e_shentsize;
    Elf64_Shdr shstr;
    if (pread(fd, &shstr, sizeof shstr, shstr_off) != sizeof shstr) {
        perror("shstr");
        close(fd);
        return 1;
    }
    char *shstrtab = malloc(shstr.sh_size);
    if (!shstrtab
        || pread(fd, shstrtab, shstr.sh_size, shstr.sh_offset)
               != (ssize_t)shstr.sh_size) {
        perror("shstrtab");
        free(shstrtab);
        close(fd);
        return 1;
    }

    Elf64_Shdr text = { 0 };
    for (uint16_t i = 0; i < eh.e_shnum; ++i) {
        Elf64_Shdr sh;
        off_t ofs = eh.e_shoff + (off_t)i * eh.e_shentsize;
        if (pread(fd, &sh, sizeof sh, ofs) != sizeof sh) {
            perror("shdr");
            free(shstrtab);
            close(fd);
            return 1;
        }
        if (strcmp(shstrtab + sh.sh_name, ".text") == 0) {
            text = sh;
            break;
        }
    }
    free(shstrtab);
    if (text.sh_size == 0) {
        fprintf(stderr, "%s: .text not found\n", path);
        close(fd);
        return 1;
    }

    uint8_t *buf = malloc(text.sh_size);
    if (!buf
        || pread(fd, buf, text.sh_size, text.sh_offset)
               != (ssize_t)text.sh_size) {
        perror("load .text");
        free(buf);
        close(fd);
        return 1;
    }
    close(fd);
    *buf_out = buf;
    *len_out = text.sh_size;
    return 0;
}

/* Initialise disassembler state */
static void
init_disassembler(disassemble_info *di, uint8_t *buf, size_t len,
                  stream_state *ss)
{
    memset(di, 0, sizeof *di);
    init_disassemble_info(di, ss, dis_fprintf, dis_fprintf_styled);
    di->arch = bfd_arch_i386;
    di->mach = bfd_mach_x86_64;
    di->read_memory_func = buffer_read_memory;
    di->buffer = buf;
    di->buffer_vma = 0;
    di->buffer_length = len;
    disassemble_init_for_target(di);
}
static disassembler_ftype
pick_disassembler(void)
{
    return disassembler(bfd_arch_i386, false, bfd_mach_x86_64, NULL);
}

// ----------------------------------------------------------------------------
// Mode‑specific patchers
// ----------------------------------------------------------------------------

/* Generic patch driver (receives patch lambda) */
typedef void (*insn_patch_cb)(uint8_t *in, size_t pc, size_t isz, size_t total,
                              uint8_t *out, size_t *outpc);

static int
patch_driver(uint8_t *buf, size_t len, const char *outpath, insn_patch_cb patch)
{
    uint8_t stub[11];
    build_stub(stub);
    uint8_t *outbuf = malloc(len + sizeof stub);

    stream_state ss = { 0 };
    disassemble_info di;
    init_disassembler(&di, buf, len, &ss);
    disassembler_ftype dis = pick_disassembler();

    size_t pc = 0, out = 0;

    if (g_insn_hexdump)
        printf("Original hex:\n");

    while (pc < len) {
        size_t isz = dis(pc, &di);
        if (!isz) {
            outbuf[out++] = buf[pc++];
            continue;
        }
        if (g_insn_hexdump) {
            for (size_t i = 0; i < isz; i++) {
                printf("%02x", buf[pc + i]);
            }
        }
        patch(buf, pc, isz, len, outbuf, &out);
        pc += isz;
    }
    if (g_insn_hexdump)
        printf("\n");
    memcpy(outbuf + out, stub, sizeof stub);
    out += sizeof stub;

    int ofd = open(outpath, O_CREAT | O_TRUNC | O_WRONLY, 0755);
    if (ofd < 0 || write(ofd, outbuf, out) != (ssize_t)out) {
        perror("write");
        free(outbuf);
        return 1;
    }
    close(ofd);
    free(outbuf);
    return 0;
}

/* WASM specific patch callbacks */
static void
patch_wasm_cb(uint8_t *in, size_t pc, size_t isz, size_t total, uint8_t *out,
              size_t *p)
{
    if (in[pc] == 0xE8 && isz >= 5) {
        int32_t rel = (int32_t)(total - (pc + isz));
        out[(*p)++] = 0xE8;
        memcpy(out + *p, &rel, 4);
        *p += 4;
    }
    else {
        memcpy(out + *p, in + pc, isz);
        *p += isz;
    }
}

/* C specific patch callbacks */
static void
patch_c_cb(uint8_t *in, size_t pc, size_t isz, size_t total, uint8_t *out,
           size_t *p)
{
    bool handled = false;
    if (isz >= 7 && in[pc] == 0x48 && in[pc + 1] == 0x8D
        && in[pc + 2] == 0x3D) {
        int32_t disp = (int32_t)((uint64_t)&ar - (uint64_t)(pc + isz));
        out[(*p)++] = 0x48;
        out[(*p)++] = 0x8D;
        out[(*p)++] = 0x3D;
        memcpy(out + *p, &disp, 4);
        *p += 4;
        handled = true;
    }
    if (!handled && in[pc] == 0xE8 && isz >= 5) {
        int32_t rel = (int32_t)(total - (pc + isz));
        out[(*p)++] = 0xE8;
        memcpy(out + *p, &rel, 4);
        *p += 4;
        handled = true;
    }
    if (!handled) {
        memcpy(out + *p, in + pc, isz);
        *p += isz;
    }
}

/* eBPF patch callback */
static void
patch_ebpf_cb(uint8_t *in, size_t pc, size_t isz, size_t total, uint8_t *out,
              size_t *p)
{
    bool handled = false;
    if (in[pc] == 0xE8 && isz >= 5) {
        int32_t rel = (int32_t)(total - (pc + isz));
        out[(*p)++] = 0xE8;
        memcpy(out + *p, &rel, 4);
        *p += 4;
        handled = true;
    }
    else if (isz >= 10 && in[pc] == 0x48 && in[pc + 1] == 0xBF) {
        uint64_t ptr = (uint64_t)&ar;
        out[(*p)++] = 0x48;
        out[(*p)++] = 0xBF;
        memcpy(out + *p, &ptr, 8);
        *p += 8;
        handled = true;
    }
    if (!handled) {
        memcpy(out + *p, in + pc, isz);
        *p += isz;
    }
}

//-------------------------------- Dispatchers --------------------------------
static int
patch_binary_wasm(const char *in, const char *out)
{
    uint8_t *buf;
    size_t len;
    if (load_elf_text(in, &buf, &len) != 0)
        return 1;

    // skip the hot-patch header
    if (len <= HOTPATCH_SKIP) {
        fprintf(stderr, "%s: .text too small for skip\n", in);
        free(buf);
        return 1;
    }
    uint8_t *body = buf + HOTPATCH_SKIP;
    size_t body_len = len - HOTPATCH_SKIP;

    int r = patch_driver(body, body_len, out, patch_wasm_cb);
    free(buf);
    return r;
}
static int
patch_binary_c(const char *in, const char *out)
{
    uint8_t *buf;
    size_t len;
    if (load_elf_text(in, &buf, &len) != 0)
        return 1;
    int r = patch_driver(buf, len, out, patch_c_cb);
    free(buf);
    return r;
}
static int
patch_binary_ebpf(const char *in, const char *out)
{
    int fd = open(in, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 1;
    }
    int len = file_size(fd);
    if (len < 0) {
        perror("size");
        close(fd);
        return 1;
    }
    uint8_t *buf = malloc(len);
    if (!buf || read(fd, buf, len) != len) {
        perror("read");
        free(buf);
        close(fd);
        return 1;
    }
    close(fd);
    int r = patch_driver(buf, len, out, patch_ebpf_cb);
    free(buf);
    return r;
}

// ----------------------------------------------------------------------------
// Timing harness
// ----------------------------------------------------------------------------
static int
run_timing_loop(const char *patched_file, int runs)
{
    int fd = open(patched_file, O_RDONLY);
    if (fd < 0) {
        perror("open patched");
        return 1;
    }
    int len = file_size(fd);
    if (len < 0) {
        perror("size");
        close(fd);
        return 1;
    }
    void *ptr = mmap(NULL, len, PROT_EXEC, MAP_SHARED, fd, 0);
    if (ptr == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return 1;
    }
    close(fd);
    // create function pointer to executable patched binary
    void (*fun)(void *) = (void (*)(void *))ptr;

    // setup array for the argument for the patched binary function
    uint8_t arg[0x40] = { 0 };
    *(uint64_t *)(arg + 0x10) = (uint64_t)ar;
    *(uint64_t *)(arg + 0x30) = (uint64_t)ar;
    *(uint64_t *)(arg + 0x38) = (uint64_t)ar;

    unsigned long long start = rdtscl();

    // Run the function
    for (int i = 0; i < runs; ++i) {
        fun(arg);
    }

    unsigned long long end = rdtscl();

    printf("Executed %d runs – average cycles: %.2f\n", runs,
           (double)(end - start) / runs);
    munmap(ptr, len);
    return 0;
}

static int
patch_dispatch(const char *mode, const char *in, const char *out)
{
    if (strcmp(mode, "wasm") == 0)
        return patch_binary_wasm(in, out);
    if (strcmp(mode, "c") == 0)
        return patch_binary_c(in, out);
    if (strcmp(mode, "ebpf") == 0)
        return patch_binary_ebpf(in, out);
    fprintf(stderr, "Unknown mode '%s' – use wasm|c|ebpf\n", mode);
    return 1;
}

int
main(int argc, char **argv)
{
    bool hexdump = false;
    int argi = 1;
    if (argc == 5 && strcmp(argv[1], "-v") == 0) {
        hexdump = true;
        argi = 2;
    }
    if (argc - argi != 3) {
        fprintf(stderr, "Usage: %s [-v] <wasm|c|ebpf> <input_bin> <num_runs>\n",
                argv[0]);
        return 1;
    }

    g_insn_hexdump = hexdump;

    const char *mode = argv[argi];
    const char *in = argv[argi + 1];
    int runs = atoi(argv[argi + 2]);
    if (runs <= 0) {
        fprintf(stderr, "num_runs must be >0\n");
        return 1;
    }

    const char *out = "patched-binary.o";

    // Patch the binary
    if (patch_dispatch(mode, in, out) != 0)
        return 1;

    // Run the patched binary
    if (run_timing_loop(out, runs) != 0)
        return 1;

    if (hexdump) {
        int pfd = open(out, O_RDONLY);
        if (pfd < 0) {
            perror("open patched for hexdump");
        }
        else {
            int psz = file_size(pfd);
            uint8_t *pbuf = malloc(psz);
            if (!pbuf) {
                fprintf(stderr, "malloc failed for patched hexdump buffer\n");
            }
            else if (read(pfd, pbuf, psz) != psz) {
                perror("hexdump read patched");
                free(pbuf);
            }
            else {
                printf("Patched hex:\n");
                for (int i = 0; i < psz; i++)
                    printf("%02x", pbuf[i]);
                printf("\n");
                free(pbuf);
            }
            close(pfd);
        }
    }

    return 0;
}