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

static const char BPF_FILE[] = "bpf-binary.o";

typedef struct {
	char *insn_buffer;
	bool reenter;
} stream_state;

/* This approach isn't very memory efficient or clear,
 * but it avoids external size/buffer tracking in this
 * example.
 */
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
//enum disassembler_style style
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

char *disassemble_raw(uint8_t *input_buffer, size_t input_buffer_size) {
	char *disassembled = NULL;
	stream_state ss = {};
// /usr/include/dis-asm.h:482:13
	disassemble_info disasm_info = {};
	init_disassemble_info(&disasm_info, &ss, dis_fprintf, dis_fprintf_styled);
	disasm_info.arch = bfd_arch_i386;
	disasm_info.mach = bfd_mach_x86_64;
	disasm_info.read_memory_func = buffer_read_memory;
	disasm_info.buffer = input_buffer;
	disasm_info.buffer_vma = 0;
	disasm_info.buffer_length = input_buffer_size;
	disassemble_init_for_target(&disasm_info);

	disassembler_ftype disasm;
	disasm = disassembler(bfd_arch_i386, false, bfd_mach_x86_64, NULL);

	size_t pc = 0;
	while (pc < input_buffer_size) {
		size_t insn_size = disasm(pc, &disasm_info);
		pc += insn_size;

		if (disassembled == NULL) {
			asprintf(&disassembled, "%s", ss.insn_buffer);
		} else {
			char *tmp;
			asprintf(&tmp, "%s\n%s", disassembled, ss.insn_buffer);
			free(disassembled);
			disassembled = tmp;
		}

		/* Reset the stream state after each instruction decode.
		*/
		free(ss.insn_buffer);
		ss.reenter = false;
	}
	return disassembled;
}

int fileSize(int fd) {
	struct stat s;
	if (fstat(fd, &s) == -1) {
		return -1;
	}
	return(s.st_size);
}

int main(int argc, char const *argv[]) {
//	uint8_t input_buffer[] = {
//		0x55,             /* push rbp */
//		0x48, 0x89, 0xe5, /* mov rbp, rsp */
//		0x89, 0x7d, 0xfc, /* mov DWORD PTR [rbp-0x4], edi */
//		0x8b, 0x45, 0xfc, /* mov eax, DWORD PTR [rbp-0x4] */
//		0x0f, 0xaf, 0xc0, /* imul eax, rax */
//		0x5d,             /* pop ebp */
//		0xc3,             /* ret */
//	};

	//size_t input_buffer_size = sizeof(input_buffer);
	
	int fd = open(BPF_FILE, O_RDONLY);
	void *pointer = 0;

	int size = fileSize(fd);

	uint8_t *buffer = malloc(size);

	ssize_t bytesRead = read(fd, buffer, size);

	char *disassembled = disassemble_raw(buffer, bytesRead);
	puts(disassembled);
	free(disassembled);
	free(buffer);

	return 0;
}
