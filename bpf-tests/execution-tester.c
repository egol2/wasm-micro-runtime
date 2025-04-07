#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include<sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>

static const char BPF_FILE[] = "non-inlined-bpf-array.o";

int fileSize(int fd) {
	struct stat s;
	if (fstat(fd, &s) == -1) {
		return(-1);
	}
	return(s.st_size);
}

int main(int argc, char *argv[])
{

	int fd = open(BPF_FILE, O_RDONLY);
	void *pointer = 0;

	pointer = mmap(0, fileSize(fd), PROT_EXEC, MAP_SHARED, fd, 0);

	// rewrite/relocate function calls


	void (*fptr)() = (void (*)()) pointer;

	fptr();
	//mprotect();
	

	return 0;
}
