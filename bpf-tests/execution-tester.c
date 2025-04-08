#define _GNU_SOURCE
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

int fileSize(int fd) {
    struct stat s;
    if (fstat(fd, &s) == -1) {
        return -1;
    }
    return s.st_size;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <patched_binary> <num_runs>\n", argv[0]);
        return 1;
    }
    
    const char *binary_file = argv[1];
    int num_runs = atoi(argv[2]);
    if (num_runs <= 0) {
        fprintf(stderr, "Number of runs must be positive.\n");
        return 1;
    }
    
    // Open the binary file
    int fd = open(binary_file, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 1;
    }
    
    int size = fileSize(fd);
    if (size < 0) {
        perror("fileSize");
        close(fd);
        return 1;
    }
    
    // Memory map the binary with PROT_EXEC (and PROT_READ)
    void *pointer = mmap(NULL, size, PROT_EXEC, MAP_SHARED, fd, 0);
    if (pointer == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return 1;
    }
    close(fd);
    
    // Create a function pointer to the entry point of the binary.
    void (*fptr)() = (void (*)()) pointer;
    
    // start time
    struct timespec start, end;
    if (clock_gettime(CLOCK_REALTIME, &start) != 0) {
        perror("clock_gettime start");
        munmap(pointer, size);
        return 1;
    }
    
    // run binary
    for (int i = 0; i < num_runs; i++) {
        fptr();
    }
    
    // Get ending time.
    if (clock_gettime(CLOCK_REALTIME, &end) != 0) {
        perror("clock_gettime end");
        munmap(pointer, size);
        return 1;
    }
    
    // Compute total elapsed time in nanoseconds.
    long long start_ns = start.tv_sec * 1000000000LL + start.tv_nsec;
    long long end_ns = end.tv_sec * 1000000000LL + end.tv_nsec;
    long long elapsed_ns = end_ns - start_ns;
    double average_ns = (double) elapsed_ns / num_runs;
    
    printf("Executed binary %d times\n", num_runs);
    printf("Total elapsed time: %lld ns\n", elapsed_ns);
    printf("Average time per execution: %.2f ns\n", average_ns);
    
    munmap(pointer, size);
    return 0;
}
