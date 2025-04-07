/* 
    Program to automatically run and hook bpf programs to a provided hookpoint

*/
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>

// static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
// {
//     return vfprintf(stderr, format, args);
// }

/**
@param <tracepoint category> <tracepoint> <bpf file name>
*/
int main(int argc, char **argv)
{
    char * category = argv[1];
    char * tp = argv[2];
    char * bpf_file_name = argv[3];
    // char * tp = "syscalls/sys_enter_write";
    // char * bpf_file_name = "minimal.bpf.o";

    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link = NULL;
    struct bpf_map *map;

    /* Set up libbpf errors and debug info callback */
    // libbpf_set_print(libbpf_print_fn);

    /* Open BPF application */
    // obj = bpf_object__open(bpf_name);
    obj = bpf_object__open(bpf_file_name);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: opening BPF object file failed\n");
        return 0;
    }

    /* find bpf program in object file */
    prog = bpf_object__find_program_by_name(obj, "bpf_prog1");
    if (!prog) {
        fprintf(stderr, "ERROR: finding a prog in obj file failed\n");
        goto cleanup;
    }

    /* Load & verify BPF programs */
    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load and verify BPF object\n");
        goto cleanup;
    }

    /* Pin the object*/
    bpf_object__pin_programs(obj, "/sys/fs/bpf/prog");

    /* Attach tracepoint handler */
    link = bpf_program__attach_tracepoint(prog, category, tp);
    // link = bpf_program__attach_raw_tracepoint(prog, tp);
    if (libbpf_get_error(link)) {
        fprintf(stderr, "ERROR: bpf_program__attach_tracepoint failed\n");
        link = NULL;
        goto cleanup;
    }

    /* Pin the link */
    bpf_link__pin(link, "/sys/fs/bpf/link");

    /* find map if there is any in the bpf object*/
    map = bpf_object__find_map_by_name(obj, "my_map");

    if (map) {
        /* Pin the map */
        bpf_map__pin(map, "/sys/fs/bpf/map");
        int key = 0;
        int value;
        printf("-----------------------\n");
        printf("Reading data from a Map in kernel space...\n");
        // while (1) {
        //     // Write value into map
        //     // bpf_map_update_elem(bpf_map__fd(prog->maps.my_map), &key, &value, BPF_ANY);
        //     bpf_map__lookup_elem(map, &key, sizeof(key), &value, sizeof(value), 0);
        //     // printf("Value read from map: %d\n", value);
        //     // sleep(0.1);
        // }
    }
    else {

        printf("No map found in bpf program proceeding without it...\n");

    }
    /* ----------------------- */

    printf("Successfully started!\n");

    // printf("Successfully started! Please run `cat /sys/kernel/debug/tracing/trace_pipe` "
    //        "to see output of the BPF programs.\n");

cleanup:
    // bpf_link__destroy(link);
    // bpf_object__close(obj);
    // bpf_object__unpin_programs(obj, "/sys/fs/bpf/prog");
    return 0;
}