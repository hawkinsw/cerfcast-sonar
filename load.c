#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>

#include "bpf/libbpf.h"
#include "bpf/bpf.h"

int main() {
  struct bpf_object *object = bpf_object__open("bpf/prog.o");
  int loaded = bpf_object__load(object);

  if (loaded < 0) {
    perror("Failed to load the object");
    return 0;
  }

  printf("Here.\n");
  struct bpf_program *program =
      bpf_object__find_program_by_name(object, "handle_packet_rx");
  if (!program) {
    bpf_object__close(object);
    perror("Failed to load the object");
    return 0;
  }

  int map_fd = bpf_object__find_map_fd_by_name(object, "pid_map");
  struct bpf_link *link = bpf_program__attach(program);

  if (!link) {
    bpf_object__close(object);
    perror("Failed to link the object");
    return 0;
  }

  sleep(5);

  if (map_fd) {
    uint32_t key = 0;
    uint64_t result = 0;
    if (bpf_map_lookup_elem(map_fd, &key, &result)< 0) {
      perror("Failed to look up the element");
    }
  	printf("result: %lu\n", result);
  }

  bpf_object__close(object);
  return 0;
}
#if 0
int reset_error_detector(struct error_detector_status *status) {
  if (status->map) {
    uint32_t key = 0;
    uint64_t reset_value = 0;
    if (bpf_map_update_elem(status->map, &key, &reset_value, 0)< 0) {
      perror("Failed to reset the error element");
      return -1;
    } 
  }
  return 0;
}

#endif
