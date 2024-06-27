#include "vmlinux.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_tracing.h"
#include "bpf/bpf_core_read.h"

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, u32);
  __type(value, long unsigned int);
  __uint(max_entries, 2);
} pid_map SEC(".maps");

SEC("tracepoint/net/netif_receive_skb")
int handle_packet_rx(u64 *ctx) {
  u32 hkey = 0;
  long unsigned int zero = 0;
  long unsigned int *pm = bpf_map_lookup_elem(&pid_map, &hkey);

  if (!pm) {
    bpf_map_update_elem(&pid_map, &hkey, &zero, BPF_NOEXIST);
    pm = bpf_map_lookup_elem(&pid_map, &hkey);
    if (!pm)
      return -1;
  }

  if (pm) {
    *pm += 1;
  }
  return 0;
}

char LICENSE[] SEC("license") = "GPL";
