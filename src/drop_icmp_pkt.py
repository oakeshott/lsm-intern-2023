#!/usr/bin/python3
# -*- coding: utf-8 -*-


from bcc import BPF
from bcc import lib
import sys
import time
import json
from socket import inet_ntop, ntohs, AF_INET, AF_INET6
from struct import pack
import ctypes as ct
import joblib
from datetime import datetime

def usage():
    print("Usage: {0} <ifdev> <output-dir> <flag>".format(sys.argv[0]))
    exit(1)

bpf_text = """
#include <uapi/linux/bpf.h>
#include <linux/inet.h>
#include <linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>

BPF_HASH(dropcnt, u32, u32);
int drop_icmp_packet(struct xdp_md *ctx) {
  void* data_end = (void*)(long)ctx->data_end;
  void* data     = (void*)(long)ctx->data;

  struct ethhdr *eth = data;
  u64 nh_off = sizeof(*eth);

  if (data + nh_off > data_end) {
    return XDP_PASS;
  }

  if (eth->h_proto == htons(ETH_P_IP)) {
    struct iphdr *iph = data + nh_off;
    if ((void*)&iph[1] > data_end) {
        return XDP_PASS;
    }
    u32 protocol;
    protocol = iph->protocol;
    if (protocol == 1) {
      u32 value = 0, *vp;
      vp = dropcnt.lookup_or_init(&protocol, &value);
      *vp += 1;
      return XDP_DROP;
    }
  }
  return XDP_PASS;
}

"""

if __name__ == '__main__':
    device = sys.argv[1]
    flags = 0
    offload_device = None
    if len(sys.argv) == 3:
        if "-S" in sys.argv:
            # XDP_FLAGS_SKB_MODE
            flags |= BPF.XDP_FLAGS_SKB_MODE
        if "-D" in sys.argv:
            # XDP_FLAGS_DRV_MODE
            flags |= BPF.XDP_FLAGS_DRV_MODE
        if "-H" in sys.argv:
            # XDP_FLAGS_HW_MODE
            maptype = "array"
            offload_device = device.encode()
            flags |= BPF.XDP_FLAGS_HW_MODE

    ret = []
    b = BPF(text=bpf_text, debug=0,  cflags=["-w"],
            # allow_rlimit=True,
            device=offload_device)
    try:
        fn = b.load_func("drop_icmp_packet", BPF.XDP)
        b.attach_xdp(device, fn, flags=flags)

        dropcnt          = b.get_table("dropcnt")

        while True:
            try:
                dropcnt.clear()
                time.sleep(1)
                for k, v in dropcnt.items():
                    print("{} {}: {} pps".format(time.strftime("%H:%M:%S"), k.value, v.value))
            except KeyboardInterrupt:
                break
    finally:
        b.remove_xdp(device, flags)
