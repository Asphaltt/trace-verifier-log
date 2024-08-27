#ifndef __BPF_ALL_H_
#define __BPF_ALL_H_

#include "vmlinux.h"

#include "bpf/bpf_tracing_net.h"
#include "bpf/bpf_iter.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_endian.h"
#include "bpf/bpf_core_read.h"
#include "bpf/bpf_compiler.h"
#include "bpf/bpf_tc.h"
#include "bpf/bpf_tracing.h"
#include "bpf/bpf_map_helpers.h"
#include "bpf/bpf_csum.h"

#define ctx_ptr(ctx, mem) ((void *)(unsigned long)ctx->mem)

char _license[] SEC("license") = "GPL";


#endif // __BPF_ALL_H_