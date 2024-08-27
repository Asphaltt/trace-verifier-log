#include "bpf_all.h"

struct vlog_cache {
    char fmt[1024+6];
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct vlog_cache);
    __uint(max_entries, 1);
} vlog_cache SEC(".maps");

static __always_inline struct vlog_cache *
__get_vlog_cache(void)
{
    __u32 key = 0;
    return bpf_map_lookup_elem(&vlog_cache, &key);
}

#define NR_REG_ARGUMENTS 6
#define NR_ARM64_MAX_REG_ARGUMENTS 31

static __inline unsigned long
regs_get_kernel_stack_nth_addr(struct pt_regs *regs, unsigned int n)
{
    unsigned long *addr = (unsigned long *)regs->sp, retval = 0;

    addr += n;
    return 0 != bpf_probe_read_kernel(&retval, sizeof(retval), addr) ? 0 : retval;
}

static __inline unsigned long
regs_get_nth_argument(struct pt_regs *regs, unsigned int n)
{
    switch (n) {
    case 0:
        return PT_REGS_PARM1_CORE(regs);
    case 1:
        return PT_REGS_PARM2_CORE(regs);
    case 2:
        return PT_REGS_PARM3_CORE(regs);
    case 3:
        return PT_REGS_PARM4_CORE(regs);
    case 4:
        return PT_REGS_PARM5_CORE(regs);
    case 5:
        return PT_REGS_PARM6_CORE(regs);
    default:
#if defined(__TARGET_ARCH_arm64)
        if (n < NR_ARM64_MAX_REG_ARGUMENTS)
            return regs->regs[n];
        else
            return 0;
#elif defined(__TARGET_ARCH_x86)
        n -= NR_REG_ARGUMENTS - 1;
        return regs_get_kernel_stack_nth_addr(regs, n);
#else
        return 0;
#endif
    }
}

static __always_inline void
__vlog(struct pt_regs *ctx)
{
    __u64 args[9];
    const char *arg2 = (const char *) PT_REGS_PARM2(ctx);

    for (int i = 0; i < 9; i++)
        args[i] = regs_get_nth_argument(ctx, i + 2);

    struct vlog_cache *cache = __get_vlog_cache();
    if (!cache)
        return;

    // bpf_probe_read_kernel_str(&cache->fmt[6], 1024, arg2);
    int n = bpf_probe_read_kernel_str(&cache->fmt[6], 1024, arg2);
    if (n < 0)
        return;

    cache->fmt[0] = 'V';
    cache->fmt[1] = 'L';
    cache->fmt[2] = 'O';
    cache->fmt[3] = 'G';
    cache->fmt[4] = ':';
    n &= 1024 - 1;
    cache->fmt[5] = cache->fmt[6+n-2] == '\n' ? '1' : '0';
    // bpf_printk("end: %02x %02x %02x\n", cache->fmt[6+n-2], cache->fmt[6+n-1], cache->fmt[6+n]);
    bpf_trace_vprintk((const char *) &cache->fmt, 1030, &args, 9*8);
}

SEC("kprobe")
int k_vlog(struct pt_regs *ctx)
{
    __vlog(ctx);

    return BPF_OK;
}