#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_PAYLOAD_SIZE 512

/* From enum iter_type in kernel BTF (6.18) */
#define ITER_UBUF    0
#define ITER_IOVEC   1

struct dpi_event {
	__u32 pid;
	__u32 uid;
	__u64 timestamp;
	__u32 payload_len;
	char comm[16];
	char payload[MAX_PAYLOAD_SIZE];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

static __always_inline int contains_ghp_prefix(const char *buf, __u32 len)
{
	if (len < 4)
		return 0;

	__u32 scan_len = len;
	if (scan_len > MAX_PAYLOAD_SIZE - 4)
		scan_len = MAX_PAYLOAD_SIZE - 4;

#pragma unroll
	for (int i = 0; i < MAX_PAYLOAD_SIZE - 4; i++) {
		if ((__u32)i >= scan_len)
			break;
		if (buf[i] == 'g' && buf[i + 1] == 'h' &&
		    buf[i + 2] == 'p' && buf[i + 3] == '_') {
			return 1;
		}
	}
	return 0;
}

static __always_inline long read_memory(void *dst, __u32 len, const void *src)
{
	long ret;

	ret = bpf_probe_read_user(dst, len, src);
	if (ret < 0)
		ret = bpf_probe_read_kernel(dst, len, src);
	return ret;
}

static __always_inline int read_iter_payload(struct msghdr *msg, void *dst,
					     __u32 max_len, __u32 *out_len)
{
	__u8 iter_type;
	__kernel_size_t count;
	size_t iov_offset;
	const struct iovec *iov_ptr = NULL;
	void *ubuf = NULL;
	struct iovec iov = {};
	void *src = NULL;
	__u32 read_len;

	iter_type = BPF_CORE_READ(msg, msg_iter.iter_type);
	count = BPF_CORE_READ(msg, msg_iter.count);
	if (count == 0)
		return -1;

	iov_offset = BPF_CORE_READ(msg, msg_iter.iov_offset);
	read_len = count > max_len ? max_len : (__u32)count;

	if (iter_type == ITER_IOVEC) {
		iov_ptr = BPF_CORE_READ(msg, msg_iter.__iov);
		if (!iov_ptr)
			return -1;

		if (read_memory(&iov, sizeof(iov), iov_ptr) < 0)
			return -1;
		if (!iov.iov_base)
			return -1;

		src = iov.iov_base + iov_offset;
	} else if (iter_type == ITER_UBUF) {
		ubuf = BPF_CORE_READ(msg, msg_iter.ubuf);
		if (!ubuf)
			return -1;

		src = ubuf + iov_offset;
	} else {
		return -1;
	}

	if (read_memory(dst, read_len, src) < 0)
		return -1;

	*out_len = read_len;
	return 0;
}

SEC("kprobe/tcp_sendmsg")
int kprobe_tcp_sendmsg(struct pt_regs *ctx)
{
	struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);
	struct dpi_event *event;
	__u32 payload_len = 0;

	if (!msg)
		return 0;

	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
		return 0;

	__builtin_memset(event->payload, 0, sizeof(event->payload));
	payload_len = 0;

	if (read_iter_payload(msg, event->payload, MAX_PAYLOAD_SIZE,
			      &payload_len) < 0) {
		bpf_ringbuf_discard(event, 0);
		return 0;
	}

	if (!contains_ghp_prefix(event->payload, payload_len)) {
		bpf_ringbuf_discard(event, 0);
		return 0;
	}

	event->pid = bpf_get_current_pid_tgid() >> 32;
	event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
	event->timestamp = bpf_ktime_get_ns();
	event->payload_len = payload_len;
	bpf_get_current_comm(&event->comm, sizeof(event->comm));

	bpf_ringbuf_submit(event, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";