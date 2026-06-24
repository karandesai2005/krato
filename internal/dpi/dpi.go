package dpi

//go:generate sh -c "clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I../../ebpf -c ../../ebpf/dpi.c -o dpi_bpf.o"

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type DPIEvent struct {
	PID        uint32
	UID        uint32
	Timestamp  uint64
	PayloadLen uint32
	Comm       [16]byte
	Payload    [512]byte
}

type AlertCallback func(pid uint32, comm string, payload string)

func Monitor(onAlert AlertCallback) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("failed to remove memlock: %w", err)
	}

	objPath, err := locateObjectFile()
	if err != nil {
		return err
	}

	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return fmt.Errorf("failed to load eBPF object %s: %w", objPath, err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("failed to create collection: %w", err)
	}
	defer coll.Close()

	kp, err := link.Kprobe("tcp_sendmsg", coll.Programs["kprobe_tcp_sendmsg"], nil)
	if err != nil {
		return fmt.Errorf("failed to attach kprobe to tcp_sendmsg: %w", err)
	}
	defer kp.Close()

	log.Println("✅ DPI kprobe attached to tcp_sendmsg")

	rd, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		return fmt.Errorf("failed to open ringbuf: %w", err)
	}
	defer rd.Close()

	log.Println("👁️  DPI watching outbound TCP for GitHub PATs (ghp_*)...")

	for {
		record, err := rd.Read()
		if err != nil {
			if os.IsNotExist(err) {
				break
			}
			continue
		}

		var event DPIEvent
		if err := binary.Read(
			bytes.NewReader(record.RawSample),
			binary.LittleEndian,
			&event,
		); err != nil {
			continue
		}

		if event.PayloadLen == 0 || event.PayloadLen > uint32(len(event.Payload)) {
			continue
		}

		comm := nullTerminated(event.Comm[:])
		payload := string(event.Payload[:event.PayloadLen])
		onAlert(event.PID, comm, payload)
	}

	return nil
}

func locateObjectFile() (string, error) {
	candidates := []string{
		"internal/dpi/dpi_bpf.o",
		filepath.Join("internal", "dpi", "dpi_bpf.o"),
	}

	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(exeDir, "internal", "dpi", "dpi_bpf.o"),
			filepath.Join(exeDir, "dpi_bpf.o"),
		)
	}

	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			abs, err := filepath.Abs(path)
			if err != nil {
				return path, nil
			}
			return abs, nil
		}
	}

	return "", fmt.Errorf("dpi_bpf.o not found — run: go generate ./internal/dpi")
}

func nullTerminated(b []byte) string {
	n := bytes.IndexByte(b, 0)
	if n == -1 {
		return string(b)
	}
	return string(b[:n])
}