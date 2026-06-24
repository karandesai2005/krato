package dpi

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

var patRegex = regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`)

// dpiEvent mirrors struct dpi_event in ebpf/dpi.c.
type dpiEvent struct {
	PID        uint32
	UID        uint32
	Timestamp  uint64
	PayloadLen uint32
	Comm       [16]byte
	Payload    [512]byte
}

// Monitor loads the DPI eBPF program, attaches a kprobe to tcp_sendmsg,
// and invokes cb for each ring-buffer event whose payload matches a GitHub PAT.
func Monitor(cb func(pid uint32, comm string, payload string)) error {
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

		var event dpiEvent
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

		payload := string(event.Payload[:event.PayloadLen])
		if !patRegex.MatchString(payload) {
			continue
		}

		comm := nullTerminated(event.Comm[:])
		cb(event.PID, comm, payload)
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

	return "", fmt.Errorf("dpi_bpf.o not found — run: scripts/build-ebpf.sh")
}

func nullTerminated(b []byte) string {
	n := bytes.IndexByte(b, 0)
	if n == -1 {
		return string(b)
	}
	return string(b[:n])
}