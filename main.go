// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/iovisor/gobpf/pkg/tracepipe"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang vlog ./bpf/vlog.c -- -I./bpf/headers -Wall -D__TARGET_ARCH_x86

func main() {
	err := rlimit.RemoveMemlock()
	if err != nil {
		log.Fatalf("Failed to remove memlock rlimit: %v", err)
	}

	var obj vlogObjects
	err = loadVlogObjects(&obj, nil)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Printf("Verifier errors: %+v", ve)
		}
		log.Fatalf("Failed to load bpf obj: %v", err)
	}

	hooks := []string{
		"verbose",
		"bpf_log",
		"bpf_verifier_log_write",
	}

	for _, hook := range hooks {
		kp, err := link.Kprobe(hook, obj.K_vlog, nil)
		if err != nil {
			if errors.Is(err, unix.ENOENT) || errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.EADDRNOTAVAIL) {
				continue
			}
			log.Fatalf("Failed to attach kprobe(%s): %v", hook, err)
		}

		log.Printf("Attached kprobe(%s)", hook)
		defer kp.Close()
	}

	ctx, stop := signal.NotifyContext(context.Background(), unix.SIGINT, unix.SIGTERM)
	defer stop()
	errg, ctx := errgroup.WithContext(ctx)

	pipe, err := tracepipe.New()
	if err != nil {
		log.Fatalf("Failed to create tracepipe: %v", err)
	}

	errg.Go(func() error {
		<-ctx.Done()
		_ = pipe.Close()
		return nil
	})

	errg.Go(func() error {
		return run(ctx, pipe)
	})

	if err := errg.Wait(); err != nil {
		log.Fatalf("Error: %v", err)
	}
}

func run(ctx context.Context, pipe *tracepipe.TracePipe) error {
	type TracePipe struct {
		file   *os.File
		reader *bufio.Reader
	}

	tp := (*TracePipe)(unsafe.Pointer(pipe))

	var buf bytes.Buffer

	for {
		line, err := tp.reader.ReadString('\n')

		select {
		case <-ctx.Done():
			return nil
		default:
		}

		if err != nil {
			return fmt.Errorf("failed to read line: %w", err)
		}

		if line == "" {
			continue
		}

		_, b, ok := strings.Cut(line, "bpf_trace_printk: VLOG:")
		if ok {
			x, b := b[0], b[1:len(b)-1]
			buf.WriteString(b)
			if x == '1' { // ends with '\n'
				fmt.Println(buf.String())
				buf.Reset()
			}
		}
	}
}
