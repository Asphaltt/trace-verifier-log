<!--
 Copyright 2024 Leon Hwang.
 SPDX-License-Identifier: Apache-2.0
-->

# trace-verifier-log

`trace-verifier-log` is a tool to trace bpf verifier log based on [bpf_trace_vprintk()](https://github.com/torvalds/linux/commit/10aceb629e198429c849d5e995c3bb1ba7a9aaa3) helper, which requires Linux kernel **5.16** or later.

## Usage

```bash
$ sudo ./trace-verifier-log
2024/08/28 12:18:25 Attached kprobe(bpf_log)
2024/08/28 12:18:25 Attached kprobe(bpf_verifier_log_write)
```

## Use case

It's really useful to show the verifier log when fail to attach freplace program.

```bash
$ sudo ./freplace --freplace-failed
2024/08/28 12:13:13 Failed to freplace(stub_handler_static): create link: invalid argument

$ sudo ./trace-verifier-log
2024/08/28 12:12:54 Attached kprobe(bpf_log)
2024/08/28 12:12:54 Attached kprobe(bpf_verifier_log_write)
stub_handler_static() is not a global function
```

It's really annoying no error message when fail to attach freplace program, but now you can see the error message with `trace-verifier-log`.

## License

`trace-verifier-log` is licensed under the Apache License, Version 2.0. See [LICENSE](./LICENSE) for the full license text.
