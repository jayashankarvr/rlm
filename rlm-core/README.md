# rlmctl-core

The library behind [rlm](https://crates.io/crates/rlmctl): cgroup v2 limit management under systemd user delegation, and the engine of `rlm-guard`, which freezes or caps a runaway app under memory pressure instead of letting the OOM killer act.

This crate is an internal part of rlm and its API may change between minor versions. To use rlm, install the command-line tool:

```
cargo install rlmctl
```

Documentation, safety notes and the guard FAQ: https://github.com/jayashankarvr/rlm

License: Apache-2.0
