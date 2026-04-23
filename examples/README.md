# Examples

This directory mirrors the example-oriented layout used by the other Palisade
components.

- `basic_defaults.rs` walks through default policy hardening and a simple event
  sequence
- `policy_reload.rs` demonstrates production-safe policy reloads
- `runtime_hot_paths.rs` shows fixed-buffer readback on the public API
- `timing_profile.rs` contrasts intrinsic execution with an explicit timing floor
- `encrypted_logging.rs` demonstrates delegated encrypted audit persistence
  (`--features log`)

Run an example with:

```bash
cargo run --example basic_defaults
```

Run the logging example with:

```bash
cargo run --example encrypted_logging --features log
```
