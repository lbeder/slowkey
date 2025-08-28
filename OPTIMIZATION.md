# Performance & Efficiency Guide for Running Slowkey

This guide organizes our field notes into a practical, reproducible checklist for getting both maximum performance and high efficiency when running Slowkey. Terminology is kept consistent throughout.

## Table of Contents

- [Operating System Choice](#operating-system-choice)
  - [Recommendation](#recommendation)
- [Linux Distributions & Kernel](#linux-distributions--kernel)
  - [Recommendations](#recommendations)
- [CPU Architecture & Library Backends](#cpu-architecture--library-backends)
  - [Recommendations](#recommendations-1)
- [Speed vs. Efficiency (single instance vs. many)](#speed-vs-efficiency-single-instance-vs-many)
- [Monitoring & Useful Tools](#monitoring--useful-tools)
  - [Setup](#setup)
  - [Live monitoring](#live-monitoring)
  - [Notes](#notes)
- [Hardware: Desktop vs. Laptop](#hardware-desktop-vs-laptop)
- [What Actually Drives Performance](#what-actually-drives-performance)
- [Stability, Integrity & Verification](#stability-integrity--verification)
  - [Best practices](#best-practices)
- [Quick Checklist (TL;DR)](#quick-checklist-tldr)
- [Reproducible Benchmark Template](#reproducible-benchmark-template)
  - [Using the `bench` Command](#using-the-bench-command)
  - [Using the Stability-test or Derive Command](#using-the-stability-test-or-derive-command)

## Operating System Choice

Bottom line: Linux consistently outperforms Windows for this workload—sometimes by a small margin, sometimes by a very large one.

In our tests, the Linux build of Slowkey runs faster than the Windows build even when Linux is run inside Windows (WSL/VM) on the same host. We attribute this to library choices, compile targets, and Linux’s resource management under CPU+RAM-intensive loads.

If long-term/parallel key stretching is not a priority, Windows is acceptable and will work fine.

### Recommendation

Prefer native Linux on bare metal for best and most predictable performance.

## Linux Distributions & Kernel

Most distros are within a similar range, but Manjaro consistently came out ahead by a noticeable margin in our testing; Arch-based distros generally performed better than the rest.

Vanilla Debian also performed very well in some cases.

Performance varies with hardware, kernel version, microcode, and drivers. There is no single universal winner for every machine.

### Recommendations

Start with an Arch-based distro (e.g., Manjaro) for likely the best performance out of the box.

If performance looks sub-optimal, test a newer kernel (or a different flavor) and compare.

## CPU Architecture & Library Backends

Intel generally performed much better until we switched scrypt from libsodium to a Rust-native implementation on AMD. After that, AMD came close to Intel on systems of similar class.

Conversely, the Rust-native scrypt performed poorly on Intel; on Intel, libsodium was the stronger choice for scrypt.

For Argon2, libsodium worked best across both AMD and Intel in our testing.

Balloon was used via a Rust-native implementation (not available in libsodium in our setup).

With default parameters on an overclocked but stable Intel Core Ultra 9 285K-class system, the fastest single-instance, single iteration average speed we saw was ~1.16 seconds. Because Slowkey runs all three algorithms per iteration (usually each as a separate process thread), the slowest algorithm (often Balloon at defaults) determines iteration completion time.

### Recommendations

Intel systems: prefer libsodium scrypt + libsodium Argon2 + Rust-native Balloon.

AMD systems: try Rust-native scrypt (often much better on AMD), libsodium Argon2, Rust-native Balloon.

Always benchmark your hardware; backends/implementations are architecture-sensitive. As a general rule of thumb the newest generation and most high-end hardware and processor will outperform both in raw single process speed and even more so with multi-threading. Higher sustained CPU clock speeds are proportional to lower iteration times.

Processor Note: CPUs with a higher PL1 sustained power draw generally achieve stronger multithreaded performance because they can maintain higher clock speeds across many cores without throttling.

## Speed vs. Efficiency (single instance vs. many)

For maximum speed (lowest latency): run a single instance.

For higher efficiency (higher total throughput): run multiple instances—this uses hardware more fully but slows each instance. Power draw will typically rise.

Diminishing returns kick in when you hit CPU or memory bandwidth limits.

Practical caps (with default parameters)

16 GB RAM → around 4 instances with a decent multi-core CPU.

32 GB RAM → around 10 instances on a strong multi-core CPU.

Beyond 32 GB, the CPU usually becomes the bottleneck; extra RAM alone won’t help.

Stability note

Pushing clocks/voltages for long stretches can reduce stability. If speed/latency isn’t critical, prefer conservative, stock settings. Use the slowkey stability-test command to test concurrent task (instance) limitations and stability.

## Parallel Creation with Serial Enforcement (Daisy-Chaining)

To speed up creation while preserving serial time for decryption:

1. Run multiple instances across multiple machines (in a secure environment).

2. Take the output of instance A and encrypt the next set of starting parameters (password+salt) with it (either using an external encryption app or using the slowkey 'secrets' command).

3. Repeat the chaining for A→B→C→… so the final key depends on the whole chain.

Ten instances created in parallel over 1 week can force ~10 weeks of serial effort to re-derive, because the decryptor must process the chain sequentially.

## Monitoring & Useful Tools

These help you observe frequency, temps, throttling, and stability (some may already be pre-installed in your distro):

**htop**: interactive process viewer; useful to watch Slowkey instances, per-process CPU and memory usage, and thread counts.

**lm-sensors**: detects hardware sensors (temps, voltages, fans) so you can read actual temperatures and fan speeds.

**s-tui**: a terminal-based UI that graphs CPU temperature, frequency, and utilization in real time; handy to spot throttling visually.

**thermald**: thermal management daemon (especially useful on many Intel systems) that can help stabilize thermal throttling and power draw (highly recommended).

**cpupower** (or the kernel-tools package that provides it): utilities to inspect and set CPU frequency governors and related frequency scaling controls.

**lscpu**: provides CPU topology and per-core details (commonly available via util-linux).

### Setup

Detect sensors (answer prompts; safe defaults are fine):

```sh
sudo sensors-detect
```

Start thermald (helps stabilize power/thermals on many Intel systems):

```sh
sudo systemctl enable --now thermald
```

Put CPU frequency scaling into "performance" mode:

```sh
sudo cpupower frequency-set -g performance
```

On some systems, you may need to ensure the cpupower service or the relevant driver is active. If the command errors, verify the package and kernel headers match your running kernel. On some systems may also be controllable through the stock power management panel / power profiles daemon.

### Live Monitoring

Top-down system view:

```sh
htop
```

Real-time temps/voltage/frequencies (text UI):

```sh
s-tui
```

Sensors and per-core clocks every 0.5s:

```sh
watch -n 0.5 'sensors; grep -i "cpu mhz" /proc/cpuinfo'
```

Per-core details:

```sh
lscpu --extended
```

### Notes

Some gaming laptops and OEM desktops expose performance profiles via firmware/ACPI, vendor tools, or GRUB kernel parameters. If available, setting a Performance profile can reduce frequency oscillation and boost sustained clocks. May require updating the kernel especially for newer hardware.

Some machines allow manual fan curves. Higher fan speeds lower temps (and throttling) at the cost of noise.

## Hardware: Desktop vs. Laptop

Desktops: better thermals and power delivery → typically higher sustained performance. Also the better option for achieving maximum single instance iteration speed.

Gaming laptops: can be surprisingly capable for long runs, are portable, and don’t require a UPS. For serious but convenient key stretching, a gaming laptop is the easiest path especially because they are already performance optimized and stress tested by the manufacturers as there is almost no modification/customization flexibility compared to a desktop machine.

For modest needs or single-instance runs, any decent laptop will do the job.

## What Actually Drives Performance

CPU core frequency (sustained, not just peak or boost)

Core count & topology (but remember, each added instance slows per-instance latency)

Memory bandwidth and, critically, memory latency

Thermal headroom and power limits (higher PL1 = stronger multithreaded performance)

## Stability, Integrity & Verification

Overheating or marginal stability can cause silent computation faults—fatal for key recovery because the regenerated key won’t match.

RAM overheating was a common culprit; CPU instability can also corrupt results.

Aggressive, long-duration runs can hasten CPU degradation (notably seen on some recent Intel Core i9 13th/14th gen parts).

### Best Practices

Keep clocks/voltages modest unless you absolutely need speed.

Prefer lower temps (better fan curves, adequate cooling, clean intake filters).

Verify every stretch: run at least twice with identical inputs and confirm the derived keys match byte-for-byte before trusting the output.

Consider daisy-chaining (Section 5) to avoid pushing a single box to its limits during creation.

## Quick Checklist (TL;DR)

✅ Use Linux (bare metal) when possible.

✅ Start with Manjaro/Arch or Debian; try newer kernels if results lag.

✅ Pick backends/implementations per architecture:

- **Intel**: libsodium scrypt, libsodium Argon2, Rust-native Balloon

- **AMD**: Rust-native scrypt, libsodium Argon2, Rust-native Balloon

✅ For speed: single instance. For efficiency: many instances (watch CPU/RAM limits).

✅ Typical caps:  ~4 instances @ 16 GB, ~10 instances @ 32 GB (defaults).

✅ Useful tools: htop, lm-sensors, s-tui, thermald, cpupower, lscpu.

✅ Performance boosts: enable thermald (Intel specific), set performance governor.

✅ Monitor temps and clocks; keep the system cool and stable.

✅ Verify outputs by running stretches twice and comparing.

## Reproducible Benchmark Template

### Using the `bench` Command

The bench command performs an exhaustive per-algorithm benchmarking pass so you can evaluate individual algorithm performance across available backends/implementations and parameters.

### Using the Stability-test or Derive Command

The stability-test command lets you choose how many instances to run (using default parameters) and tests against pre-computed results for stability; by setting a lower iteration count than the default 2000 you can quickly compare completion speeds with different concurrent task (instance) counts. For more iterations and a longer stability test you can repeat by command chaining. To really push the computer to its limits you can run an additional stress test (s-tui / stress-ng / ...) in parallel to the slowkey stability-test.

Alternatively you can use the derive command for more fine-grained control and details.

1. Reboot to a known-good baseline (no vendor overclock, clean background tasks).

2. Recommended to set governor to performance (see Section 6).

3. Start htop and s-tui in side terminals.

4. Run single instance with default params; record iteration time and temps.

5. Run N instances (e.g., 2, 4, 8, 10) and record total throughput and per-instance latency (iteration speed).

6. Swap scrypt backend (libsodium ↔ Rust-native) and repeat on the same machine.

7. Change kernel or distro only after you have a stable baseline.

Record every run with exact versions (kernel, microcode, library SHAs), ambient temp, and cooling profile for apples-to-apples comparisons.
