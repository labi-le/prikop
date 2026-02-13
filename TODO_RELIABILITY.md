# Reliability & Accuracy Improvements TODO

- [ ] **1. Fix Verifier Connection Reuse**: Ensure each test uses a fresh TCP connection. Connection reuse (Keep-Alive) bypasses DPI desync logic, leading to false positives/negatives.
- [ ] **2. Prevent Evolution Extinction**: If a generation fails completely, regenerate it from scratch instead of ending the phase.
- [ ] **3. Clean Genomes (Remove IPv6 Noise)**: Stop generating IPv6 flags for IPv4-only tests to reduce command-line clutter and mutation noise.
- [ ] **4. Improve nfqws Readiness & Cleanup**:
    - Add a more robust check for nfqws startup.
    - Ensure iptables rules are applied with specific chain existence checks.
- [ ] **5. WorkerPool Stability**:
    - Fix potential race conditions during container removal.
    - Limit the rate of worker respawns.
