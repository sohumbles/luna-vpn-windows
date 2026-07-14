# Luna SpeedTest 2.0

The existing website route `/speedtest` uses a deterministic state machine:

`idle → preparing → detecting-client → selecting-server → measuring-idle-latency → measuring-download → measuring-upload → finalizing → completed`

`cancelled` and `failed` are explicit exits. `AbortController` cancels every active request and component teardown also aborts work.

## Measurement model

- Idle latency uses HTTP round trips measured with `performance.now()`. Warmup samples are excluded and the median is shown.
- Jitter is the median absolute difference between adjacent usable latency samples.
- Download reads actual chunks from `response.body` and uses 2–8 adaptive streams.
- Upload uses generated in-memory binary payloads and counts bytes only after server confirmation.
- Loaded latency is measured concurrently during download and upload.
- Loss is failed HTTP probes divided by observed probes. It is explicitly application-level loss, not ICMP packet loss, and is hidden without observations.
- Throughput uses decimal Mbps; live sample arrays are bounded.

The website same-origin API is a functional baseline. High-bandwidth public use should point the server catalog at dedicated Docker speed nodes with known capacity. No VPN credentials, user files, browsing history or traffic contents are collected by the test.

## Visual state model

- The cratered moon and outer scale remain stable so live values do not shift the layout.
- Download pulls particles toward the gauge centre; upload sends them outward.
- The energy stream, gauge colour, direction marker and result rows follow the active measurement phase.
- Successful completion emits two fading waves. Cancellation and failure never display a success animation.
- `prefers-reduced-motion` disables decorative movement while preserving every measured value and control.

Public endpoint: https://security-luna-vpn.ru/speedtest
