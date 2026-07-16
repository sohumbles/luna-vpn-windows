# Luna VPN for Windows

Luna is a Windows desktop client for managing Xray-based VPN/proxy profiles.
The interface is implemented with WPF and PowerShell, while the native launcher
hosts PowerShell in-process without displaying a console window.

Current source version: **1.5.2-release**.

Official website: https://security-luna-vpn.ru/

Luna SpeedTest: https://security-luna-vpn.ru/speedtest

## Features

- VLESS Reality, VMess, Trojan and Shadowsocks profile import;
- subscriptions and server catalogue;
- System Proxy mode and native Xray TUN mode for Windows 10/11;
- working Split Tunneling exclusions for websites, IPv4/IPv6 addresses and
  CIDR networks, applications and games in both System Proxy and TUN modes;
- process-aware direct routing by the full path to an executable file;
- selection of application/game rules from currently running Windows processes;
- local validation, import and export of Split Tunneling rules;
- real network counters;
- route-quality diagnostics for YouTube, Discord, Microsoft, GitHub and
  Cloudflare;
- comparison of service availability without VPN and through the selected VPN;
- DNS, TCP, tunnel, TLS, HTTP, TTFB and response-validation phases;
- single-instance protection and system tray integration.

Route-quality diagnostics are not a speed test. They use short HTTPS requests
and report the measured result, timeout or protocol error without replacing it
with synthetic values.

The 1.5.1 desktop layout keeps the connection control, mode and selected-server
latency visible while only the server catalogue scrolls. The interface keeps
the Russian/English language selector and the dark/light/automatic theme selector.

In System Proxy mode, Luna's local selective HTTP/CONNECT proxy maps loopback
connections to the owning PID and full executable path, then chooses direct or
Xray upstream routing. This covers proxy-aware HTTP/HTTPS. Applications that
ignore the Windows proxy and UDP traffic already use a direct connection in
this mode. TUN mode uses Xray's native Windows TUN inbound for system-wide
TCP/UDP rules and requests elevation only when the tunnel starts. Exclusion
rules stay in the local Luna state file and are not sent to the Luna backend.

## Repository layout

- `src/Luna.ps1` — application UI and VPN logic;
- `src/LunaLauncher.cs` — console-free native launcher;
- `installer/LunaInstaller.cs` — offline per-user installer;
- `packaging/msix` — Microsoft Store MSIX template and packaging script;
- `assets` — Luna desktop artwork;
- `docs` — changelog, release notes and privacy policy.

## Building

The repository intentionally does not include Xray binaries, GeoIP/GeoSite
databases, Wintun, server subscriptions, API tokens or private configuration.

To build a distributable package:

1. Obtain Xray-core and its data files from their official distribution.
2. Place the runtime payload under `packaging/msix/Payload/x64`.
3. Compile `src/LunaLauncher.cs`, embedding `src/Luna.ps1` as `Luna.Script` and
   `assets/luna-icon.png` as `Luna.Icon`.
4. For Microsoft Store packaging, run `Build-Store-Package.ps1` with the exact
   Package Identity values from Partner Center.

Example:

```powershell
.\packaging\msix\Build-Store-Package.ps1 `
  -PackageName "PACKAGE_IDENTITY_NAME" `
  -Publisher "CN=PUBLISHER_ID" `
  -PublisherDisplayName "Publisher name"
```

## Privacy and support

Luna can send sanitized diagnostic error reports only after explicit user
consent. Profiles and full local logs remain on the device unless the user
exports them. Client-side and server-side filters remove connection secrets,
addresses and user paths from reports.

- Telegram: https://t.me/luna_vpnSecurity
- Email: idontgod22480@gmail.com

## Security

Do not publish subscription URLs, UUIDs, private keys, tokens, passwords or
complete VPN configurations in issues. See [SECURITY.md](SECURITY.md).

Copyright © 2026 Luna. All rights reserved.

