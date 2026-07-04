# Luna VPN for Windows

Luna is a Windows desktop client for managing Xray-based VPN/proxy profiles.
The interface is implemented with WPF and PowerShell, while the native launcher
hosts PowerShell in-process without displaying a console window.

Current source version: **1.3.1-release**.

## Features

- VLESS Reality, VMess, Trojan and Shadowsocks profile import;
- subscriptions and server catalogue;
- System Proxy and TUN modes;
- split tunnelling and per-application traffic diagnostics;
- real network counters;
- route-quality diagnostics for YouTube, Discord, Microsoft, GitHub and
  Cloudflare;
- comparison of service availability without VPN and through the selected VPN;
- DNS, TCP, tunnel, TLS, HTTP, TTFB and response-validation phases;
- single-instance protection and system tray integration.

Route-quality diagnostics are not a speed test. They use short HTTPS requests
and report the measured result, timeout or protocol error without replacing it
with synthetic values.

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

Luna does not include telemetry upload in the current source release. Local
logs and profiles remain on the device unless the user exports them.

- Website: https://security-luna-vpn.ru/
- Privacy: https://security-luna-vpn.ru/privacy
- Telegram: https://t.me/luna_vpnSecurity
- Email: idontgod22480@gmail.com

## Security

Do not publish subscription URLs, UUIDs, private keys, tokens, passwords or
complete VPN configurations in issues. See [SECURITY.md](SECURITY.md).

Copyright © 2026 Luna. All rights reserved.

