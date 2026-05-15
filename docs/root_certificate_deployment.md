# Root Certificate Deployment Guide

## Download URLs
- Windows: `/api/v1/certificates/root/download/windows`
- macOS: `/api/v1/certificates/root/download/macos`
- Linux: `/api/v1/certificates/root/download/linux`
- iOS: `/api/v1/certificates/root/download/ios`
- Android: `/api/v1/certificates/root/download/android`

## Platform steps
- Windows: open certificate file, install to `Trusted Root Certification Authorities` (Local Computer).
- macOS: import into Keychain Access `System` keychain and set trust to `Always Trust`.
- Linux (Debian/Ubuntu): copy to `/usr/local/share/ca-certificates/<organization>-root-ca.crt` and run `sudo update-ca-certificates`.
- iOS: install profile, then enable full trust in `Settings > General > About > Certificate Trust Settings`.
- Android: install CA cert from Security settings; use managed profiles where possible for enterprise fleets.
