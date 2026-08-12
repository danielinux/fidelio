# Fidelio

Fidelio turns a Raspberry Pi RP2040 board into a personal USB security key. It
supports FIDO2/WebAuthn, discoverable credentials (passkeys), and legacy
CTAP1/U2F, using wolfCrypt for cryptography and wolfCOSE for CBOR/COSE.

You need an RP2040 board and one normally-open push-button. No secure element
or other external component is required.

## What it supports

- CTAP2/FIDO2 and WebAuthn, with CTAP1/U2F compatibility
- Physical user presence through a push-button
- FIDO2 PINs and PIN-protected operations
- Up to 16 discoverable credentials, with one account per relying party
- Unlimited non-discoverable credentials
- The WebAuthn `hmac-secret` extension
- ES256, Ed25519, ES384, ES512, ML-DSA-44, ML-DSA-65, and ML-DSA-87
- Raspberry Pi Pico and Waveshare RP2040-Zero boards
- A master secret reconstructed from the chip's SRAM power-on state instead of
  stored in flash

Fidelio chooses the strongest credential algorithm offered by the relying
party. Most existing services will negotiate ES256; newer algorithms work only
with clients and services that support them.

## Quick start

### 1. Prepare the hardware

Connect a normally-open push-button between GND and the board's presence pin.
The firmware cannot approve registration or authentication without it.

| `BOARD` value | Board | Presence button | Indicator |
|---|---|---|---|
| `pico` (default) | Raspberry Pi Pico | GPIO15 | On-board LED |
| `rp2040-zero` | Waveshare RP2040-Zero v1.1 | GPIO29 | WS2812 on GPIO16 |

On a Raspberry Pi Pico, the button can be soldered directly in place:

![Raspberry Pi Pico button wiring](doc/raspi_mod_button.png)

### 2. Install the build tools

The host needs:

- Git
- CMake 3.31 or newer
- an Arm GNU embedded toolchain (`arm-none-eabi-gcc`)
- OpenSSL, `xxd`, and standard Unix tools

`fido2-tools` is optional but useful for detecting the finished key and setting
its PIN.

### 3. Clone Fidelio and its dependencies

```sh
git clone https://github.com/danielinux/fidelio.git
cd fidelio
git submodule update --init --single-branch \
    pico-sdk lib/wolfssl lib/wolfcose
git -C pico-sdk submodule update --init --single-branch lib/tinyusb
```

### 4. Create the attestation identity

Run this once for each device identity:

```sh
./mkcert.sh
```

This generates an attestation certificate and embeds it in `src/cert.c`. Edit
`attestation-cert.conf` first if you want to customize the certificate fields.
Do not share `cert-master-key.pem`: it is the attestation private key. It is
separate from the authenticator master secret described in [Security
model](#security-model).

### 5. Build the firmware

For a Raspberry Pi Pico:

```sh
cmake -S . -B build -DFAMILY=rp2040 -DPICO_SDK_PATH="$PWD/pico-sdk"
cmake --build build
```

For a Waveshare RP2040-Zero, add `-DBOARD=rp2040-zero` to the configure command.
An unknown `BOARD` value is rejected rather than silently selecting another
pinout.

### 6. Flash and enroll the device

Hold BOOTSEL while connecting the board, then copy the UF2 file to the mounted
`RPI-RP2` volume:

```sh
cp build/fidelio.uf2 /path/to/RPI-RP2/
```

The first enrollment takes two cold boots:

1. The device records helper data for its SRAM PUF, blinks once repeatedly,
   and does not appear as a USB security key.
2. Unplug it completely, wait a few seconds, and plug it back in. A reset is
   not enough. The device verifies that it can reconstruct the same secret,
   commits the enrollment, and then starts normally.

If it blinks twice, unplug it and try another cold boot. See [LED halt
codes](#led-halt-codes) for details.

### 7. Check the key and set a PIN

On Linux, find the HID device and set a PIN with `fido2-tools`:

```sh
fido2-token -L
fido2-token -S /dev/hidrawX
```

Replace `/dev/hidrawX` with the path reported by `fido2-token -L`, and press the
presence button when prompted. You can then register and log in at
[WebAuthn.io](https://webauthn.io/) to test a complete WebAuthn flow.

## Everyday use

When a browser or application asks for the security key, connect Fidelio and
press its button while the indicator is lit. Enter the PIN if the client asks
for user verification.

Keep another login or recovery method for every important account. Losing the
device means losing access to its credentials; a person holding both the key
and any required first factor may also be able to authenticate.

### Discoverable credentials (passkeys)

Non-discoverable credentials need no device storage: the service returns the
credential ID during authentication, and Fidelio uses it to derive the same
private key again. Their number is therefore not limited by flash capacity.

Discoverable credentials must be found from the site name alone, so Fidelio
stores them in a ChaCha20-Poly1305 sealed vault. The vault holds 16 sites.
Fidelio is designed as a personal authenticator and stores one discoverable
identity per relying party; creating another for the same site replaces the
first. Use non-discoverable credentials if you need multiple accounts on one
site.

PIN state and the credential vault are each written to alternating flash
sectors so an interrupted update does not leave a partially written live copy.

### Factory reset

Hold the presence button while plugging in the device and keep it held for 10
seconds. The indicator turns yellow while Fidelio erases the PUF checkpoint,
PIN, counters, and discoverable credentials. It then returns to the two-boot
enrollment sequence.

This permanently invalidates every credential created by the device, including
non-discoverable credentials. Revoke the old key at every service; its previous
master secret cannot be recovered.

## Security model

Fidelio derives a unique credential key for each relying party and registration.
Credential private keys are never stored in flash or inside credential IDs;
they are reconstructed only for the operation that needs them.

The root of those derivations is a secret reconstructed at every cold boot from
the power-on state of a reserved SRAM block. A wolfCrypt BCH(127,50,t=13) fuzzy
extractor corrects normal variation. Flash contains only a random salt and
non-secret helper data used for error correction, not the master secret.

Consequently, copying one device's flash to a different RP2040 does not clone
the authenticator: the other chip has a different SRAM response and derives
different keys. The master secret exists in RAM only while the enrolled device
is powered.

Fidelio reports a WebAuthn signature counter of zero. WebAuthn permits this,
and a global counter would allow activity at different relying parties to be
correlated. The legacy U2F path retains an incrementing counter because deployed
U2F verifiers such as `pam_u2f` expect it.

Flash still contains security-sensitive state: encrypted discoverable-credential
metadata, the PIN verifier and retry state, U2F counters, and PUF helper data.
A flash dump does not reveal credential private keys, but physical possession
of a working enrolled device must still be treated as possession of the
authentication factor.

### Firmware updates

Flashing a newer Fidelio UF2 leaves enrollment state intact, so existing
credentials continue to work as long as the PUF profile is unchanged. Changing
`WC_PUF_BCH_T` or `WC_PUF_NUM_CODEWORDS` in `src/user_settings.h` makes the
stored profile incompatible and produces halt code 3 instead of silently
deriving a different secret.

## LED halt codes

If Fidelio cannot start, the indicator blinks a fixed number of times, pauses,
and repeats:

| Flashes | Meaning | Action |
|---|---|---|
| 1 | Enrollment recorded; verification required | Unplug and reconnect; a reset is not enough |
| 2 | SRAM PUF reconstruction failed on this boot | Unplug, wait a few seconds, and reconnect |
| 3 | PUF profile or reserved-memory mismatch | Fix the firmware configuration or memory map |

Code 2 can occur occasionally because cold-boot SRAM varies. Fidelio does not
retry with a warm reset, which would reuse the same SRAM contents, and it never
automatically re-enrolls, which would silently replace the secret and invalidate
all credentials.

On one measured Waveshare RP2040-Zero, reconstruction failed on about one boot
in seven. This is a board-specific measurement, not a guaranteed rate for every
RP2040.

## Board qualification diagnostic

Before trusting a new board design, build the PUF diagnostic instead of the
authenticator:

```sh
cmake -S . -B build-diag -DFAMILY=rp2040 \
    -DPICO_SDK_PATH="$PWD/pico-sdk" \
    -DBOARD=rp2040-zero -DFIDELIO_PUF_DIAG=ON
cmake --build build-diag
cp build-diag/fidelio.uf2 /path/to/RPI-RP2/
```

On its first cold boot the diagnostic captures a reference. On later cold
boots it compares the SRAM response, appends per-codeword error counts to the
last flash sector, shows blue for reference captured, green for comfortable,
amber for within the correction limit, or red for a reconstruction failure,
and prints details on UART0 (GPIO0/GPIO1, 115200 8N1).

Power-cycle the board at least a dozen times, waiting a few seconds between
boots. With the board in BOOTSEL mode, read the log using `picotool`:

```sh
picotool save -r 0x101ff000 0x10200000 puflog.bin
```

The reference must come from a genuine cold boot, not the reboot immediately
after flashing: the BOOTSEL path disturbs part of SRAM. A healthy response has
a Hamming weight near 50%, and no 127-bit codeword should routinely exceed the
13-bit correction limit.

Measurements from one RP2040-Zero over 33 cold boots were:

| Measurement | Result |
|---|---|
| Bit error rate against enrollment | 4.9%–7.0%, mean 5.9% |
| Worst codeword per boot | 10–15 errors out of 127 bits |
| Reconstruction failures at t=13 | 5 of 33 (about 15%) |

Do not leave the diagnostic installed: it is not an authenticator and it writes
to the final flash sector.

## Additional build options

| CMake option | Purpose |
|---|---|
| `-DBOARD=pico` | Select the board pinout (`pico` is the default) |
| `-DFIDELIO_PUF_DIAG=ON` | Replace the authenticator with the PUF diagnostic |
| `-DFIDELIO_BENCH=ON` | Replace the authenticator with the wolfCrypt benchmark |
| `-DFIDELIO_BENCH_CLOCK_KHZ=48000` | Set the benchmark system clock |
| `-DFIDELIO_ALG_PROBE=ON` | Force-link the algorithm sizing probe |
| `-DFIDELIO_EXTRA_DEFS=...` | Add wolfSSL feature macros for development builds |

To add a board, define its `PRESENCE_BUTTON`, LED type, and available ADC
entropy channels in `src/pins.h`, then map a new `BOARD` value to that definition
in `CMakeLists.txt`. GPIO 26+N corresponds to ADC channel N; do not list a
channel whose GPIO is used by another function. On the RP2040-Zero, GPIO29 is
the button, so its ADC channel 3 is deliberately excluded.

## Testing and integrations

Run the host-side COSE wire-format regression test with:

```sh
make -C tests run
```

For GitHub, open **Settings → Password and authentication → Two-factor
authentication → Security keys**, register a new key, and press the Fidelio
button when asked. Always configure a separate recovery method.

For Linux PAM/U2F, install `libpam-u2f` and `pamu2fcfg`, then follow their
distribution documentation. For CTAP2 resident credentials, use `fido2-tools`
and `libpam-fido2`. Keep a root console open while changing `/etc/pam.d` and
test each change immediately to avoid locking yourself out.

## License

Fidelio is licensed under the [GNU General Public License, version 3 or
later](LICENSE). It links wolfSSL and wolfCOSE, which are also GPLv3. wolfSSL
Inc. offers commercial licenses for proprietary use; see
`lib/wolfssl/LICENSING`.
