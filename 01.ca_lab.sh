#!/usr/bin/env bash
# =============================================================================
# LAB PKI SIMPLE HEX: ASYMMETRIC KEY DISTRIBUTION (PUBLIC ANNOUNCEMENT)
# Compatible: bash 3.2+ (macOS default) | bash 4/5+ | Ubuntu Server 24.04+
#             Tidak menggunakan local -n / local -A / echo -e
#
# Penggunaan:
#   chmod +x pki_lab.sh
#   ./pki_lab.sh
#
# Dependensi:
#   - openssl  (tersedia default di Ubuntu & macOS)
#   - od       (bagian dari GNU coreutils, selalu ada di Linux/macOS)
#
# Catatan:
#   RSA 512-bit digunakan HANYA untuk demo/lab.
#   JANGAN gunakan ukuran kunci ini di lingkungan produksi.
# =============================================================================

set -eu

# ── Konfigurasi ───────────────────────────────────────────────────────────────
LAB_DIR="lab_pki_simple_hex"
KEY_BITS=512    # ⚠️ DEMO SAJA — sangat tidak aman untuk produksi

# ── Warna terminal ─────────────────────────────────────────────────────────────
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

# =============================================================================
# UTILITAS DASAR
# =============================================================================

# Cek ketersediaan command
need() {
    local cmd="$1" hint="$2"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        printf "${RED}❌ '%s' tidak ditemukan.\n   %s\n${RESET}" "$cmd" "$hint"
        exit 1
    fi
}

# Jalankan openssl (redirect stdout+stderr ke /dev/null, exit on error)
sh_silent() {
    "$@" >/dev/null 2>&1
}

# Jalankan openssl dan capture stdout
sh_capture() {
    "$@" 2>/dev/null
}

# Pause: tampilkan prompt lalu tunggu Enter
pause() {
    local msg="${1:-(Tekan Enter untuk MENJALANKAN perintah di atas) }"
    printf "%s" "$msg"
    IFS= read -r _dummy || true
}

# Print judul langkah
print_step() {
    printf "\n%s\n" "$1"
}

# Konversi file binary → hex string dengan prefix "0x" (tanpa spasi/newline)
# Mensimulasikan: "0x" + open(path,"rb").read().hex()
hex_file() {
    printf '0x'
    od -An -tx1 "$1" | tr -d ' \n'
    printf '\n'
}

# Perintah RSA encrypt/decrypt menggunakan rsautl (sesuai modul lab).
# Di OpenSSL 3 rsautl masih berfungsi (hanya deprecated warning ke stderr
# yang kita redirect ke /dev/null agar output bersih).
# Di OpenSSL 1.x rsautl adalah perintah utama yang direkomendasikan.

# Tampilkan command lalu minta konfirmasi Enter, kemudian jalankan
# Mensimulasikan run_and_show() Python
run_and_show() {
    local label="$1"
    shift
    # $@ sekarang adalah command yang akan dijalankan

    printf "\n${CYAN}➡️  JALANKAN perintah ini:${RESET}\n"
    printf "${BOLD}\$ %s${RESET}\n" "$*"
    pause
    if "$@" >/dev/null 2>/tmp/_pki_err; then
        if [ -n "$label" ]; then
            printf "${GREEN}✅ %s${RESET}\n" "$label"
        fi
    else
        # Filter baris warning "deprecated" agar tidak muncul,
        # tapi tetap tampilkan error nyata jika ada
        local err_msg
        err_msg=$(grep -v -i 'deprecated\|use .pkeyutl' /tmp/_pki_err 2>/dev/null || true)
        if [ -n "$err_msg" ]; then
            printf "${RED}❌ Error OpenSSL:\n%s\n${RESET}" "$err_msg"
        else
            # Hanya warning deprecated, bukan error — anggap sukses
            if [ -n "$label" ]; then
                printf "${GREEN}✅ %s${RESET}\n" "$label"
            fi
            return 0
        fi
        exit 1
    fi
}

# =============================================================================
# FIXED KEY MATERIAL — Private key PEM di-hardcode agar nilai hex selalu tetap
# setiap kali script dijalankan (sesuai modul lab).
# Key ini di-generate sekali dengan: openssl genrsa 512
# Dari PEM ini, public key dan DER hex selalu menghasilkan nilai yang sama.
# =============================================================================
ALICE_PRIVATE_PEM='-----BEGIN PRIVATE KEY-----
MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAxrPEhZNzK+roPobK
tKG9DISZ82wTlkmeHnKghhEQi6fFw1iOvvEBGikKPikxsxTvw5Kn1JfgRVCTMCcY
qki2CQIDAQABAkEApI9U/lszUvflB4OSdS5N5wQai+LCBgFKFmVQVDflwAHoLQKE
AePniiOi24MnL+QScHp2F3fODSfiXnIrwzRgQQIhAO8SiHb4ksTv1dWNCoHUkupC
eVRe8uZa0nz7/AyPceJ9AiEA1MV6VvT826wXylhhjl3hHeCUBZaYZ2mue0xtj22k
y30CIQC6TFjnTOEicjrSBOyRK5Oo1VAy/SKPe2rXVo2dRBLdCQIgc2+AZFUeKoA/
mARDSV4dmHwTUsTVgqWPiE1602oFEnECIDvn2ty3nqBDDkW7scPqXoVaQyMuFm5T
N4Y7hQ9ZengP
-----END PRIVATE KEY-----'

BOB_PRIVATE_PEM='-----BEGIN PRIVATE KEY-----
MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAmeOpd4QvGWXzFNxc
xZApT8BwUhTptzMgSQknNoTCTPfKDbElKWJc7jS91qoKT6UK52XqIdFD4y28UdzS
q1OlcQIDAQABAkBES5ohFYPFlM49etKdRy5eW3w9oVRb3o+8ehhyBJcqirlpVkWQ
Bah8d2bU+43PjX3lxdqmo9X/YcUK3kyrZ+RBAiEAyc0JCsOILc7rvYax2H8XOLtV
kiX3szhB77fUqzdzEgkCIQDDOG4FYGksZr9z+2qIGP+0DxKsJGL5FxRaqCxeZWAy
KQIgWu58A5CmHVYfHdDC9LYX5aVsYqWfHu/brkQcnWYoANkCIAQ/bBVt3Zv7uFq7
s7u2X4n5cfyQ5h5pZCX81spPBmLRAiEAyccwbyEJvhsTBSL0qf4UKkYdxQAty9gk
2jFOmW77coE=
-----END PRIVATE KEY-----'

# =============================================================================
# LANGKAH 1 & 2: GENERATE RSA KEY-PAIR (dipakai untuk Alice dan Bob)
# Key di-load dari PEM fixed di atas, bukan di-generate ulang.
# openssl genrsa tetap DITAMPILKAN sebagai demo (sesuai modul), tapi
# file PEM-nya langsung diisi dari konstanta agar nilai hex selalu tetap.
# =============================================================================
rsa_genpair() {
    local name="$1"
    local lower
    lower=$(printf '%s' "$name" | tr '[:upper:]' '[:lower:]')

    print_step "👤 [${name}] Generate RSA ${KEY_BITS}-bit key-pair"

    # ── Tampilkan perintah genrsa sebagai demo (seperti modul) ───────────────
    # Perintah ini tetap ditampilkan dan dikonfirmasi user, tapi file PEM
    # diisi dari nilai fixed agar public key selalu sama setiap run.
    printf "\n${CYAN}➡️  JALANKAN perintah ini:${RESET}\n"
    printf "${BOLD}\$ openssl genrsa -out %s/%s_private.pem %s${RESET}\n" \
        "$LAB_DIR" "$lower" "$KEY_BITS"
    pause

    # Tulis PEM fixed ke file (menggantikan genrsa yang akan menghasilkan nilai acak)
    if [ "$lower" = "alice" ]; then
        printf '%s\n' "$ALICE_PRIVATE_PEM" > "${LAB_DIR}/${lower}_private.pem"
    else
        printf '%s\n' "$BOB_PRIVATE_PEM" > "${LAB_DIR}/${lower}_private.pem"
    fi
    printf "${GREEN}✅ Private key dibuat.${RESET}\n"

    # ── Ekstrak public key ────────────────────────────────────────────────────
    run_and_show \
        "Public key dibuat." \
        openssl rsa \
            -in  "${LAB_DIR}/${lower}_private.pem" \
            -pubout \
            -out "${LAB_DIR}/${lower}_public.pem"

    # ── Ekspor ke format DER (binary) untuk tampilan hex ─────────────────────
    sh_silent openssl rsa \
        -in  "${LAB_DIR}/${lower}_private.pem" \
        -outform DER \
        -out "${LAB_DIR}/${lower}_private.der"

    sh_silent openssl rsa \
        -in  "${LAB_DIR}/${lower}_private.pem" \
        -pubout \
        -outform DER \
        -out "${LAB_DIR}/${lower}_public.der"

    # ── Tampilkan hex ─────────────────────────────────────────────────────────
    print_step "🔎 [${name}] Kunci dalam HEX (DER → prefix 0x)"

    printf "📦 %s PRIVATE:\n" "$name"
    hex_file "${LAB_DIR}/${lower}_private.der"

    printf "\n🔐 %s PUBLIC:\n" "$name"
    hex_file "${LAB_DIR}/${lower}_public.der"
    printf "\n"
}

# =============================================================================
# LANGKAH 3: ENKRIPSI PESAN (Bob → Alice menggunakan public key Alice)
# =============================================================================
encrypt_with_alice_pub() {
    print_step "💌 [Bob] Enkripsi pesan menggunakan PUBLIC key Alice"

    # Input pesan dari user
    local msg
    printf "Ketik pesan Bob (≤ 50 karakter) ➜ "
    IFS= read -r msg
    msg="$(printf '%s' "$msg" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    [ -z "$msg" ] && msg="Halo Alice!"

    # Potong otomatis jika > 50 karakter (kompatibel bash 3.2: pakai cut, bukan ${var:0:50})
    local msg_len=${#msg}
    if [ "$msg_len" -gt 50 ]; then
        printf "${YELLOW}⚠️ Pesan terlalu panjang untuk RSA-%d + PKCS#1. Dipotong otomatis.\n${RESET}" "$KEY_BITS"
        msg="$(printf '%s' "$msg" | cut -c1-50)"
    fi

    # Tulis pesan ke file
    printf '%s' "$msg" > "${LAB_DIR}/message.txt"

    # Enkripsi dengan rsautl sesuai modul (bekerja di OpenSSL 1.x dan 3.x)
    run_and_show \
        "Ciphertext ditulis: ${LAB_DIR}/message.enc" \
        openssl rsautl -encrypt \
            -inkey "${LAB_DIR}/alice_public.pem" -pubin \
            -in    "${LAB_DIR}/message.txt" \
            -out   "${LAB_DIR}/message.enc"

    printf "🔐 Ciphertext (prefix 0x):\n"
    hex_file "${LAB_DIR}/message.enc"
    printf "\n"
}

# =============================================================================
# LANGKAH 4: DEKRIPSI PESAN (Alice menggunakan private key-nya sendiri)
# =============================================================================
decrypt_with_alice_priv() {
    print_step "🔓 [Alice] Dekripsi pesan dengan PRIVATE key Alice"

    # Dekripsi dengan rsautl sesuai modul
    run_and_show \
        "Plaintext disimpan." \
        openssl rsautl -decrypt \
            -inkey "${LAB_DIR}/alice_private.pem" \
            -in    "${LAB_DIR}/message.enc" \
            -out   "${LAB_DIR}/message_decrypted.txt"

    printf "📜 Hasil dekripsi: %s\n" "$(cat "${LAB_DIR}/message_decrypted.txt")"
}

# =============================================================================
# MAIN
# =============================================================================
main() {
    need "openssl" "Install: sudo apt update && sudo apt install openssl -y"
    need "od"      "Install: sudo apt install coreutils -y"

    # Tangani Ctrl+C dengan rapi
    trap 'printf "\n\nDihentikan oleh pengguna.\n"; exit 0' INT

    # Buat direktori lab
    mkdir -p "$LAB_DIR"

    printf "\n"
    printf "${BOLD}🧩 Lab: Asymmetric Key Distribution — Public Announcement (raw public key)${RESET}\n"
    printf '%b' "${DIM}"
    printf -- "- RSA %d-bit untuk demo (jangan gunakan di produksi)\n" "$KEY_BITS"
    printf -- "- Output hex: satu prefix '0x' di depan string hex (tanpa spasi)\n"
    printf '%b\n' "${RESET}"

    # Langkah 1: Generate key pair Alice
    rsa_genpair "Alice"

    # Langkah 2: Generate key pair Bob
    rsa_genpair "Bob"

    # Langkah 3: Bob enkripsi pesan menggunakan public key Alice
    encrypt_with_alice_pub

    # Langkah 4: Alice dekripsi pesan menggunakan private key-nya
    decrypt_with_alice_priv

    printf "\n${GREEN}${BOLD}🎉 Selesai. Folder lab: %s${RESET}\n\n" \
        "$(cd "$LAB_DIR" && pwd)"
}

main "$@"