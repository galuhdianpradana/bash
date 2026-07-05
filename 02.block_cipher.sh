#!/usr/bin/env bash
# =============================================================================
# LAB C: BLOCK CIPHER (SPECK128) — Bash Implementation
# Compatible: Ubuntu Server 24.04+ | bash 4.x+ | python3 (included by default)
#
# Penggunaan:
#   chmod +x speck128.sh
#   ./speck128.sh
#
# Dependensi:
#   - python3 (tersedia default di Ubuntu 22.04+)
#   - Tidak perlu library Python tambahan (hanya stdlib)
# =============================================================================

set -euo pipefail

# ── Warna terminal ────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# ── Cek ketersediaan Python3 ──────────────────────────────────────────────────
check_dependencies() {
    if ! command -v python3 &>/dev/null; then
        echo -e "${RED}❌ python3 tidak ditemukan.${RESET}"
        echo -e "   Install dengan: ${YELLOW}sudo apt-get install -y python3${RESET}"
        exit 1
    fi
}

# ── Core Speck128 — dijalankan via python3 inline ────────────────────────────
#
# Aritmatika 128-bit murni tidak tersedia di Bash (hanya 64-bit signed).
# Python3 digunakan sebagai backend kalkulasi. Seluruh UI/flow tetap di Bash.
# Python3 tersedia secara default di Ubuntu 22.04 dan 24.04.
#
run_python() {
    python3 - "$@" <<'PYEOF'
import sys

MASK64 = 0xFFFFFFFFFFFFFFFF
MASK128 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

def rol(x, n):
    return ((x << n) & MASK64) | (x >> (64 - n))

def ror(x, n):
    return (x >> n) | ((x << (64 - n)) & MASK64)

def generate_subkeys(key128):
    MASK16 = 0xFFFF
    k = [(key128 >> (16 * i)) & MASK16 for i in reversed(range(8))]
    rounds  = 32
    subkeys = [k[0]]
    l       = list(k[1:])
    for i in range(1, rounds):
        l_i = (rol(l[i - 1], 2) ^ subkeys[i - 1]) + i
        l_i &= MASK16
        k_i  = rol(subkeys[i - 1], 3) ^ l_i
        k_i &= MASK16
        l.append(l_i)
        subkeys.append(k_i)
    return subkeys

def speck128_encrypt(plaintext, key128):
    x       = (plaintext >> 64) & MASK64
    y       =  plaintext        & MASK64
    subkeys = generate_subkeys(key128)
    for i in range(32):
        x = rol(x, 8)
        x = (x + y) & MASK64
        x ^= subkeys[i]
        y  = rol(y, 3)
        y ^= x
    return (x << 64) | y

def speck128_decrypt(ciphertext, key128):
    x       = (ciphertext >> 64) & MASK64
    y       =  ciphertext        & MASK64
    subkeys = generate_subkeys(key128)
    for i in range(31, -1, -1):
        y ^= x
        y  = ror(y, 3)
        x ^= subkeys[i]
        x  = (x - y) & MASK64
        x  = ror(x, 8)
    return (x << 64) | y

def str_to_block128(text):
    encoded = text.encode('utf-8')
    if len(encoded) > 16:
        raise ValueError("Plaintext terlalu panjang, maksimal 16 karakter (128-bit).")
    return int.from_bytes(encoded, byteorder='big')

def block128_to_str(block):
    # big-endian: byte nol (padding) ada di sisi KIRI (MSB), strip kiri
    raw = block.to_bytes(16, byteorder='big').lstrip(b'\x00')
    return raw.decode('utf-8', errors='replace')

# ── Dispatch ──────────────────────────────────────────────────────────────────
mode   = sys.argv[1]            # "encrypt" | "decrypt"
key128 = int(sys.argv[2], 16)

if mode == "encrypt":
    plaintext = sys.argv[3]
    try:
        pt_block = str_to_block128(plaintext)
    except ValueError as e:
        print(f"ERROR:{e}", file=sys.stderr)
        sys.exit(1)
    ct = speck128_encrypt(pt_block, key128)
    print(f"0x{ct:032x}")

elif mode == "decrypt":
    ct_hex = sys.argv[3]
    try:
        ct = int(ct_hex, 16)
        if not (0 <= ct <= MASK128):
            raise ValueError
    except ValueError:
        print("ERROR:Format cipher tidak valid (harus 32 karakter hex).", file=sys.stderr)
        sys.exit(1)
    pt_block = speck128_decrypt(ct, key128)
    print(block128_to_str(pt_block))

else:
    print("ERROR:Mode tidak dikenali.", file=sys.stderr)
    sys.exit(1)
PYEOF
}

# ── Validasi kunci hex (maks 32 karakter = 128-bit) ──────────────────────────
validate_key() {
    local key="$1"
    key="${key#0x}"; key="${key#0X}"    # hapus prefix 0x jika ada
    if [[ -z "$key" ]] || [[ ! "$key" =~ ^[0-9a-fA-F]{1,32}$ ]]; then
        echo -e "${RED}❌ Kunci tidak valid. Harus hingga 32 karakter hex (128-bit).${RESET}" >&2
        exit 1
    fi
    printf '%s' "$key"
}

# ── Mode Enkripsi ─────────────────────────────────────────────────────────────
do_encrypt() {
    local key="$1"
    local plaintext

    printf "${CYAN}📨 Masukkan plaintext (maks 16 karakter): ${RESET}"
    IFS= read -r plaintext

    if [[ ${#plaintext} -gt 16 ]]; then
        echo -e "${RED}❌ Plaintext terlalu panjang (maks 16 karakter / 128-bit).${RESET}"
        exit 1
    fi

    local result err
    if ! result=$(run_python "encrypt" "$key" "$plaintext" 2>/tmp/_speck_err); then
        err=$(<"/tmp/_speck_err")
        echo -e "${RED}❌ ${err#ERROR:}${RESET}"
        exit 1
    fi

    echo -e "\n${GREEN}🧪 Hasil enkripsi (hex): ${BOLD}${result}${RESET}"
}

# ── Mode Dekripsi ─────────────────────────────────────────────────────────────
do_decrypt() {
    local key="$1"
    local ct_input

    printf "${CYAN}🔐 Masukkan ciphertext (hex, 32 karakter): ${RESET}"
    IFS= read -r ct_input

    ct_input="${ct_input#0x}"; ct_input="${ct_input#0X}"   # strip prefix 0x

    if [[ ! "$ct_input" =~ ^[0-9a-fA-F]{32}$ ]]; then
        echo -e "${RED}❌ Format cipher tidak valid (harus tepat 32 karakter hex).${RESET}"
        exit 1
    fi

    local result err
    if ! result=$(run_python "decrypt" "$key" "$ct_input" 2>/tmp/_speck_err); then
        err=$(<"/tmp/_speck_err")
        echo -e "${RED}❌ ${err#ERROR:}${RESET}"
        exit 1
    fi

    echo -e "\n${GREEN}📬 Hasil dekripsi: ${BOLD}${result}${RESET}"
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
    check_dependencies

    echo -e "${BOLD}${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║   LAB C: BLOCK CIPHER (SPECK128 - Plaintext up to 128-bit)  ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${RESET}"

    printf "${YELLOW}🔑 Masukkan kunci (hex, maks 32 karakter / 128-bit): ${RESET}"
    IFS= read -r key_input

    local key
    key=$(validate_key "$key_input")

    echo ""
    echo -e "${BOLD}Mode:${RESET}"
    echo "  1. Enkripsi"
    echo "  2. Dekripsi"
    printf "${YELLOW}💬 Pilih mode (1/2): ${RESET}"
    IFS= read -r choice

    echo ""
    case "$choice" in
        1) do_encrypt "$key" ;;
        2) do_decrypt "$key" ;;
        *)
            echo -e "${RED}❌ Mode tidak dikenali. Pilih 1 atau 2.${RESET}"
            exit 1
            ;;
    esac

    echo ""
}

main "$@"