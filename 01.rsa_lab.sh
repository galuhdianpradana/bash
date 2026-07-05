#!/usr/bin/env bash
# =============================================================================
# LAB RSA STEP-BY-STEP — Bash Implementation
# Compatible: bash 3.2+ (macOS default) | bash 4/5+ | Ubuntu Server 24.04+
#             Tidak menggunakan local -n / local -A / echo -e / [[ =~ ]]
#             sehingga berjalan di macOS /bin/bash maupun GNU bash di Linux.
#
# Penggunaan:
#   chmod +x rsa_stepbystep.sh
#   ./rsa_stepbystep.sh
#
# Dependensi:
#   - python3  (tersedia default di Ubuntu 22.04+ dan macOS 12.3+)
#   - Tidak perlu library Python tambahan (hanya stdlib)
#
# Langkah-langkah:
#   1. Generate kunci RSA (p, q → n, e, d)
#   2. Enkripsi pesan ASCII → ciphertext
#   3. Dekripsi ciphertext → pesan asli
# =============================================================================

set -eu

# ── Warna terminal ─────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

# ── Cek ketersediaan python3 ───────────────────────────────────────────────────
check_dependencies() {
    if ! command -v python3 >/dev/null 2>&1; then
        printf "${RED}❌ python3 tidak ditemukan.\n${RESET}"
        printf "   Install dengan: ${YELLOW}sudo apt-get install -y python3\n${RESET}"
        exit 1
    fi
}

# ── Backend python3: semua kalkulasi RSA ───────────────────────────────────────
#
# Sub-commands:
#   is_prime    <n>                  → exit 0 jika prima, 1 jika tidak
#   generate    <p> <q>              → cetak N= E= D= PHI= ke stdout
#   encrypt     <plaintext> <e> <n>  → cetak CT_DEC= CT_HEX= M_DEC=
#   decrypt     <ciphertext> <d> <n> → cetak PLAINTEXT=
#
run_python() {
    python3 - "$@" <<'PYEOF'
import sys, math

# ── Extended GCD ──────────────────────────────────────────────────────────────
def egcd(a, b):
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = egcd(b % a, a)
    return gcd, y1 - (b // a) * x1, x1

# ── Modular inverse ───────────────────────────────────────────────────────────
def modinv(e, phi):
    gcd, x, _ = egcd(e, phi)
    return x % phi if gcd == 1 else None

# ── Deterministic primality (trial division — cocok untuk prime kecil dari user)
def is_prime(n):
    if n <= 1:  return False
    if n <= 3:  return True
    if n % 2 == 0: return False
    i = 3
    while i * i <= n:
        if n % i == 0: return False
        i += 2
    return True

# ── Dispatcher ────────────────────────────────────────────────────────────────
cmd = sys.argv[1]

# ── is_prime ──────────────────────────────────────────────────────────────────
if cmd == "is_prime":
    try:
        n = int(sys.argv[2])
    except ValueError:
        print("ERROR:Bukan angka desimal valid.", file=sys.stderr)
        sys.exit(2)
    sys.exit(0 if is_prime(n) else 1)

# ── generate ──────────────────────────────────────────────────────────────────
elif cmd == "generate":
    try:
        p = int(sys.argv[2])
        q = int(sys.argv[3])
    except ValueError:
        print("ERROR:p dan q harus angka desimal.", file=sys.stderr)
        sys.exit(2)

    if not is_prime(p):
        print(f"ERROR:{p} bukan bilangan prima.", file=sys.stderr)
        sys.exit(1)
    if not is_prime(q):
        print(f"ERROR:{q} bukan bilangan prima.", file=sys.stderr)
        sys.exit(1)
    if p == q:
        print("ERROR:p dan q harus berbeda.", file=sys.stderr)
        sys.exit(1)

    n   = p * q
    phi = (p - 1) * (q - 1)

    # Pilih e: coba 65537 dulu, fallback ke bilangan ganjil >= 3
    e = 65537
    if math.gcd(e, phi) != 1:
        e = None
        for c in range(3, phi, 2):
            if math.gcd(c, phi) == 1:
                e = c
                break
        if e is None:
            print("ERROR:Tidak dapat menemukan e yang valid untuk phi ini.", file=sys.stderr)
            sys.exit(1)

    d = modinv(e, phi)
    if d is None:
        print("ERROR:Gagal menghitung d (e dan phi tidak koprim).", file=sys.stderr)
        sys.exit(1)

    print(f"N={n}")
    print(f"E={e}")
    print(f"D={d}")
    print(f"PHI={phi}")

# ── encrypt ───────────────────────────────────────────────────────────────────
elif cmd == "encrypt":
    plaintext = sys.argv[2]
    try:
        e = int(sys.argv[3])
        n = int(sys.argv[4])
    except ValueError:
        print("ERROR:e dan n harus angka desimal.", file=sys.stderr)
        sys.exit(2)

    if not plaintext:
        print("ERROR:Pesan tidak boleh kosong.", file=sys.stderr)
        sys.exit(1)

    try:
        m = int.from_bytes(plaintext.encode('utf-8'), byteorder='big')
    except Exception as ex:
        print(f"ERROR:Gagal mengubah pesan ke bytes: {ex}", file=sys.stderr)
        sys.exit(1)

    if m >= n:
        bits_needed = m.bit_length()
        print(
            f"ERROR:Pesan terlalu besar untuk n={n}.\n"
            f"       Pesan butuh {bits_needed}-bit, sedangkan n hanya {n.bit_length()}-bit.\n"
            f"       Gunakan p dan q yang lebih besar.",
            file=sys.stderr
        )
        sys.exit(1)

    c = pow(m, e, n)
    print(f"CT_DEC={c}")
    print(f"CT_HEX=0x{c:x}")
    print(f"M_DEC={m}")

# ── decrypt ───────────────────────────────────────────────────────────────────
elif cmd == "decrypt":
    ct_raw = sys.argv[2]
    try:
        c = int(ct_raw, 0)   # auto-detect: "0x..." → hex, angka biasa → desimal
    except ValueError:
        print("ERROR:Ciphertext tidak valid. Gunakan angka desimal atau format 0x...", file=sys.stderr)
        sys.exit(1)

    try:
        d = int(sys.argv[3])
        n = int(sys.argv[4])
    except ValueError:
        print("ERROR:d dan n harus angka desimal.", file=sys.stderr)
        sys.exit(2)

    if c < 0 or c >= n:
        print(f"ERROR:Ciphertext harus berada di rentang 0 <= c < n={n}.", file=sys.stderr)
        sys.exit(1)

    m = pow(c, d, n)
    length = (m.bit_length() + 7) // 8
    if length == 0:
        print("ERROR:Hasil dekripsi adalah nol — kunci atau ciphertext salah.", file=sys.stderr)
        sys.exit(1)

    try:
        plaintext = m.to_bytes(length, byteorder='big').decode('utf-8')
    except Exception:
        print("ERROR:Hasil dekripsi bukan teks UTF-8 valid — kunci atau ciphertext salah.", file=sys.stderr)
        sys.exit(1)

    print(f"PLAINTEXT={plaintext}")

else:
    print(f"ERROR:Sub-command tidak dikenal: {cmd}", file=sys.stderr)
    sys.exit(2)
PYEOF
}

# ── Helper: ambil nilai KEY dari string "KEY=value\n..." ──────────────────────
_get() {
    printf '%s' "$1" | grep "^${2}=" | cut -d= -f2-
}

# ── Return channel untuk read_integer (bash 3.2 compat, tanpa local -n) ───────
_READ_RESULT=""

# ── Baca bilangan positif dari stdin ──────────────────────────────────────────
read_integer() {
    local prompt="$1"
    local raw

    while true; do
        printf "${CYAN}${prompt}${RESET}"
        IFS= read -r raw
        raw="$(printf '%s' "$raw" | tr -d '[:space:]')"

        if [ -z "$raw" ]; then
            printf "${RED}  ❌ Input tidak boleh kosong.\n${RESET}"
            continue
        fi
        case "$raw" in
            ''|*[!0-9]*)
                printf "${RED}  ❌ Masukkan angka desimal positif.\n${RESET}"
                continue
                ;;
        esac

        _READ_RESULT="$raw"
        return 0
    done
}

# ── Baca string bebas dari stdin ───────────────────────────────────────────────
read_string() {
    local prompt="$1"
    local raw

    while true; do
        printf "${CYAN}${prompt}${RESET}"
        IFS= read -r raw

        if [ -z "$raw" ]; then
            printf "${RED}  ❌ Input tidak boleh kosong.\n${RESET}"
            continue
        fi

        _READ_RESULT="$raw"
        return 0
    done
}

# ── Baca ciphertext: boleh hex (0x...) atau desimal ───────────────────────────
read_ciphertext() {
    local prompt="$1"
    local raw

    while true; do
        printf "${CYAN}${prompt}${RESET}"
        IFS= read -r raw
        raw="$(printf '%s' "$raw" | tr -d '[:space:]')"

        if [ -z "$raw" ]; then
            printf "${RED}  ❌ Input tidak boleh kosong.\n${RESET}"
            continue
        fi

        # Cek: boleh angka murni ATAU 0x/0X diikuti hex digits
        case "$raw" in
            0x*|0X*)
                local hexpart="${raw#0x}"; hexpart="${hexpart#0X}"
                case "$hexpart" in
                    ''|*[!0-9a-fA-F]*)
                        printf "${RED}  ❌ Format hex tidak valid (gunakan 0x diikuti digit hex).\n${RESET}"
                        continue ;;
                esac ;;
            ''|*[!0-9]*)
                printf "${RED}  ❌ Masukkan angka desimal atau hex (0x...).\n${RESET}"
                continue ;;
        esac

        _READ_RESULT="$raw"
        return 0
    done
}

# ── Tekan ENTER untuk lanjut ───────────────────────────────────────────────────
press_enter() {
    printf "${DIM}$1${RESET}"
    IFS= read -r _dummy || true
}

# =============================================================================
# LANGKAH 1: PEMBANGKITAN KUNCI RSA
# =============================================================================
step_1_generate_keys() {
    printf "\n${BOLD}${BLUE}"
    printf "╔═══════════════════════════════════════════════════════╗\n"
    printf "║       LANGKAH 1: PEMBANGKITAN KUNCI RSA               ║\n"
    printf "╚═══════════════════════════════════════════════════════╝\n"
    printf "${RESET}\n"

    printf "${DIM}Tips: Untuk demo gunakan prima kecil seperti 257 dan 263.\n"
    printf "      Untuk n yang cukup besar: p,q minimal 4-digit prima.\n${RESET}\n"

    local p q result err

    # Loop input p dan q sampai valid
    while true; do
        read_integer "Masukkan bilangan prima p: "
        p="$_READ_RESULT"
        read_integer "Masukkan bilangan prima q: "
        q="$_READ_RESULT"

        if ! result=$(run_python generate "$p" "$q" 2>/tmp/_rsa_err); then
            err="$(cat /tmp/_rsa_err)"
            printf "${RED}  ❌ %s\n${RESET}" "${err#ERROR:}"
            printf "${YELLOW}  ↩ Silakan masukkan ulang p dan q.\n\n${RESET}"
            continue
        fi
        break
    done

    # Parse hasil
    RSA_N="$(_get "$result" N)"
    RSA_E="$(_get "$result" E)"
    RSA_D="$(_get "$result" D)"
    RSA_PHI="$(_get "$result" PHI)"

    printf "\n${GREEN}${BOLD}✅ Kunci RSA berhasil dibuat!${RESET}\n\n"
    printf "${BOLD}📐 Parameter:${RESET}\n"
    printf "   p (prima 1)            = %s\n"   "$p"
    printf "   q (prima 2)            = %s\n"   "$q"
    printf "   phi = (p-1)(q-1)       = %s\n"   "$RSA_PHI"
    printf "\n"
    printf "${BOLD}🔑 Kunci Publik:${RESET}\n"
    printf "   Modulus       (n)      = %s\n"   "$RSA_N"
    printf "   Public exp.   (e)      = %s\n"   "$RSA_E"
    printf "\n"
    printf "${BOLD}🔐 Kunci Privat:${RESET}\n"
    printf "   Private exp.  (d)      = %s\n"   "$RSA_D"
}

# =============================================================================
# LANGKAH 2: ENKRIPSI PESAN
# =============================================================================
step_2_encryption() {
    printf "\n${BOLD}${BLUE}"
    printf "╔═══════════════════════════════════════════════════════╗\n"
    printf "║       LANGKAH 2: ENKRIPSI PESAN                      ║\n"
    printf "╚═══════════════════════════════════════════════════════╝\n"
    printf "${RESET}\n"

    local plaintext n_input e_input result err

    read_string "Masukkan pesan ASCII yang akan dienkripsi: "
    plaintext="$_READ_RESULT"

    # Jika kunci sudah ada dari langkah 1, tampilkan sebagai default
    if [ -n "${RSA_N:-}" ]; then
        printf "${DIM}  (dari langkah 1: n=%s, e=%s)${RESET}\n" "$RSA_N" "$RSA_E"
        printf "${CYAN}Masukkan nilai modulus (n) [Enter = %s]: ${RESET}" "$RSA_N"
        IFS= read -r n_input
        n_input="$(printf '%s' "$n_input" | tr -d '[:space:]')"
        [ -z "$n_input" ] && n_input="$RSA_N"

        printf "${CYAN}Masukkan nilai public exponent (e) [Enter = %s]: ${RESET}" "$RSA_E"
        IFS= read -r e_input
        e_input="$(printf '%s' "$e_input" | tr -d '[:space:]')"
        [ -z "$e_input" ] && e_input="$RSA_E"
    else
        read_integer "Masukkan nilai modulus (n): "
        n_input="$_READ_RESULT"
        read_integer "Masukkan nilai public exponent (e): "
        e_input="$_READ_RESULT"
    fi

    if ! result=$(run_python encrypt "$plaintext" "$e_input" "$n_input" 2>/tmp/_rsa_err); then
        err="$(cat /tmp/_rsa_err)"
        printf "${RED}❌ %s\n${RESET}" "${err#ERROR:}"
        RSA_CT=""
        return 1
    fi

    RSA_CT="$(_get "$result" CT_DEC)"
    local ct_hex m_dec
    ct_hex="$(_get "$result" CT_HEX)"
    m_dec="$(_get  "$result" M_DEC)"

    printf "\n${GREEN}${BOLD}✅ Enkripsi berhasil!${RESET}\n\n"
    printf "${BOLD}📋 Detail enkripsi:${RESET}\n"
    printf "   Pesan asli (ASCII)     = '%s'\n"  "$plaintext"
    printf "   Pesan sebagai angka    = %s\n"    "$m_dec"
    printf "   Modulus         (n)    = %s\n"    "$n_input"
    printf "   Public exp.     (e)    = %s\n"    "$e_input"
    printf "\n"
    printf "${BOLD}📦 Ciphertext:${RESET}\n"
    printf "   Angka desimal          = %s\n"    "$RSA_CT"
    printf "   Hex                    = %s\n"    "$ct_hex"
}

# =============================================================================
# LANGKAH 3: DEKRIPSI PESAN
# =============================================================================
step_3_decryption() {
    printf "\n${BOLD}${BLUE}"
    printf "╔═══════════════════════════════════════════════════════╗\n"
    printf "║       LANGKAH 3: DEKRIPSI PESAN                      ║\n"
    printf "╚═══════════════════════════════════════════════════════╝\n"
    printf "${RESET}\n"

    local ct_input n_input d_input result err

    # Jika ciphertext tersedia dari langkah 2, tawarkan sebagai default
    if [ -n "${RSA_CT:-}" ]; then
        printf "${CYAN}Masukkan ciphertext (angka/hex) [Enter = %s]: ${RESET}" "$RSA_CT"
        IFS= read -r ct_input
        ct_input="$(printf '%s' "$ct_input" | tr -d '[:space:]')"
        [ -z "$ct_input" ] && ct_input="$RSA_CT"
    else
        read_ciphertext "Masukkan ciphertext (angka desimal atau 0x...): "
        ct_input="$_READ_RESULT"
    fi

    # Jika kunci tersedia dari langkah 1, tawarkan sebagai default
    if [ -n "${RSA_N:-}" ]; then
        printf "${DIM}  (dari langkah 1: n=%s, d=%s)${RESET}\n" "$RSA_N" "$RSA_D"
        printf "${CYAN}Masukkan nilai modulus (n) [Enter = %s]: ${RESET}" "$RSA_N"
        IFS= read -r n_input
        n_input="$(printf '%s' "$n_input" | tr -d '[:space:]')"
        [ -z "$n_input" ] && n_input="$RSA_N"

        printf "${CYAN}Masukkan nilai private exponent (d) [Enter = %s]: ${RESET}" "$RSA_D"
        IFS= read -r d_input
        d_input="$(printf '%s' "$d_input" | tr -d '[:space:]')"
        [ -z "$d_input" ] && d_input="$RSA_D"
    else
        read_integer "Masukkan nilai modulus (n): "
        n_input="$_READ_RESULT"
        read_integer "Masukkan nilai private exponent (d): "
        d_input="$_READ_RESULT"
    fi

    if ! result=$(run_python decrypt "$ct_input" "$d_input" "$n_input" 2>/tmp/_rsa_err); then
        err="$(cat /tmp/_rsa_err)"
        printf "${RED}❌ %s\n${RESET}" "${err#ERROR:}"
        return 1
    fi

    local plaintext
    plaintext="$(_get "$result" PLAINTEXT)"

    printf "\n${GREEN}${BOLD}✅ Dekripsi berhasil!${RESET}\n\n"
    printf "${BOLD}🔓 Pesan hasil dekripsi:${RESET}\n"
    printf "   '%s'\n\n" "$plaintext"
}

# =============================================================================
# MAIN
# =============================================================================
main() {
    check_dependencies

    printf "${BOLD}${CYAN}"
    printf "╔═══════════════════════════════════════════════════════╗\n"
    printf "║           LAB RSA STEP-BY-STEP                        ║\n"
    printf "║   Pembangkitan Kunci → Enkripsi → Dekripsi            ║\n"
    printf "╚═══════════════════════════════════════════════════════╝\n"
    printf "${RESET}\n"

    # Variabel global untuk berbagi state antar langkah
    RSA_N="" RSA_E="" RSA_D="" RSA_CT=""

    # ── Langkah 1 ────────────────────────────────────────────────────────────
    press_enter "Tekan ENTER untuk memulai Langkah 1 (Generate Kunci)..."
    step_1_generate_keys

    # ── Langkah 2 ────────────────────────────────────────────────────────────
    printf "\n"
    press_enter "Tekan ENTER untuk melanjutkan ke Langkah 2 (Enkripsi)..."
    step_2_encryption

    # ── Langkah 3 ────────────────────────────────────────────────────────────
    printf "\n"
    press_enter "Tekan ENTER untuk melanjutkan ke Langkah 3 (Dekripsi)..."
    step_3_decryption

    printf "${BOLD}${GREEN}=== Selesai! ===${RESET}\n\n"
}

main "$@"