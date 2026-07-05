#!/usr/bin/env bash
# =============================================================================
# LAB DIFFIE-HELLMAN KEY EXCHANGE — Bash Implementation
# Compatible: bash 3.2+ (macOS default) | bash 4.x+ | Ubuntu Server 24.04+
#             Tidak menggunakan local -n (nameref) atau local -A (assoc array)
#             sehingga berjalan di macOS /bin/bash maupun GNU bash di Linux.
#
# Penggunaan:
#   chmod +x diffie_hellman.sh
#   ./diffie_hellman.sh
#
# Dependensi:
#   - python3  (tersedia default di Ubuntu 22.04+ dan macOS 12.3+)
#
# Catatan desain:
#   Bash hanya mendukung integer 64-bit signed. DH biasanya memakai bilangan
#   prima 1024-bit ke atas (ratusan digit) sehingga aritmatika bignum dan
#   konversi hex diserahkan ke python3 inline. Bash tetap mengelola seluruh
#   UI, prompt, validasi format, dan alur program.
# =============================================================================

set -euo pipefail

# ── Warna terminal ────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

# ── Cek ketersediaan python3 ──────────────────────────────────────────────────
check_dependencies() {
    if ! command -v python3 &>/dev/null; then
        printf "${RED}❌ python3 tidak ditemukan.\n${RESET}"
        printf "   Install dengan: ${YELLOW}sudo apt-get install -y python3\n${RESET}"
        exit 1
    fi
}

# ── Backend python3: semua kalkulasi bignum ───────────────────────────────────
#
# Dipanggil oleh fungsi Bash dengan argumen:
#   run_python <sub-command> [args...]
#
# Sub-commands:
#   validate_prime  <n>          → exits 0 jika probable prime, 1 jika tidak
#   validate_int    <s>          → exits 0 jika string adalah integer valid, 1 jika tidak
# Sub-commands:
#   validate_prime  <n>          → exits 0 jika probable prime, 1 jika tidak
#   validate_int    <s>          → exits 0 jika string adalah integer valid, 1 jika tidak
#   compute_dh  <p> <g> <a> <b> → cetak semua hasil DH ke stdout
#
# Catatan: generator g TIDAK divalidasi rentang 1<g<p. Secara matematis
# pow(g, a, p) otomatis menghitung (g mod p)^a mod p, sehingga g>=p tetap
# menghasilkan hasil yang konsisten dan valid (lihat compute_dh di bawah).
#
run_python() {
    python3 - "$@" <<'PYEOF'
import sys

# ── Miller-Rabin probabilistic primality test ─────────────────────────────────
def is_probably_prime(n, k=25):
    """Probabilistic primality (Miller-Rabin, k rounds). Error < 4^(-k)."""
    if n < 2:  return False
    if n == 2: return True
    if n == 3: return True
    if n % 2 == 0: return False
    # Sieve kecil untuk eliminasi cepat
    small = [3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97]
    for sp in small:
        if n == sp: return True
        if n % sp == 0: return False
    # Dekomposisi n-1 = 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    import random
    rng = random.SystemRandom()   # CSPRNG
    for _ in range(k):
        a = rng.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

# ── Format desimal + hex ──────────────────────────────────────────────────────
def fmt(n):
    return f"{n} (0x{n:x})"

# ── Dispatcher ────────────────────────────────────────────────────────────────
cmd = sys.argv[1]

if cmd == "validate_prime":
    try:
        n = int(sys.argv[2])
    except ValueError:
        print("ERROR:Bukan angka desimal valid.", file=sys.stderr)
        sys.exit(2)
    if n < 2:
        print("ERROR:Bilangan prima harus >= 2.", file=sys.stderr)
        sys.exit(1)
    if not is_probably_prime(n):
        print(f"ERROR:{n} bukan bilangan prima (uji Miller-Rabin).", file=sys.stderr)
        sys.exit(1)
    sys.exit(0)

elif cmd == "validate_int":
    try:
        int(sys.argv[2])
        sys.exit(0)
    except ValueError:
        sys.exit(1)

elif cmd == "compute_dh":
    p = int(sys.argv[2])
    g = int(sys.argv[3])
    a = int(sys.argv[4])
    b = int(sys.argv[5])

    # Validasi secret key — hanya tolak nilai trivial (0, 1) yang membuat
    # hasil g^a mod p selalu sama dengan 1 atau g sendiri (tidak ada
    # kerahasiaan). Rentang a/b TIDAK dibatasi terhadap p, karena secara
    # matematis pow(g, a, p) tetap valid untuk a >= p (lihat catatan di atas).
    if a <= 1:
        print("ERROR:Secret key a harus lebih besar dari 1.", file=sys.stderr)
        sys.exit(1)
    if b <= 1:
        print("ERROR:Secret key b harus lebih besar dari 1.", file=sys.stderr)
        sys.exit(1)

    # Hitung public key
    A = pow(g, a, p)
    B = pow(g, b, p)

    # Hitung shared secret
    shared_A = pow(B, a, p)
    shared_B = pow(A, b, p)

    match = (shared_A == shared_B)

    # Output terstruktur (diparse oleh Bash)
    print(f"P_HEX=0x{p:x}")
    print(f"G_HEX=0x{g:x}")
    print(f"A_DEC={a}")
    print(f"A_HEX=0x{a:x}")
    print(f"B_DEC={b}")
    print(f"B_HEX=0x{b:x}")
    print(f"PUB_A_DEC={A}")
    print(f"PUB_A_HEX=0x{A:x}")
    print(f"PUB_B_DEC={B}")
    print(f"PUB_B_HEX=0x{B:x}")
    print(f"SHARED_A_DEC={shared_A}")
    print(f"SHARED_A_HEX=0x{shared_A:x}")
    print(f"SHARED_B_DEC={shared_B}")
    print(f"SHARED_B_HEX=0x{shared_B:x}")
    print(f"MATCH={'1' if match else '0'}")

else:
    print(f"ERROR:Sub-command tidak dikenal: {cmd}", file=sys.stderr)
    sys.exit(2)
PYEOF
}

# ── Baca integer besar dari stdin dengan prompt ───────────────────────────────
# Kompatibel bash 3.2+: tidak memakai local -n (nameref, bash 4.3+).
# Hasil disimpan ke variabel global _READ_RESULT; caller mengambilnya dengan:
#   read_integer "prompt..." ; myvar="$_READ_RESULT"
_READ_RESULT=""
read_integer() {
    local prompt="$1"
    local raw

    while true; do
        printf "${CYAN}${prompt}${RESET}"
        IFS= read -r raw
        # Hapus semua whitespace (kompatibel bash 3.2 tanpa ${var//pattern/})
        raw="$(printf '%s' "$raw" | tr -d '[:space:]')"

        if [ -z "$raw" ]; then
            printf "${RED}  ❌ Input tidak boleh kosong.\n${RESET}"
            continue
        fi

        # Cek angka desimal murni (positif saja; secret key harus positif)
        case "$raw" in
            ''|*[!0-9]*)
                printf "${RED}  ❌ Input harus berupa angka desimal positif.\n${RESET}"
                continue
                ;;
        esac

        _READ_RESULT="$raw"
        return 0
    done
}

# ── Validasi bilangan prima (lewat python3) ───────────────────────────────────
validate_prime() {
    local n="$1"
    local err
    if ! err=$(run_python validate_prime "$n" 2>&1); then
        printf "${RED}  ❌ %s\n${RESET}" "${err#ERROR:}"
        return 1
    fi
    return 0
}

# ── Tampilkan hasil DH ────────────────────────────────────────────────────────
# Kompatibel bash 3.2+: tidak memakai local -A (associative array, bash 4+).
# Parsing dilakukan dengan grep + cut langsung dari string multiline.
display_results() {
    local data="$1"

    # Helper: ambil nilai untuk KEY dari data "KEY=value\n..."
    _get() { printf '%s' "$data" | grep "^${1}=" | cut -d= -f2-; }

    local P_HEX G_HEX A_DEC A_HEX B_DEC B_HEX
    local PUB_A_DEC PUB_A_HEX PUB_B_DEC PUB_B_HEX
    local SHARED_A_DEC SHARED_A_HEX SHARED_B_DEC SHARED_B_HEX MATCH

    P_HEX="$(_get P_HEX)"        G_HEX="$(_get G_HEX)"
    A_DEC="$(_get A_DEC)"        A_HEX="$(_get A_HEX)"
    B_DEC="$(_get B_DEC)"        B_HEX="$(_get B_HEX)"
    PUB_A_DEC="$(_get PUB_A_DEC)"  PUB_A_HEX="$(_get PUB_A_HEX)"
    PUB_B_DEC="$(_get PUB_B_DEC)"  PUB_B_HEX="$(_get PUB_B_HEX)"
    SHARED_A_DEC="$(_get SHARED_A_DEC)"  SHARED_A_HEX="$(_get SHARED_A_HEX)"
    SHARED_B_DEC="$(_get SHARED_B_DEC)"  SHARED_B_HEX="$(_get SHARED_B_HEX)"
    MATCH="$(_get MATCH)"

    printf "\n"
    printf "${BOLD}${BLUE}┌─────────────────────────────────────────────────────────────┐\n${RESET}"
    printf "${BOLD}${BLUE}│              HASIL DIFFIE-HELLMAN KEY EXCHANGE              │\n${RESET}"
    printf "${BOLD}${BLUE}└─────────────────────────────────────────────────────────────┘\n${RESET}"

    printf "\n${BOLD}📌 Parameter Umum:${RESET}\n"
    printf "   p = ${DIM}%s${RESET}\n"   "$P_HEX"
    printf "   g = %s\n"                 "$G_HEX"

    printf "\n${BOLD}🔐 Secret Key (Private — jangan dibagikan!):${RESET}\n"
    printf "   a (milik A) = %s\n"       "$A_DEC"
    printf "               = %s\n"       "$A_HEX"
    printf "   b (milik B) = %s\n"       "$B_DEC"
    printf "               = %s\n"       "$B_HEX"

    printf "\n${BOLD}🌐 Public Key (hasil perhitungan, boleh dibagikan):${RESET}\n"
    printf "   A = g^a mod p\n"
    printf "     = %s\n"                 "$PUB_A_DEC"
    printf "     = %s\n"                 "$PUB_A_HEX"
    printf "\n"
    printf "   B = g^b mod p\n"
    printf "     = %s\n"                 "$PUB_B_DEC"
    printf "     = %s\n"                 "$PUB_B_HEX"

    printf "\n${BOLD}🔑 Shared Secret (harus sama di kedua sisi):${RESET}\n"
    printf "   S_A = B^a mod p = %s\n"  "$SHARED_A_DEC"
    printf "       = %s\n"              "$SHARED_A_HEX"
    printf "\n"
    printf "   S_B = A^b mod p = %s\n"  "$SHARED_B_DEC"
    printf "       = %s\n"              "$SHARED_B_HEX"

    printf "\n"
    if [ "$MATCH" = "1" ]; then
        printf "${GREEN}${BOLD}   ✅ Key exchange berhasil! Kunci bersama cocok.${RESET}\n"
    else
        printf "${RED}${BOLD}   ❌ Key exchange gagal! Kunci bersama tidak cocok.${RESET}\n"
    fi
    printf "\n"
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
    check_dependencies

    printf "${BOLD}${CYAN}"
    printf "╔═══════════════════════════════════════════════════════════════╗\n"
    printf "║       LAB DIFFIE-HELLMAN KEY EXCHANGE (FORMAT HEX 0x...)     ║\n"
    printf "╚═══════════════════════════════════════════════════════════════╝\n"
    printf "${RESET}\n"

    printf "${DIM}Tips: Untuk demo cepat, gunakan prima kecil (misal p=23, g=5, a=6, b=15)\n${RESET}"
    printf "${DIM}      Untuk keamanan nyata, gunakan prima >= 1024-bit.\n${RESET}"
    printf "\n"

    # ── Input p ───────────────────────────────────────────────────────────────
    local p g a b result err

    while true; do
        read_integer "Masukkan bilangan prima p (desimal): "
        p="$_READ_RESULT"
        validate_prime "$p" && break
    done

    # ── Input g ───────────────────────────────────────────────────────────────
    # Tidak ada batasan g < p — secara matematis g >= p tetap valid karena
    # pow(g, a, p) otomatis menghitung (g mod p)^a mod p.
    read_integer "Masukkan generator g (desimal): "
    g="$_READ_RESULT"

    printf "\n${BOLD}🔐 Masukkan Secret Key (integer, harus lebih besar dari 1):${RESET}\n"

    # ── Input a ───────────────────────────────────────────────────────────────
    read_integer "  Secret key pengguna A (a): "
    a="$_READ_RESULT"

    # ── Input b ───────────────────────────────────────────────────────────────
    read_integer "  Secret key pengguna B (b): "
    b="$_READ_RESULT"

    printf "\n${DIM}⏳ Menghitung...${RESET}\n"

    # ── Hitung dan tampilkan ──────────────────────────────────────────────────
    if ! result=$(run_python compute_dh "$p" "$g" "$a" "$b" 2>/tmp/_dh_err); then
        err=$(<"/tmp/_dh_err")
        printf "${RED}❌ %s\n${RESET}" "${err#ERROR:}"
        exit 1
    fi

    display_results "$result"
}

main "$@"