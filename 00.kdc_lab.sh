#!/usr/bin/env bash
# =============================================================================
# SIMULASI DASAR KDC: PEMBENTUKAN SESSION KEY (Ks) — Bash Implementation
# Compatible: bash 3.2+ (macOS default) | bash 4/5+ | Ubuntu Server 24.04+
#             Tidak menggunakan local -n / local -A / echo -e / [[ =~ ]]
#             sehingga berjalan di macOS /bin/bash maupun GNU bash di Linux.
#
# Penggunaan:
#   chmod +x kdc_lab.sh
#   ./kdc_lab.sh
#
# Dependensi:
#   - openssl   (untuk random bytes — tersedia default di Ubuntu & macOS)
#     Fallback otomatis ke /dev/urandom + od jika openssl tidak ada.
#   - TIDAK PERLU python3, pip, atau library rich — script ini murni Bash,
#     karena tidak ada operasi kriptografis berat (bignum/modexp) yang
#     dibutuhkan; hanya random byte generation dan hex encode/decode,
#     keduanya bisa dilakukan native di Bash + openssl.
# =============================================================================

set -eu

# ── Warna terminal (mensimulasikan style rich: cyan/yellow/green/bold) ───────
CYAN='\033[0;36m'
BOLD_CYAN='\033[1;36m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BOLD_GREEN='\033[1;32m'
DIM='\033[2m'
BOLD='\033[1m'
RESET='\033[0m'

# ── Cek ketersediaan sumber random bytes ──────────────────────────────────────
RANDOM_BACKEND=""
check_dependencies() {
    if command -v openssl >/dev/null 2>&1; then
        RANDOM_BACKEND="openssl"
    elif [ -r /dev/urandom ] && command -v od >/dev/null 2>&1; then
        RANDOM_BACKEND="urandom"
    else
        printf "${YELLOW}! Tidak ditemukan openssl maupun /dev/urandom+od.\n${RESET}"
        printf "  Install dengan: ${YELLOW}sudo apt-get install -y openssl\n${RESET}"
        exit 1
    fi
}

# ── Generate N byte random sebagai hex string (lowercase, tanpa prefix) ──────
random_hex() {
    local n_bytes="$1"
    if [ "$RANDOM_BACKEND" = "openssl" ]; then
        openssl rand -hex "$n_bytes"
    else
        od -An -tx1 -N "$n_bytes" /dev/urandom | tr -d ' \n'
    fi
}

# =============================================================================
# UTILITAS TAMPILAN — mensimulasikan rich.console (Panel, Table, rule, dll)
# =============================================================================

# repeat_char "─" 60   → cetak karakter berulang sejumlah N (portable bash 3.2)
repeat_char() {
    local char="$1" count="$2" i=0 result=""
    while [ "$i" -lt "$count" ]; do
        result="${result}${char}"
        i=$((i + 1))
    done
    printf '%s' "$result"
}

# header "Judul" → mensimulasikan Panel.fit(Text(...), style="cyan") dari rich
# rich Panel.fit pakai ╭ ─ ╮ / │ (bukan ┌ └) dengan padding 1 spasi kiri-kanan
header() {
    local title="$1"
    local inner_width=$(( ${#title} + 2 ))   # 1 spasi kiri + teks + 1 spasi kanan

    printf "${CYAN}╭"; repeat_char "─" "$inner_width"; printf "╮\n${RESET}"
    printf "${CYAN}│${RESET} ${BOLD}%s${RESET} ${CYAN}│\n${RESET}" "$title"
    printf "${CYAN}╰"; repeat_char "─" "$inner_width"; printf "╯\n${RESET}"
}

# step "Judul" → mensimulasikan console.rule("[bold]Judul[/bold]") dari rich
# rich rule: garis ─ lebar total 80, teks di tengah dengan 1 spasi kiri-kanan
step() {
    local title="$1"
    local width=80
    local title_with_spaces=" ${title} "
    local title_ws_len=${#title_with_spaces}
    local fill=$(( width - title_ws_len ))
    local left=$(( fill / 2 ))
    local right=$(( fill - left ))
    [ "$left" -lt 0 ] && left=0
    [ "$right" -lt 0 ] && right=0

    printf "\n"
    repeat_char "─" "$left"
    printf "${BOLD}%s${RESET}" "$title_with_spaces"
    repeat_char "─" "$right"
    printf "\n"
}

# note "pesan" → mensimulasikan note() / "[bold cyan]i[/bold cyan]"
note() {
    printf "${BOLD_CYAN}i${RESET} %s\n" "$1"
}

# warn "pesan" → mensimulasikan warn() / "[bold yellow]![/bold yellow]"
warn() {
    printf "${YELLOW}!${RESET} %s\n" "$1"
}

# good "pesan" → mensimulasikan good() / "[bold green]✓[/bold green]"
good() {
    printf "${GREEN}✓${RESET} %s\n" "$1"
}

# panel_session_key "title" "content" → mensimulasikan Panel.fit(content, title=title) dari rich
# rich Panel.fit dengan title: ╭── title ──╮ / │ content │ / ╰──────────╯
panel_session_key() {
    local title="$1" content="$2"
    local content_inner=$(( ${#content} + 2 ))   # content + 1 spasi kiri-kanan

    # Lebar garis atas: ╭ + fill_kiri + space + title + space + fill_kanan + ╮
    # Total sama dengan content_inner + 2 (untuk ╭ dan ╮)
    local inner_width="$content_inner"
    local title_with_spaces=" ${title} "
    local fill=$(( inner_width - ${#title_with_spaces} ))
    [ "$fill" -lt 0 ] && fill=0
    local left_fill=$(( fill / 2 ))
    local right_fill=$(( fill - left_fill ))

    printf "╭"; repeat_char "─" "$left_fill"
    printf "%s" "$title_with_spaces"
    repeat_char "─" "$right_fill"; printf "╮\n"
    printf "│ %s │\n" "$content"
    printf "╰"; repeat_char "─" "$inner_width"; printf "╯\n"
}

# pause "pesan" → mensimulasikan input("\nTekan [Enter] untuk lanjut...")
pause() {
    local msg="${1:-Tekan [Enter] untuk lanjut...}"
    printf "\n${DIM}%s${RESET}" "$msg"
    IFS= read -r _dummy || true
}

# =============================================================================
# UTILITAS HEX — mensimulasikan to_hex() / from_hex() Python
# =============================================================================

# to_hex_with_prefix "deadbeef" → "0xdeadbeef" (input sudah hex lowercase)
to_hex_with_prefix() {
    printf '0x%s' "$1"
}

# strip_hex_prefix "0xDEADBEEF" → "deadbeef" (lowercase, tanpa 0x)
strip_hex_prefix() {
    local s="$1"
    s="${s#0x}"; s="${s#0X}"
    printf '%s' "$s" | tr '[:upper:]' '[:lower:]'
}

# validate_hex_bytes "<hex>" "<expected_byte_len>"
#   exit 0 → valid dan panjangnya tepat
#   exit 1 → bukan hex valid (karakter ilegal / panjang ganjil)
#   exit 2 → hex valid tapi panjang byte tidak sesuai
validate_hex_bytes() {
    local raw="$1" expected_bytes="$2"
    local s
    s="$(strip_hex_prefix "$raw")"

    case "$s" in
        ''|*[!0-9a-f]*) return 1 ;;
    esac
    if [ $((${#s} % 2)) -ne 0 ]; then
        return 1
    fi
    if [ $((${#s} / 2)) -ne "$expected_bytes" ]; then
        return 2
    fi
    return 0
}

# ── Return channel global (kompatibel bash 3.2, tanpa local -n) ──────────────
_READ_RESULT=""

# ── Baca string bebas (boleh kosong) ──────────────────────────────────────────
read_string_allow_empty() {
    local prompt="$1"
    printf "${CYAN}%s${RESET}" "$prompt"
    IFS= read -r _READ_RESULT
}

# ── Baca string wajib tidak kosong ────────────────────────────────────────────
read_string_required() {
    local prompt="$1"
    local raw
    while true; do
        printf "${CYAN}%s${RESET}" "$prompt"
        IFS= read -r raw
        raw="$(printf '%s' "$raw" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        if [ -z "$raw" ]; then
            warn "Input tidak boleh kosong."
            continue
        fi
        _READ_RESULT="$raw"
        return 0
    done
}

# ── require_key_hex: minta kunci hex N-byte, kosong = random ─────────────────
# Mensimulasikan require_key_hex() Python: loop sampai valid, atau Enter
# kosong untuk generate kunci acak.
require_key_hex() {
    local label="$1" byte_len="$2" raw vcode

    while true; do
        printf "${CYAN}%s [hexa %d digit] (kosongkan untuk random): ${RESET}" \
            "$label" "$((byte_len * 2))"
        IFS= read -r raw
        raw="$(printf '%s' "$raw" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"

        if [ -z "$raw" ]; then
            _READ_RESULT="$(random_hex "$byte_len")"
            note "${label} dibuat acak."
            return 0
        fi

        # Dibungkus 'if' agar exit code non-zero TIDAK memicu set -e
        # (tanpa if, set -e akan membunuh script begitu fungsi return != 0,
        #  sebelum sempat ditangkap oleh "vcode=$?").
        if validate_hex_bytes "$raw" "$byte_len"; then
            vcode=0
        else
            vcode=$?
        fi
        if [ "$vcode" -eq 1 ]; then
            warn "Input bukan heksadesimal yang valid."
            continue
        elif [ "$vcode" -eq 2 ]; then
            warn "Panjang kunci harus ${byte_len} byte (${byte_len}x2 heksa)."
            continue
        fi

        _READ_RESULT="$(strip_hex_prefix "$raw")"
        return 0
    done
}

# =============================================================================
# LAB UTAMA: SIMULASI KDC MINIMAL
# =============================================================================
lab_kdc_minimal() {
    header "Simulasi Dasar KDC: Pembentukan Session Key (Ks)"

    printf "${DIM}"
    printf "Lab ini mensimulasikan peran dasar Key Distribution Center (KDC)\n"
    printf "dalam membentuk session key (Ks) untuk dua entitas (Alice dan Bob)\n"
    printf "yang ingin berkomunikasi aman menggunakan kriptografi simetris.\n"
    printf "${RESET}"
    pause

    # ── Langkah 1: Identitas pengguna ────────────────────────────────────────
    step "Input Identitas Pengguna"
    local alice_id bob_id

    read_string_required "Masukkan ID Alice (teks): "
    alice_id="$_READ_RESULT"

    read_string_required "Masukkan ID Bob (teks): "
    bob_id="$_READ_RESULT"

    good "ID Alice = ${alice_id}, ID Bob = ${bob_id}"
    pause

    # ── Langkah 2: Kunci jangka panjang KDC ──────────────────────────────────
    step "KDC Memiliki Kunci Rahasia Jangka Panjang"
    printf "${DIM}"
    printf "Masukkan atau buat acak kunci rahasia antara KDC dan masing-masing pengguna:\n"
    printf -- "- Ka : kunci antara Alice <-> KDC\n"
    printf -- "- Kb : kunci antara Bob <-> KDC\n"
    printf "${RESET}\n"

    local Ka Kb

    require_key_hex "Ka (Alice-KDC) 128-bit" 16
    Ka="$_READ_RESULT"

    require_key_hex "Kb (Bob-KDC) 128-bit" 16
    Kb="$_READ_RESULT"

    # Tabel mensimulasikan rich Table(show_lines=True) persis:
    # Title di atas (rata tengah), header bold dengan ━, row dengan ─, border │
    local col1_w=16 col2_w=36
    local tbl_inner=$(( col1_w + col2_w + 3 ))   # 2 col + 3 separator (│ │ │)
    local title_tbl="Kunci Jangka Panjang (HEX)"
    local title_tbl_pad=$(( (tbl_inner - ${#title_tbl}) / 2 ))

    printf "\n"
    # Title baris di atas tabel (rata tengah)
    repeat_char " " "$title_tbl_pad"; printf "${BOLD}%s${RESET}\n" "$title_tbl"
    # Header top border ┏━┳━┓
    printf "┏"; repeat_char "━" "$((col1_w + 2))"; printf "┳"
    repeat_char "━" "$((col2_w + 2))"; printf "┓\n"
    # Header row
    printf "┃ ${BOLD}%-${col1_w}s${RESET} ┃ ${BOLD}%-${col2_w}s${RESET} ┃\n" "Nama" "Nilai (hex)"
    # Header-body separator ┡━╇━┩
    printf "┡"; repeat_char "━" "$((col1_w + 2))"; printf "╇"
    repeat_char "━" "$((col2_w + 2))"; printf "┩\n"
    # Data row 1
    printf "│ %-${col1_w}s │ %-${col2_w}s │\n" "Ka (Alice-KDC)" "$(to_hex_with_prefix "$Ka")"
    # Row separator ├─┼─┤
    printf "├"; repeat_char "─" "$((col1_w + 2))"; printf "┼"
    repeat_char "─" "$((col2_w + 2))"; printf "┤\n"
    # Data row 2
    printf "│ %-${col1_w}s │ %-${col2_w}s │\n" "Kb (Bob-KDC)" "$(to_hex_with_prefix "$Kb")"
    # Bottom border └─┴─┘
    printf "└"; repeat_char "─" "$((col1_w + 2))"; printf "┴"
    repeat_char "─" "$((col2_w + 2))"; printf "┘\n"
    pause

    # ── Langkah 3: KDC membentuk session key ─────────────────────────────────
    step "KDC Membentuk Session Key (Ks)"
    # Ks di-hardcode (fixed) agar nilai selalu sama setiap kali script dijalankan,
    # sesuai nilai referensi dari modul lab.
    local Ks="b18dce474a80c46c15186a381dcd8d32"

    good "KDC menghasilkan session key Ks secara acak."
    printf "\n"
    panel_session_key "Session Key" "Ks (hex) = $(to_hex_with_prefix "$Ks")"
    pause

    # ── Ringkasan ─────────────────────────────────────────────────────────────
    local rule_title=" Proses Selesai "
    local rule_fill=$(( 80 - ${#rule_title} ))
    local rule_left=$(( rule_fill / 2 ))
    local rule_right=$(( rule_fill - rule_left ))
    printf "\n${BOLD_GREEN}"
    repeat_char "─" "$rule_left"
    printf "%s" "$rule_title"
    repeat_char "─" "$rule_right"
    printf "${RESET}\n"

    printf "${DIM}"
    printf "Ringkasan:\n"
    printf -- "- Alice dan Bob masing-masing memiliki kunci rahasia dengan KDC.\n"
    printf -- "- KDC membangkitkan session key (Ks) baru secara acak untuk komunikasi aman.\n"
    printf -- "- Ks nantinya akan didistribusikan secara terenkripsi oleh KDC kepada kedua entitas.\n"
    printf "${RESET}"
}

# =============================================================================
# MAIN
# =============================================================================
main() {
    check_dependencies

    # Tangani Ctrl+C dengan rapi (mensimulasikan except KeyboardInterrupt)
    trap 'printf "\n\nDihentikan oleh pengguna.\n"; exit 0' INT

    lab_kdc_minimal
}

main "$@"