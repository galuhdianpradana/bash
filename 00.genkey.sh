#!/bin/bash

adjust_key_hex() {
    local input="$1"
    local target_len="$2"

    # Ubah ke hex
    local hex
    hex=$(printf "%s" "$input" | xxd -p -c 256)

    local target_hex_len=$((target_len * 2))
    local current_hex_len=${#hex}

    if (( current_hex_len < target_hex_len )); then
        while (( ${#hex} < target_hex_len )); do
            hex="${hex}00"
        done
    elif (( current_hex_len > target_hex_len )); then
        hex=${hex:0:$target_hex_len}
    fi

    echo "$hex"
}

echo "=== LAB A: PEMBANGKITAN KUNCI SIMETRIS ==="
echo

read -rp "🔤 Masukkan string sebagai kunci: " key

length=$(printf "%s" "$key" | wc -c)

echo "🧠 Panjang string: $length byte"
echo
echo "📏 Pilih panjang kunci (bit):"
echo "1. 64-bit (8 byte)"
echo "2. 128-bit (16 byte)"

read -rp "💬 Pilihan (1/2): " pilihan

case "$pilihan" in
    1)
        target=8
        ;;
    2)
        target=16
        ;;
    *)
        echo "❌ Pilihan tidak valid."
        exit 1
        ;;
esac

hasil=$(adjust_key_hex "$key" "$target")

echo
echo "🔑 Kunci hasil (hex): 0x$hasil"