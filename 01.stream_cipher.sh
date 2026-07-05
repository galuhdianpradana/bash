#!/bin/bash

xor_process() {
    local input="$1"
    local key="$2"
    local mode="$3"

    if [[ "$mode" == "decrypt" ]]; then
        # input berupa hex
        input=$(echo "$input" | xxd -r -p)
    fi

    local result=""

    local input_len=${#input}
    local key_len=${#key}

    for ((i=0; i<input_len; i++)); do
        p=$(printf "%d" "'${input:i:1}")
        k=$(printf "%d" "'${key:$((i % key_len)):1}")

        xor=$((p ^ k))

        if [[ "$mode" == "encrypt" ]]; then
            result+=$(printf "%02x" "$xor")
        else
            result+=$(printf "\\$(printf '%03o' "$xor")")
        fi
    done

    echo -ne "$result"
}

echo "=== LAB B: STREAM CIPHER (XOR) ==="

read -rp "🔑 Masukkan kunci (string): " key

echo
echo "1. Enkripsi"
echo "2. Dekripsi"

read -rp "💬 Pilih mode (1/2): " mode

case "$mode" in
1)
    read -rp "📨 Masukkan pesan asli: " plaintext

    cipher=$(xor_process "$plaintext" "$key" encrypt)

    echo
    echo "🧪 Hasil enkripsi:"
    echo "🔑 Hasil (hex): 0x$cipher"
    ;;
2)
    read -rp "🔐 Masukkan cipher (hex): " cipher

    cipher=${cipher#0x}

    if [[ ! "$cipher" =~ ^[0-9a-fA-F]+$ ]]; then
        echo "❌ Input bukan hexadecimal."
        exit 1
    fi

    plain=$(xor_process "$cipher" "$key" decrypt)

    echo
    echo "📬 Hasil dekripsi: $plain"
    ;;
*)
    echo "❌ Mode tidak dikenali."
    ;;
esac