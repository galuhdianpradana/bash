from Crypto.Random import get_random_bytes  # Masih disertakan kalau mau dipakai nanti

def adjust_key_length(key: bytes, target_len: int) -> bytes:
    """Mengubah panjang kunci menjadi sesuai dengan panjang target."""
    if len(key) < target_len:
        return key.ljust(target_len, b'\x00')
    elif len(key) > target_len:
        return key[:target_len]
    return key

def input_and_adjust_string():
    """Meminta input kunci string dari pengguna dan mengubah panjangnya sesuai pilihan."""
    s = input("🔤 Masukkan string sebagai kunci: ").strip()
    raw_key = s.encode()
    print(f"🧠 Panjang string: {len(raw_key)} byte")

    print("\n📏 Pilih panjang kunci (bit):")
    print("1. 64-bit (8 byte)")
    print("2. 128-bit (16 byte)")
    size_choice = input("💬 Pilihan (1/2): ").strip()

    if size_choice == "1":
        target_len = 8
    elif size_choice == "2":
        target_len = 16
    else:
        print("❌ Pilihan tidak valid.")
        return None

    adjusted_key = adjust_key_length(raw_key, target_len)
    print(f"\n🔑 Kunci hasil (hex): 0x{adjusted_key.hex()}")
    return adjusted_key

if __name__ == "__main__":
    print("=== LAB A: PEMBANGKITAN KUNCI SIMETRIS ===\n")
    key = input_and_adjust_string()

