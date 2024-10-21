import threading
import time

class SDES:
    P4 = [2, 4, 3, 1]
    P8 = [6, 3, 7, 4, 8, 5, 10, 9]
    P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
    IP = [2, 6, 3, 1, 4, 8, 5, 7]
    IP_1 = [4, 1, 3, 5, 7, 2, 8, 6]
    EP = [4, 1, 2, 3, 2, 3, 4, 1]
    S1 = [[1, 0, 3, 2], [3, 2, 1, 0], [0, 2, 1, 3], [3, 1, 3, 2]]
    S2 = [[0, 1, 2, 3], [2, 0, 1, 3], [3, 0, 1, 0], [2, 1, 0, 3]]

    def fx1(self, a, b, c):
        x = 0
        for i in range(len(b)):
            x <<= 1
            x |= (a >> (c - b[i])) & 1
        return x

    def EP_func(self, a, b):
        t = self.fx1(a, self.EP, 4) ^ b
        t0 = (t >> 4) & 0xf
        t1 = t & 0xf
        x1 = ((t0 & 0x8) >> 2) | (t0 & 1)
        y1 = (t0 >> 1) & 0x3
        x2 = ((t1 & 0x8) >> 2) | (t1 & 1)
        y2 = (t1 >> 1) & 0x3
        t0 = self.S1[x1][y1]
        t1 = self.S2[x2][y2]
        return self.fx1((t0 << 2) | t1, self.P4, 4)

    def fx2(self, a, b):
        l = (a >> 4) & 0xf
        r = a & 0xf
        return ((l ^ self.EP_func(r, b)) << 4) | r

    def DES(self, key):
        x = int(key, 2)
        x = self.fx1(x, self.P10, 10)
        lk = (x >> 5) & 0x1f
        rk = x & 0x1f
        lk = ((lk & 0xf) << 1) | ((lk & 0x10) >> 4)
        rk = ((rk & 0xf) << 1) | ((rk & 0x10) >> 4)
        self.x1 = self.fx1((lk << 5) | rk, self.P8, 10)
        lk = ((lk & 0x07) << 2) | ((lk & 0x18) >> 3)
        rk = ((rk & 0x07) << 2) | ((rk & 0x18) >> 3)
        self.x2 = self.fx1((lk << 5) | rk, self.P8, 10)

    def encrypt_byte(self, byte, key):
        self.DES(key)
        temp = int(byte, 2)
        temp = self.fx1(temp, self.IP, 8)
        temp = self.fx2(temp, self.x1)
        temp = ((temp & 0xf) << 4) | ((temp >> 4) & 0xf)
        temp = self.fx2(temp, self.x2)
        return self.fx1(temp, self.IP_1, 8)

    def decrypt_byte(self, byte, key):
        self.DES(key)
        temp = int(byte, 2)
        temp = self.fx1(temp, self.IP, 8)
        temp = self.fx2(temp, self.x2)
        temp = ((temp & 0xf) << 4) | ((temp >> 4) & 0xf)
        temp = self.fx2(temp, self.x1)
        return self.fx1(temp, self.IP_1, 8)

    def check_key(self, key, encrypted_byte, expected_byte):
        decrypted_byte = self.decrypt_byte(encrypted_byte, key)
        return decrypted_byte == expected_byte

def brute_force_decrypt(encrypted_byte, expected_byte, key_range):
    sdes = SDES()
    keys_found = []
    for i in key_range:
        key = format(i, '010b')
        if sdes.check_key(key, encrypted_byte, expected_byte):
            keys_found.append(key)
    return keys_found

def analyze_duplicate_keys(encrypted_byte, expected_byte):
    sdes = SDES()
    key_map = {}
    duplicate_keys = {}

    for i in range(1024):  # 2^10 possible keys
        key = format(i, '010b')
        cipher_text = sdes.encrypt_byte(expected_byte, key)

        if cipher_text in key_map:
            if cipher_text not in duplicate_keys:
                duplicate_keys[cipher_text] = [key_map[cipher_text]]
            duplicate_keys[cipher_text].append(key)
        else:
            key_map[cipher_text] = key

    return duplicate_keys

if __name__ == "__main__":
    encrypted_byte = input("Enter the encrypted byte (8-bit binary): ")
    expected_byte = input("Enter the expected decrypted byte (8-bit binary): ")

    # 检查输入有效性
    if len(encrypted_byte) != 8 or len(expected_byte) != 8 or not (set(encrypted_byte) <= {'0', '1'}) or not (set(expected_byte) <= {'0', '1'}):
        print("Invalid input. Please enter valid 8-bit binary strings.")
    else:
        start_time = time.time()

        # Create threads for brute force
        threads = []
        num_threads = 4
        keys_per_thread = 1024 // num_threads
        keys_found = []

        for i in range(num_threads):
            key_range = range(i * keys_per_thread, (i + 1) * keys_per_thread)
            thread = threading.Thread(target=lambda k=key_range: keys_found.extend(brute_force_decrypt(encrypted_byte, expected_byte, k)))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        end_time = time.time()
        print(f"Brute force completed in {end_time - start_time:.2f} seconds.")

        # 分析重复密钥
        duplicate_keys = analyze_duplicate_keys(encrypted_byte, expected_byte)

        if duplicate_keys:
            print("Found duplicate keys producing the same ciphertext:")
            for cipher_text, keys in duplicate_keys.items():
                print(f"Ciphertext: {cipher_text} -> Keys: {', '.join(keys)}")
        else:
            print("No duplicate keys found for this plaintext.")
