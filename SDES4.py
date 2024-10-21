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
            x = (x << 1) | ((a >> (c - b[i])) & 1)
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
        # 这里需要将lk和rk左移一位，然后再进行压缩置换
        lk = (lk << 1) | ((lk & 0x10) >> 4)
        rk = (rk << 1) | ((rk & 0x10) >> 4)
        self.x1 = self.fx1((lk << 5) | rk, self.P8, 10)
        # 这里需要将lk和rk进行扩展置换，然后再进行压缩置换
        lk = (lk & 0x1e) | ((lk & 0x01) << 1)
        rk = (rk & 0x1e) | ((rk & 0x01) << 1)
        self.x2 = self.fx1((lk << 5) | rk, self.P8, 10)

    def decrypt_byte(self, byte, key):
        self.DES(key)
        temp = int(byte, 2)
        temp = self.fx1(temp, self.IP, 8)
        temp = self.fx2(temp, self.x2)
        temp = ((temp & 0xf) << 4) | ((temp >> 4) & 0xf)
        temp = self.fx2(temp, self.x1)
        return format(self.fx1(temp, self.IP_1, 8), '08b')

    def check_key(self, key, encrypted_byte, expected_byte):
        decrypted_byte = self.decrypt_byte(encrypted_byte, key)
        print(f"Testing key: {key}, decrypted: {decrypted_byte}, expected: {expected_byte}")
        return decrypted_byte == expected_byte


def brute_force_decrypt(encrypted_byte, expected_byte, key_range):
    sdes = SDES()
    for i in key_range:
        key = format(i, '010b')
        if sdes.check_key(key, encrypted_byte, expected_byte):
            print(f"Found key: {key}")
            return key
    print("Key not found")
    return None


if __name__ == "__main__":
    try:
        encrypted_byte = input("Enter the encrypted byte (8-bit binary): ")
        expected_byte = input("Enter the expected decrypted byte (8-bit binary): ")
        if len(encrypted_byte) != 8 or len(expected_byte) != 8 or not set(encrypted_byte).issubset(
                {'0', '1'}) or not set(expected_byte).issubset({'0', '1'}):
            raise ValueError("Invalid input. Please enter valid 8-bit binary strings.")

        start_time = time.time()

        # Create threads for brute force
        threads = []
        num_threads = 4
        keys_per_thread = 1024 // num_threads

        for i in range(num_threads):
            key_range = range(i * keys_per_thread, (i + 1) * keys_per_thread)
            thread = threading.Thread(target=brute_force_decrypt, args=(encrypted_byte, expected_byte, key_range))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        end_time = time.time()
        print(f"Brute force completed in {end_time - start_time:.2f} seconds.")
    except ValueError as e:
        print(e)
