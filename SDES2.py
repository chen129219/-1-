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

    def decrypt(self, ciphertext):
        # 解密过程与加密过程相反
        temp = int(ciphertext, 2)
        temp = self.fx1(temp, self.IP, 8)
        temp = self.fx2(temp, self.x2)  # 使用第二个子密钥
        temp = ((temp & 0xf) << 4) | ((temp >> 4) & 0xf)
        temp = self.fx2(temp, self.x1)  # 使用第一个子密钥
        return self.fx1(temp, self.IP_1, 8)


if __name__ == "__main__":
    sdes = SDES()

    # 加密
    key = input("Enter 10-bit key: ")
    plaintext = input("Enter 8-bit plaintext: ")
    sdes.DES(key)
    encrypted_temp = int(plaintext, 2)
    encrypted_temp = sdes.fx1(encrypted_temp, sdes.IP, 8)
    encrypted_temp = sdes.fx2(encrypted_temp, sdes.x1)
    encrypted_temp = ((encrypted_temp & 0xf) << 4) | ((encrypted_temp >> 4) & 0xf)
    encrypted_temp = sdes.fx2(encrypted_temp, sdes.x2)
    ciphertext = sdes.fx1(encrypted_temp, sdes.IP_1, 8)
    encrypted_text = bin(ciphertext)[2:].zfill(8)
    print(f"Ciphertext: {encrypted_text}")

    # 解密
    decrypted_temp = sdes.decrypt(encrypted_text)
    decrypted_text = bin(decrypted_temp)[2:].zfill(8)
    print(f"Decrypted plaintext: {decrypted_text}")
