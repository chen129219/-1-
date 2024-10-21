 import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton

def permute(original, permutation):
    # 对原始列表进行排列
    return [original[i - 1] for i in permutation]

def left_shift(bits, n):
    # 将 bits 列表左移 n 位
    return bits[n:] + bits[:n]

def generate_keys(key):
    # 定义 P10 和 P8 排列
    p10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
    p8 = [6, 3, 7, 4, 8, 5, 10, 9]

    # 通过 P10 对密钥进行置换
    key = permute(key, p10)

    # 将密钥分为左右两部分并左移
    left, right = key[:5], key[5:]
    left = left_shift(left, 1)
    right = left_shift(right, 1)
    key1 = permute(left + right, p8)  # 生成第一个子密钥

    # 再次左移
    left = left_shift(left, 2)
    right = left_shift(right, 2)
    key2 = permute(left + right, p8)  # 生成第二个子密钥

    return key1, key2

def sbox_lookup(bits, sbox):
    # 通过 S-盒子查找，计算行和列索引
    row = (bits[0] << 1) | bits[3]
    col = (bits[1] << 1) | bits[2]
    return sbox[row][col]

def f_k(bits, key):
    # 定义扩展置换表和 S-盒子
    ep = [4, 1, 2, 3, 2, 3, 4, 1]
    sbox1 = [[1, 0, 3, 2], [3, 2, 1, 0], [0, 2, 1, 3], [3, 1, 0, 2]]
    sbox2 = [[0, 1, 2, 3], [2, 3, 1, 0], [3, 0, 1, 2], [2, 1, 0, 3]]

    # 对位进行扩展置换
    expanded_bits = permute(bits, ep)
    xored = [b ^ k for b, k in zip(expanded_bits, key)]  # 进行异或操作

    # S-盒子查找
    s0 = sbox_lookup(xored[:4], sbox1)
    s1 = sbox_lookup(xored[4:], sbox2)

    # 组合和置换
    sp = (s0 << 2) | s1
    sp = [(sp >> i) & 1 for i in reversed(range(4))]

    p4 = [2, 4, 3, 1]  # P4置换表
    return permute(sp, p4)

def switch_halves(bits):
    # 交换左右半部分
    return bits[4:] + bits[:4]

def sdes_encrypt(plain_text, key):
    # 定义初始置换和逆初始置换
    ip = [2, 6, 3, 1, 4, 8, 5, 7]
    inverse_ip = [4, 1, 3, 5, 7, 2, 8, 6]

    # 生成两个子密钥
    key1, key2 = generate_keys(key)

    # 初始置换
    bits = permute(plain_text, ip)

    # 第一次轮运算
    left, right = bits[:4], bits[4:]
    f_result = f_k(right, key1)  # 使用第一个子密钥
    left = [l ^ f for l, f in zip(left, f_result)]

    # 交换和第二次轮运算
    bits = switch_halves(left + right)
    left, right = bits[:4], bits[4:]
    f_result = f_k(right, key2)  # 使用第二个子密钥
    left = [l ^ f for l, f in zip(left, f_result)]

    # 逆初始置换
    cipher_text = permute(left + right, inverse_ip)
    return cipher_text

def sdes_decrypt(cipher_text, key):
    # 解密过程，通过交换子密钥进行轮运算
    ip = [2, 6, 3, 1, 4, 8, 5, 7]
    inverse_ip = [4, 1, 3, 5, 7, 2, 8, 6]

    key1, key2 = generate_keys(key)

    # 初始置换
    bits = permute(cipher_text, ip)

    # 第一次轮运算（使用第二个子密钥）
    left, right = bits[:4], bits[4:]
    f_result = f_k(right, key2)
    left = [l ^ f for l, f in zip(left, f_result)]

    # 交换和第二次轮运算（使用第一个子密钥）
    bits = switch_halves(left + right)
    left, right = bits[:4], bits[4:]
    f_result = f_k(right, key1)
    left = [l ^ f for l, f in zip(left, f_result)]

    # 逆初始置换
    plain_text = permute(left + right, inverse_ip)
    return plain_text

class SDESTool(QWidget):
    def __init__(self):
        super().__init__()

        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()

        self.plain_text_label = QLabel("Plain Text (8-bit):")
        self.plain_text_input = QLineEdit()
        layout.addWidget(self.plain_text_label)
        layout.addWidget(self.plain_text_input)

        self.key_label = QLabel("Key (10-bit):")
        self.key_input = QLineEdit()
        layout.addWidget(self.key_label)
        layout.addWidget(self.key_input)

        self.encrypt_button = QPushButton("Encrypt")
        self.encrypt_button.clicked.connect(self.encrypt)
        layout.addWidget(self.encrypt_button)

        self.cipher_text_label = QLabel("Cipher Text (8-bit):")
        self.cipher_text_output = QLabel("")
        layout.addWidget(self.cipher_text_label)
        layout.addWidget(self.cipher_text_output)

        self.setLayout(layout)
        self.setWindowTitle('S-DES Tool')
        self.show()

    def encrypt(self):
        plain_text = list(map(int, self.plain_text_input.text()))
        key = list(map(int, self.key_input.text()))

        cipher_text = sdes_encrypt(plain_text, key)
        self.cipher_text_output.setText(''.join(map(str, cipher_text)))

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = SDESTool()
    sys.exit(app.exec_())
