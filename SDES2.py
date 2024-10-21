import sys
from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QHBoxLayout

# S-DES 帮助函数
def permute(bits, table):
    # 根据置换表对位进行排列
    return [bits[i] for i in table]

def left_shift(bits, shift):
    # 对位进行左移
    return bits[shift:] + bits[:shift]

def key_schedule(key):
    # 定义置换表 P10 和 P8 以及左移位数
    P10 = [2, 4, 1, 6, 3, 9, 0, 8, 7, 5]
    P8  = [5, 2, 6, 3, 7, 4, 9, 8]
    LS1 = 1
    LS2 = 2

    # 对密钥进行置换
    key = permute(key, P10)
    left, right = key[:5], key[5:]

    # 生成第一个子密钥
    left = left_shift(left, LS1)
    right = left_shift(right, LS1)
    key1 = permute(left + right, P8)

    # 生成第二个子密钥
    left = left_shift(left, LS2)
    right = left_shift(right, LS2)
    key2 = permute(left + right, P8)

    return key1, key2

def fk(bits, subkey):
    # 定义扩展置换表，P4 和 S-盒子
    EXPANSION_PERMUTATION = [3, 0, 1, 2, 1, 2, 3, 0]
    P4 = [1, 3, 2, 0]
    S0 = [[1, 0, 3, 2], [3, 2, 1, 0], [0, 2, 1, 3], [3, 1, 3, 2]]
    S1 = [[0, 1, 2, 3], [2, 0, 1, 3], [3, 0, 1, 0], [2, 1, 0, 3]]

    # 分为左右两部分
    left, right = bits[:4], bits[4:]
    right_expanded = permute(right, EXPANSION_PERMUTATION)

    # 与子密钥进行异或
    xor_res = [a ^ b for a, b in zip(right_expanded, subkey)]

    # 计算 S-盒子的行和列
    row1 = (xor_res[0] << 1) | xor_res[3]
    col1 = (xor_res[1] << 1) | xor_res[2]
    row2 = (xor_res[4] << 1) | xor_res[7]
    col2 = (xor_res[5] << 1) | xor_res[6]

    # 从 S-盒子中获取值
    left_sbox = S0[row1][col1]
    right_sbox = S1[row2][col2]

    # S-盒结果
    sbox_result = [(left_sbox >> 1) & 1, left_sbox & 1, (right_sbox >> 1) & 1, right_sbox & 1]

    # 返回左部与 P4 置换结果的异或，后面跟随原右部
    return [a ^ b for a, b in zip(left, permute(sbox_result, P4))] + right

def sdes_encrypt(plain_text, key):
    # 定义初始和逆初始置换表
    IP = [1, 5, 2, 0, 3, 7, 4, 6]
    IP_INV = [3, 0, 2, 4, 6, 1, 7, 5]

    # 生成子密钥
    key1, key2 = key_schedule(key)

    # 初始置换
    data = permute(plain_text, IP)

    # 第一轮
    data = fk(data, key1)
    data = data[4:] + data[:4]  # 交换左右部分

    # 第二轮
    data = fk(data, key2)

    # 逆初始置换，得到密文
    return permute(data, IP_INV)

def sdes_decrypt(cipher_text, key):
    # 定义初始和逆初始置换表
    IP = [1, 5, 2, 0, 3, 7, 4, 6]
    IP_INV = [3, 0, 2, 4, 6, 1, 7, 5]

    # 生成子密钥
    key1, key2 = key_schedule(key)

    # 初始置换
    data = permute(cipher_text, IP)

    # 第一轮（子密钥顺序相反）
    data = fk(data, key2)
    data = data[4:] + data[:4]  # 交换左右部分

    # 第二轮
    data = fk(data, key1)

    # 逆初始置换，得到明文
    return permute(data, IP_INV)

# PyQt5 Application
class SDESApp(QWidget):
    def __init__(self):
        super().__init__()

        self.initUI()

    def initUI(self):
        self.setWindowTitle('S-DES Encryptor/Decryptor')

        # Create widgets
        self.plain_text_label = QLabel('Plain Text (8-bits):')
        self.plain_text_input = QLineEdit(self)

        self.key_label = QLabel('Key (10-bits):')
        self.key_input = QLineEdit(self)

        self.result_label = QLabel('Result:')
        self.result_output = QLineEdit(self)
        self.result_output.setReadOnly(True)

        self.encrypt_button = QPushButton('加密', self)
        self.encrypt_button.clicked.connect(self.encrypt)
        self.decrypt_button = QPushButton('解密', self)
        self.decrypt_button.clicked.connect(self.decrypt)

        # Layout setup
        vbox = QVBoxLayout()
        vbox.addWidget(self.plain_text_label)
        vbox.addWidget(self.plain_text_input)
        vbox.addWidget(self.key_label)
        vbox.addWidget(self.key_input)

        hbox = QHBoxLayout()
        hbox.addWidget(self.encrypt_button)
        hbox.addWidget(self.decrypt_button)

        vbox.addLayout(hbox)
        vbox.addWidget(self.result_label)
        vbox.addWidget(self.result_output)

        self.setLayout(vbox)
        self.show()

    def encrypt(self):
        try:
            plain_text = list(map(int, self.plain_text_input.text().strip()))
            key = list(map(int, self.key_input.text().strip()))
            cipher_text = sdes_encrypt(plain_text, key)
            self.result_output.setText(''.join(map(str, cipher_text)))
        except Exception as e:
            self.result_output.setText("Error")

    def decrypt(self):
        try:
            cipher_text = list(map(int, self.plain_text_input.text().strip()))
            key = list(map(int, self.key_input.text().strip()))
            deciphered_text = sdes_decrypt(cipher_text, key)
            self.result_output.setText(''.join(map(str, deciphered_text)))
        except Exception as e:
            self.result_output.setText("Error")

# Run the application
if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = SDESApp()
    sys.exit(app.exec_())

