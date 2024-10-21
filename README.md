第一关：基本测试

<img width="116" alt="5eac136d014abad6eb4c498c33467bb4" src="https://github.com/user-attachments/assets/4b50a4f1-cb15-4edc-a6aa-991cb4d41f2d">

输入明文“10101110”，密钥“1101010011”，加密结果“11001010”

<img width="118" alt="d30bc1808852ad7f2f8a44fcd474fb8a" src="https://github.com/user-attachments/assets/4e7b2520-c375-4cf5-afb7-14c7b9cd48a6">


第二关：交叉测试

输入明文“10110100”，密钥“1011010100”，加密结果“00111000”

<img width="138" alt="39aec61049fd076a6a7c8c70cfbe5208" src="https://github.com/user-attachments/assets/621f0076-c71c-4a5d-9010-6cc08630d147">

输入加密结果“00111000”，输入密钥“1011010100”，解密结果“10110100”

<img width="132" alt="f88dabcd9cf85daab269a42b20c341ff" src="https://github.com/user-attachments/assets/a7c5f60c-f084-4b3b-b455-196f1f19f4f4">


第三关：扩展功能

![image](https://github.com/user-attachments/assets/1db5a6bd-f534-4169-b7aa-a7c371c06b85)

![image](https://github.com/user-attachments/assets/df3da4ad-cd33-4471-8f0a-53df2804e827)


第四关：暴力破解

输入“10101010”和“01010101”，输出为“1000000001”

![image](https://github.com/user-attachments/assets/d0ba884b-45f0-487e-bb30-8e65256d8c30)


第五关：封闭测试

在对称加密算法中，由于密钥空间有限，不同密钥可能产生相同的加密结果。理论上来说，任何明文分组与密文分组之间的映射关系，可能对应多个密钥。由于 S-DES 的密钥空间较小，10位的密钥长度产生的可能密钥数为1024，密钥冲突的概率增加。 在暴力破解时，使用明密文对("11100000", "00001110")，求解的可能密钥有:
['1111000010', '1111100010', '1011000010', '1011100010']

密钥空间有限：如果密钥空间较小，可能的密钥数量有限，而明文与密文的组合数量在理论上是固定的。因此，当密钥数量小于密文空间时（即密钥长度较短的算法），必然存在多个密钥可以映射到同一个密文，导致密钥冲突。

![image](https://github.com/user-attachments/assets/ff54a1ac-e869-49b6-a01b-58679d73f98a)
