import time
import os
import random
import hashlib
import chilkat
import bcrypt
import blowfish
from passlib.hash import lmhash
import scrypt
from matplotlib import gridspec
import matplotlib.pyplot as plt
import numpy as np

class Hashman:
    os.environ['PASSLIB_MAX_PASSWORD_SIZE'] = '5100'
    word_sizes = [8, 20, 60, 4000]
    salt_sizes = [8, 8, 16, 96]
    algorythms_fast = ['MD5', 'SHA1', 'SHA256', 'SHA512', 'HAVAL', 'NLTM']
    algorythms_slow = ['BCRYPT', 'SCRYPT', 'BLOWFISH']
    fast_time_saltless = [[], [], [], []]
    fast_time_salt = [[], [], [], []]
    slow_time_saltless = [[], [], [], []]
    slow_time_salt = [[], [], [], []]

    def textGen(self, size=8):
        allowed_symbols = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&()*+,-./:;<=>?@[\]^_`{|}~"
        text = ''
        for i in range(0, size):
            text += random.choice(allowed_symbols)
        return text

    def sequenceGen(self):
        data = []
        for i in range(0, len(self.word_sizes)):
            data.append(self.textGen(self.word_sizes[i]))
            print(data)
        return data

    def saltGen(self):
        salt = []
        for i in range(0, len(self.salt_sizes)):
            salt.append(self.textGen(self.salt_sizes[i]))
            print(salt)
        return salt

    def MD5_saltless(self, i, data):
        start_time = time.time()
        hashlib.md5(str.encode(data))
        end_time = time.time()
        print("MD5:", end_time - start_time, "s")
        self.fast_time_saltless[i].append(end_time - start_time)

    def SHA1_saltless(self, i, data):
        start_time = time.time()
        hashlib.sha1(str.encode(data))
        end_time = time.time()
        print("SHA1:", end_time - start_time, "s")
        self.fast_time_saltless[i].append(end_time - start_time)

    def SHA256_saltless(self, i, data):
        start_time = time.time()
        hashlib.sha256(str.encode(data))
        end_time = time.time()
        print("SHA256:", end_time - start_time, "s")
        self.fast_time_saltless[i].append(end_time - start_time)

    def SHA512_saltless(self, i, data):
        start_time = time.time()
        hashlib.sha512(str.encode(data))
        end_time = time.time()
        print("SHA512:", end_time - start_time, "s")
        self.fast_time_saltless[i].append(end_time - start_time)

    def HAVAL_saltless(self, i, data):
        crypt = chilkat.CkCrypt2()
        crypt.put_HashAlgorithm("haval")
        crypt.put_HavalRounds(5)
        crypt.put_KeyLength(256)

        start_time = time.time()
        crypt.hashStringENC(data)
        end_time = time.time()
        print("HAVAL:", end_time - start_time, "s")
        self.fast_time_saltless[i].append(end_time - start_time)

    def BCRYPT_saltless(self, i, data, salt=''):
        start_time = time.time()
        bcrypt.kdf(
            password=data.encode('utf-16'),
            salt=salt.encode('utf-16'),
            desired_key_bytes=32,
            rounds=100)
        end_time = time.time()
        print("BCRYPT:", end_time - start_time, "s")
        self.slow_time_saltless[i].append(end_time - start_time)

    def SCRYPT_saltless(self, i, data):
        start_time = time.time()
        scrypt.hash(data, '')
        end_time = time.time()
        print("SCRYPT:", end_time - start_time, "s")
        self.slow_time_saltless[i].append(end_time - start_time)

    def NLTM_saltless(self, i, data):
        start_time = time.time()
        lmhash.hash(data)
        end_time = time.time()
        print("NTLM:", end_time - start_time, "s")
        self.fast_time_saltless[i].append(end_time - start_time)

    def BLOWFISH_saltless(self, i, data):
        start_time = time.time()
        cipher = blowfish.Cipher(b"Key must be between 4 and 56 bytes long.")
        cipher.encrypt_ecb_cts(data.encode('utf-16'))
        end_time = time.time()
        print("BLOWFISH:", end_time - start_time, "s")
        self.slow_time_saltless[i].append(end_time - start_time)

    def testing_saltless(self, data):
        print("SALTLESS:")
        for i in range(0, len(data)):
            print("Word length: " + str(self.word_sizes[i]) + " symbols")
            self.MD5_saltless(i, data[i])
            self.SHA1_saltless(i, data[i])
            self.SHA256_saltless(i, data[i])
            self.SHA512_saltless(i, data[i])
            self.HAVAL_saltless(i, data[i])
            self.BCRYPT_saltless(i, data[i])
            self.SCRYPT_saltless(i, data[i])
            self.NLTM_saltless(i, data[i])
            self.BLOWFISH_saltless(i, data[i])
            print('___________________________')

    # with salt
    def MD5_salt(self, i, data, salt):
        start_time = time.time()
        hashlib.md5(str.encode(data + salt))
        end_time = time.time()
        print("MD5:", end_time - start_time, "s")
        self.fast_time_salt[i].append(end_time - start_time)

    def SHA1_salt(self, i, data, salt):
        start_time = time.time()
        hashlib.sha1(str.encode(data + salt))
        end_time = time.time()
        print("SHA1:", end_time - start_time, "s")
        self.fast_time_salt[i].append(end_time - start_time)

    def SHA256_salt(self, i, data, salt):
        start_time = time.time()
        hashlib.sha256(str.encode(data + salt))
        end_time = time.time()
        print("SHA256:", end_time - start_time, "s")
        self.fast_time_salt[i].append(end_time - start_time)

    def SHA512_salt(self, i, data, salt):
        start_time = time.time()
        hashlib.sha512(str.encode(data + salt))
        end_time = time.time()
        print("SHA512:", end_time - start_time, "s")
        self.fast_time_salt[i].append(end_time - start_time)

    def HAVAL_salt(self, i, data, salt):
        crypt = chilkat.CkCrypt2()
        crypt.put_HashAlgorithm("haval")
        crypt.put_HavalRounds(5)
        crypt.put_KeyLength(256)

        start_time = time.time()
        crypt.hashStringENC(data + salt)
        end_time = time.time()
        print("HAVAL:", end_time - start_time, "s")
        self.fast_time_salt[i].append(end_time - start_time)

    def BCRYPT_salt(self, i, data, salt):
        start_time = time.time()
        bcrypt.kdf(
            password=data.encode('utf-16'),
            salt=salt.encode('utf-16'),
            desired_key_bytes=32,
            rounds=100)
        end_time = time.time()
        print("BCRYPT:", end_time - start_time, "s")
        self.slow_time_salt[i].append(end_time - start_time)

    def SCRYPT_salt(self, i, data, salt):
        start_time = time.time()
        scrypt.hash(data, salt)
        end_time = time.time()
        print("SCRYPT:", end_time - start_time, "s")
        self.slow_time_salt[i].append(end_time - start_time)

    def NLTM_salt(self, i, data, salt):
        start_time = time.time()
        key = data + salt
        lmhash.hash(key)
        end_time = time.time()
        print("NTLM:", end_time - start_time, "s")
        self.fast_time_salt[i].append(end_time - start_time)

    def BLOWFISH_salt(self, i, data, salt):
        start_time = time.time()
        key = data + salt
        cipher = blowfish.Cipher(b"Key must be between 4 and 56 bytes long.")
        cipher.encrypt_ecb_cts(key.encode('utf-16'))
        end_time = time.time()
        print("BLOWFISH:", end_time - start_time, "s")
        self.slow_time_salt[i].append(end_time - start_time)

    def testing_salt(self, data, salt):
        print("SALT:")
        for i in range(0, len(data)):
            print("Word length: " + str(self.word_sizes[i]) + " symbols")
            self.MD5_salt(i, data[i], salt[i])
            self.SHA1_salt(i, data[i], salt[i])
            self.SHA256_salt(i, data[i], salt[i])
            self.SHA512_salt(i, data[i], salt[i])
            self.HAVAL_salt(i, data[i], salt[i])
            self.BCRYPT_salt(i, data[i], salt[i])
            self.SCRYPT_salt(i, data[i], salt[i])
            self.NLTM_salt(i, data[i], salt[i])
            self.BLOWFISH_salt(i, data[i], salt[i])
            print('___________________________')

    def visualizer(self):
        for i in range(0, 4):
            barWidth = 0.25

            fig = plt.figure(constrained_layout=True, figsize=(15, 5))
            widths = [3, 2]
            heights = [1]
            spec5 = fig.add_gridspec(ncols=2, nrows=1, width_ratios=widths, height_ratios=heights)

            r1 = np.arange(len(self.fast_time_salt[0]))
            r2 = [x + barWidth for x in r1]
            ax1 = fig.add_subplot(spec5[0, 0])
            ax1.bar(r1, self.fast_time_salt[i], color='blue', width=barWidth, edgecolor='white', label='With salt')
            ax1.bar(r2, self.fast_time_saltless[i], color='green', width=barWidth, edgecolor='white', label='Without salt')
            ax1.set_xticks(range(6))
            ax1.set_xticklabels(self.algorythms_fast, fontsize=12)

            r1 = np.arange(len(self.slow_time_salt[0]))
            r2 = [x + barWidth for x in r1]
            ax2 = fig.add_subplot(spec5[0, 1])
            ax2.bar(r1, self.slow_time_salt[i], color='blue', width=barWidth, edgecolor='white', label='With salt')
            ax2.bar(r2, self.slow_time_saltless[i], color='green', width=barWidth, edgecolor='white', label='Without salt')
            ax2.set_xticks(range(3))
            ax2.set_xticklabels(self.algorythms_slow, fontsize=12)

            fig.suptitle("Word size is " + str(self.word_sizes[i]) + " letters", fontsize=16)
            plt.legend()
            plt.show()


def main():
    Hm = Hashman()
    data = Hm.sequenceGen()
    salt = Hm.saltGen()
    Hm.testing_saltless(data)
    Hm.testing_salt(data, salt)
    Hm.visualizer()


if __name__ == '__main__':
    main()
