import random
import os

def is_prime(n):
    if n <= 1:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True

def generate_prime(bits):
    while True:
        num = random.getrandbits(bits)
        if is_prime(num):
            return num

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def mod_inverse(e, phi):
    def egcd(a, b):
        if a == 0:
            return b, 0, 1
        g, x1, y1 = egcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return g, x, y

    g, x, _ = egcd(e, phi)
    if g != 1:
        raise ValueError("No modular inverse exists")
    return x % phi

class RSA:
    def __init__(self, id):
        self.id = id
        self.keys = self.generate_rsa_keys()
        self.store_keys()

    def generate_rsa_keys(self, bits=16):
        p = generate_prime(bits)
        q = generate_prime(bits)
        n = p * q
        phi = (p - 1) * (q - 1)

        e = random.randint(2, phi - 1)
        while gcd(e, phi) != 1:
            e = random.randint(2, phi - 1)

        d = mod_inverse(e, phi)

        return {"public_key": (e, n), "private_key": (d, n)}

    def encrypt(self, message, key=None):
        if key is None:
            e, n = self.keys["public_key"]
        else:
            e, n = key

        cipher = [pow(ord(char), e, n) for char in message]
        cipher_text = ' '.join(map(str, cipher))
        return cipher_text

    def decrypt(self, ciphertext, key=None):
        if key is None:
            d, n = self.keys["private_key"]
        else:
            d, n = key

        cipher = list(map(int, ciphertext.split()))
        plaintext = ''.join([chr(pow(char, d, n)) for char in cipher])
        return plaintext

    def store_keys(self):
        dir = os.path.dirname(__file__)
        public_key_path = os.path.join(dir, f"keys/public/{self.id}.pem")
        private_key_path = os.path.join(dir, f"keys/private/{self.id}.pem")

        with open(public_key_path, "w") as f:
            f.write(f"{self.keys['public_key'][0]},{self.keys['public_key'][1]}")

        with open(private_key_path, "w") as f:
            f.write(f"{self.keys['private_key'][0]},{self.keys['private_key'][1]}")

if __name__ == "__main__":
    rsa = RSA("initiator")
    print("ID:", rsa.id)
    print("Keys:", rsa.keys)
    message = "keyganmk"
    print("Original message:", message)

    encrypted = rsa.encrypt(message, rsa.keys["public_key"])
    print("Encrypted message:", encrypted)

    decrypted = rsa.decrypt(encrypted, rsa.keys["private_key"])
    print("Decrypted message:", decrypted)