import socket
import random
import json
import os
from RSA import RSA
from des import DES

class Request:
    def __init__(self, id, dst):
        self.src = id
        self.dst = dst

    def to_json(self):
        return { "src": self.src, "dst": self.dst }

class HandshakePacket:
    def __init__(self, id, nonce):
        self.id = id
        self.nonce = nonce

    def to_json(self):
        return { "id": self.id, "nonce": self.nonce }

class Initiator:
    def __init__(self, id, des_key, pka_host='localhost', pka_port=11999, responder_host='localhost', responder_port=12001):
        self.id = id
        self.des_key = des_key
        self.rsa = RSA(self.id)
        self.keys = self.rsa.keys
        self.public_keys = {}
        self.pka_host = pka_host
        self.pka_port = pka_port
        self.responder_host = responder_host
        self.responder_port = responder_port

    def get_pka_public_key(self):
        dir = os.path.dirname(__file__)
        filename = os.path.join(dir, "keys/public/pka.pem")
        with open(filename) as f:
            self.public_keys["pka"] = tuple(map(int, f.read().split(",")))

    def generate_nonce(self):
        return random.randint(1000, 9999)

    def get_responder_public_key(self, target_id):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.pka_host, self.pka_port))
            self.get_pka_public_key()

            request = Request(self.id, target_id)
            s.sendall(json.dumps(request.to_json()).encode())

            response = s.recv(1024).decode()
            ciphertext = json.loads(response)

            decrypted_response = self.rsa.decrypt(ciphertext, self.public_keys["pka"])

        return eval(json.loads(decrypted_response))

    def initiate_handshake_and_exchange(self):
        # Step 1: Retrieve Responder's public key from PKA
        responder_public_key = self.get_responder_public_key("responder")
        if responder_public_key['status'] == "error":
            print("Failed to retrieve Responder's public key from PKA")
            return
        else:
            self.public_keys["responder"] = responder_public_key['message']
        
        nonce = self.generate_nonce()
        print(f"Generated nonce: {nonce}")

        # Step 2: Send handshake packet to Responder

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.responder_host, self.responder_port))

            handshake_packet = HandshakePacket(self.id, nonce)
            encrypted_handshake = self.rsa.encrypt(json.dumps(handshake_packet.to_json()), self.public_keys["responder"])
            s.sendall(json.dumps(encrypted_handshake).encode())

            # Step 3: Receive and verify handshake response
            response = s.recv(1024).decode()
            ciphertext = json.loads(response)

            decrypted_response = eval(self.rsa.decrypt(ciphertext))
            print(f"Received response: {decrypted_response}")

            combined_nonce = decrypted_response['nonce']
            if str(nonce) not in combined_nonce:
                print("Handshake failed!")
                return
            else:
                responder_nonce = combined_nonce[len(combined_nonce)//2:]
                handshake_back = HandshakePacket(self.id, responder_nonce)
                encrypted_handshake_back = self.rsa.encrypt(json.dumps(handshake_back.to_json()), self.public_keys["responder"])
                s.sendall(json.dumps(encrypted_handshake_back).encode())

            print("Handshake successful!")

            # Step 4: Send DES-encrypted message to Responder
            des = DES(self.des_key)
            
            cipherkey = self.rsa.encrypt(self.des_key, self.keys["private_key"])
            encrypted_des_key = self.rsa.encrypt(cipherkey, self.public_keys["responder"])
            s.sendall(encrypted_des_key.encode())

            message = input("Enter message to send: ")
            des_encrypted_message = des.encrypt(message)
            s.sendall(des_encrypted_message.encode())

            # Step 5: Receive DES-encrypted reply
            des_reply = s.recv(1024).decode()
            decrypted_reply = des.decrypt(des_reply)
            print(f"Responder replied: {decrypted_reply}")

# Example Usage
if __name__ == "__main__":
    des_key = "keyganmk"  # Example DES key (must be 8 bytes)
    initiator = Initiator("initiator", des_key)

    initiator.initiate_handshake_and_exchange()