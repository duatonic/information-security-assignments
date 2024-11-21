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
        return {"src": self.src, "dst": self.dst}

class HandshakePacket:
    def __init__(self, id, nonce):
        self.id = id
        self.nonce = nonce

    def to_json(self):
        return {"id": self.id, "nonce": self.nonce}

class Responder:
    def __init__(self, id, des_key, pka_host='localhost', pka_port=11999, host='localhost', port=12001):
        self.id = id
        self.des_key = des_key
        self.rsa = RSA(self.id)
        self.keys = self.rsa.keys
        self.public_keys = {}
        self.pka_host = pka_host
        self.pka_port = pka_port
        self.host = host
        self.port = port

    def get_pka_public_key(self):
        dir = os.path.dirname(__file__)
        filename = os.path.join(dir, "keys/public/pka.pem")
        with open(filename) as f:
            self.public_keys["pka"] = tuple(map(int, f.read().split(",")))

    def generate_nonce(self):
        return random.randint(1000, 9999)

    def get_initiator_public_key(self, target_id):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.pka_host, self.pka_port))
            self.get_pka_public_key()

            request = Request(self.id, target_id)
            s.sendall(json.dumps(request.to_json()).encode())

            response = s.recv(1024).decode()
            ciphertext = json.loads(response)

            decrypted_response = self.rsa.decrypt(ciphertext, self.public_keys["pka"])

        return eval(json.loads(decrypted_response))

    def handle_handshake_and_exchange(self, conn):
        try:
            # Step 1: Receive and decrypt handshake packet
            encrypted_handshake = conn.recv(1024).decode()
            handshake_packet = eval(self.rsa.decrypt(json.loads(encrypted_handshake)))
            initiator_id = handshake_packet["id"]
            initiator_nonce = handshake_packet["nonce"]

            # Step 2: Retrieve Initiator's public key from PKA
            initiator_public_key = self.get_initiator_public_key(initiator_id)
            if initiator_public_key['status'] == "error":
                print("Failed to retrieve Responder's public key from PKA")
                return
            else:
                self.public_keys["initiator"] = initiator_public_key['message']

            responder_nonce = self.generate_nonce()

            # Step 3: Send handshake response
            combined_nonce = f"{initiator_nonce}{responder_nonce}"

            response_packet = HandshakePacket(self.id, combined_nonce)
            encrypted_response = self.rsa.encrypt(json.dumps(response_packet.to_json()), self.public_keys["initiator"])

            conn.sendall(json.dumps(encrypted_response).encode())

            encrypted_nonce = conn.recv(1024).decode()
            ciphertext = eval(self.rsa.decrypt(json.loads(encrypted_nonce)))
            decrypted_nonce = ciphertext["nonce"]

            if responder_nonce != int(decrypted_nonce):
                print("Handshake failed: Nonces do not match")
                return
            print("Handshake successful!")

            # Step 4: Receive encrypted DES key and message
            encrypted_data = conn.recv(1024).decode()
            print(f"Received encrypted data: {encrypted_data}")
            encrypted_cipherkey = self.rsa.decrypt(encrypted_data)
            print(f"Decrypted DES key: {encrypted_cipherkey}")
            decrypted_des_key = self.rsa.decrypt(encrypted_cipherkey, self.public_keys["initiator"])
            print(f"Final decrypted DES key: {decrypted_des_key}")

            des = DES(decrypted_des_key)
            encrypted_message = conn.recv(1024).decode()
            print(f"Received encrypted message: {encrypted_message}")
            decrypted_message = des.decrypt(encrypted_message)
            print(f"Decrypted message: {decrypted_message}")

            # Step 7: Reply to Initiator using DES
            reply_message = input("Enter reply message: ")
            des_encrypted_reply = des.encrypt(reply_message)
            conn.sendall(des_encrypted_reply.encode())
            
        except Exception as e:
            print(f"Error handling connection: {e}")
        finally:
            conn.close()

    def start_server(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)
        print(f"Responder is running on {self.host}:{self.port}")
        print(f"Responder public key: {self.keys['public_key']}")

        while True:
            conn, addr = server_socket.accept()
            print(f"Connection received from {addr}")
            self.handle_handshake_and_exchange(conn)

# Example Usage
if __name__ == "__main__":
    des_key = "response"  # Example DES key (must be 8 bytes)
    des = DES(des_key)
    responder = Responder("responder", des_key)

    responder.start_server()