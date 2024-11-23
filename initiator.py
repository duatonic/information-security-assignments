import socket
import random
import json
import os
import threading
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
    
    def handle_handshake(self, client):
        try:
            nonce = self.generate_nonce()

            handshake_packet = HandshakePacket(self.id, nonce)

            encrypted_handshake = self.rsa.encrypt(json.dumps(handshake_packet.to_json()), self.public_keys["responder"])
            client.sendall(json.dumps(encrypted_handshake).encode())

            response = client.recv(1024).decode()
            cipher_response = json.loads(response)

            decrypted_response = eval(self.rsa.decrypt(cipher_response))

            combined_nonce = decrypted_response['nonce']
            if str(nonce) not in combined_nonce:
                print("<handshake failed>")
                return False
            else:
                responder_nonce = combined_nonce[len(combined_nonce)//2:]
                handshake_reply = HandshakePacket(self.id, responder_nonce)
                encrypted_handshake_reply = self.rsa.encrypt(json.dumps(handshake_reply.to_json()), self.public_keys["responder"])
                client.sendall(json.dumps(encrypted_handshake_reply).encode())

            return True
        
        except Exception as e:
            print(f"eError during handshake>: {e}")
            return False

    def handle_receive_messages(self, client, des):
        while True:
            try:
                message = client.recv(1024).decode()

                if not message:
                    break

                decrypted_message = des.decrypt(message)
                print(f"\t\t\t\t\t{decrypted_message}")

            except ConnectionError:
                break
            
    def send_des_key(self, client):        
        cipher_des_key = self.rsa.encrypt(self.des_key, self.keys["private_key"])
        encrypted_des_key = self.rsa.encrypt(cipher_des_key, self.public_keys["responder"])
        client.sendall(encrypted_des_key.encode())

    def start_initiator(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.responder_host, self.responder_port))
            print(f"<connected to responder at {self.responder_host}:{self.responder_port}>")

            response = self.get_responder_public_key("responder")
            if response['status'] == "error":
                print("<failed to retrieve responder's public key from PKA>")
                return
            else:
                self.public_keys["responder"] = response['message']
            
            print(f"<responder public key>: {self.public_keys['responder']}")

            if self.handle_handshake(s):
                print("<handshake successful>")
                
                des = DES(self.des_key)
                self.send_des_key(s)

                threading.Thread(target=self.handle_receive_messages, args=(s, des)).start()

                while True:
                    try:
                        message = input()
                        
                        if message.lower() == "exit":
                            break

                        des_encrypted_message = des.encrypt(message)
                        s.sendall(des_encrypted_message.encode())
                        
                    except KeyboardInterrupt:
                        print("<connection interrupted>")
                        break

                    except ConnectionError:
                        print("<no connection available>")
                        break

                print("<exiting>")
                s.close()

if __name__ == "__main__":
    des_key = "keyganmk"
    initiator = Initiator("initiator", des_key)

    initiator.start_initiator()