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
        return json.dumps(self.__dict__)

class HandshakePacket:
    def __init__(self, id, nonce):
        self.id = id
        self.nonce = nonce

    def to_json(self):
        return json.dumps(self.__dict__)

class Responder:
    def __init__(self, id, pka_host='localhost', pka_port=11999, host='localhost', port=12001):
        self.id = id
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
            cipher_request = self.rsa.encrypt(request.to_json(), self.public_keys["pka"])
            s.sendall(cipher_request.encode())

            response = s.recv(1024).decode()
            decrypted_response = self.rsa.decrypt(response)

        return json.loads(decrypted_response)

    def handle_handshake(self, client):
        try:
            encrypted_handshake_request = client.recv(1024).decode()
            decrypted_handshake_request = self.rsa.decrypt(encrypted_handshake_request)
            handshake_request = json.loads(decrypted_handshake_request)

            initiator_id = handshake_request["id"]
            initiator_nonce = handshake_request["nonce"]

            initiator_public_key = self.get_initiator_public_key(initiator_id)
            if initiator_public_key['status'] == "error":
                print("<failed to retrieve initiator's public key from PKA>")
                return False
            else:
                self.public_keys["initiator"] = initiator_public_key['message']

            nonce = self.generate_nonce()
            combined_nonce = f"{initiator_nonce}{nonce}"

            handshake = HandshakePacket(self.id, combined_nonce)
            encrypted_handshake = self.rsa.encrypt(handshake.to_json(), self.public_keys["initiator"])
            client.sendall(encrypted_handshake.encode())

            encrypted_response_handshake = client.recv(1024).decode()
            decrypted_response_handshake = self.rsa.decrypt(encrypted_response_handshake)
            handshake_response = json.loads(decrypted_response_handshake)

            response_nonce = handshake_response["nonce"]

            if str(nonce) not in response_nonce:
                print("<handshake failed>: nonces do not match")
                return False

            return True
        
        except Exception as e:
            print(f"<error during handshake>: {e}")
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

    def get_des_key(self, client):
        try:
            encrypted_des_key = client.recv(1024).decode()
            decrypted_des_key = self.rsa.decrypt(encrypted_des_key)
            des_key = self.rsa.decrypt(decrypted_des_key, self.public_keys["initiator"])

            des = DES(des_key)
            print(f"<DES key received>")

            return des

        except Exception as e:
            print(f"<error getting DES key>: {e}")

    def start_responder(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.bind((self.host, self.port))
            server_socket.listen(5)
            print(f"<responder running on {self.host}:{self.port}>")

            client, addr = server_socket.accept()
            print(f"<connection received>: {addr}")

            if self.handle_handshake(client):
                print("<handshake successful>")

                des = self.get_des_key(client)

                threading.Thread(target=self.handle_receive_messages, args=(client, des)).start()

                while True:
                    try:
                        message = input()

                        if message.lower() == "exit":
                            break

                        des_encrypted_message = des.encrypt(message)
                        client.sendall(des_encrypted_message.encode())

                    except KeyboardInterrupt:
                        print("<terminated by user>")
                        break

                    except ConnectionError:
                        print("<no connection available>")
                        break

                print("<exiting>")
                client.close()

if __name__ == "__main__":
    responder = Responder("responder")

    responder.start_responder()