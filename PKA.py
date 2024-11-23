import socket
import json
import os
from RSA import RSA

class Response:
    def __init__(self, status="error", message=None):
        self.status = status
        self.message = message
    
    def to_json(self):
        return json.dumps(self.__dict__)

class PublicKeyAuthority:
    def __init__(self, id, host='localhost', port=11999):
        self.id = id
        self.host = host
        self.port = port
        self.rsa = RSA(self.id)
        self.keys = self.rsa.keys
        self.public_keys = {}

    def read_public_Keys(self):
        dir = os.path.dirname(__file__)
        public_keys_path = os.path.join(dir, "keys/public")
        for filename in os.listdir(public_keys_path):
            id = filename.split(".")[0]
            if filename.endswith(".pem") and id is not self.id:
                with open(os.path.join(public_keys_path, filename)) as f:
                    key = tuple(map(int, f.read().split(",")))
                    self.public_keys[id] = key

    def handle_request(self, client):
        data = client.recv(1024).decode()
        response = Response()

        try:
            request = json.loads(data)

            if request['dst'] not in self.public_keys:
                response.status = "error"
                response.message = "requested public key not found"
            elif request['src'] not in self.public_keys:
                response.status = "error"
                response.message = "unauthorized request"
            else:
                response.status = "success"
                response.message = self.public_keys[request['dst']]
                print(f"Sent public key for {request['dst']} to {request['src']} = {self.public_keys[request['dst']]}")

        except json.JSONDecodeError:
            response.status = "error"
            response.message = "invalid JSON request"
        
        return json.dumps(response.to_json())

    def start_server(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)
        print(f"PKA is running on {self.host}:{self.port}")

        while True:
            try:
                client, addr = server_socket.accept()
                self.read_public_Keys()
                print("public keys:", pka.public_keys)
                
                response = self.handle_request(client)
                ciphertext = self.rsa.encrypt(response, self.keys["private_key"])

                client.sendall(json.dumps(ciphertext).encode())
            
                client.close()

            except KeyboardInterrupt:
                print("Shutting down PKA server")
                break

        server_socket.close()

if __name__ == "__main__":
    pka = PublicKeyAuthority("pka")

    # Start the server
    pka.start_server()