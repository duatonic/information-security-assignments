import socket
import threading

def handle_client(client_socket, other_client):
    while True:
        try:
            message = client_socket.recv(1024)
            if not message:
                break
            # Forward the message to the other client
            other_client.sendall(message)
        except ConnectionError:
            break

    client_socket.close()
    other_client.close()
    print("Connection closed.")

def main():
    host = '127.0.0.1'
    port = 12001

    # Create a TCP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(2)
    print("Server is listening for clients...")

    # Accept connections from both clients
    client1, addr1 = server_socket.accept()
    print(f"Connected to Client 1 ({client1}) at {addr1}")
    
    client2, addr2 = server_socket.accept()
    print(f"Connected to Client 2 ({client2}) at {addr2}")

    # Start a thread for each client to handle bidirectional communication
    threading.Thread(target=handle_client, args=(client1, client2)).start()
    threading.Thread(target=handle_client, args=(client2, client1)).start()

if __name__ == "__main__":
    main()
