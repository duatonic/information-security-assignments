import socket
import threading
import des as encryption

def receive_messages(client_socket, des):
    while True:
        try:
            message = client_socket.recv(1024)
            message = message.decode()

            if not message:
                break
            
            print("\t\t\t\tReceived Encrypted:", message)
            print("\t\t\t\t", des.decrypt(message))

        except ConnectionError:
            break

def main():
    host = '127.0.0.1'
    port = 12002

    # Create a TCP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))
    print("Connected to server.")

    # create DES object
    des = encryption.DES('keyganmk')

    # Start a thread to continuously receive messages
    threading.Thread(target=receive_messages, args=(client_socket, des)).start()

    # Loop to send messages
    while True:
        message = input()
        if message.lower() == "exit":
            break
        encrypted_message = des.encrypt(message)
        print("Sent Encrypted:", encrypted_message)
        client_socket.sendall(encrypted_message.encode())

    client_socket.close()

if __name__ == "__main__":
    main()