import socket
import threading
import des as encryption

def receive_messages(client_socket, des):
    while True:
        try:
            message = client_socket.recv(1024)
            if not message:
                break
            decrypted_message = des.decrypt(message.decode())
            print("\t\t\tDecrypted message:", decrypted_message)
        except ConnectionError:
            break

def main():
    host = '127.0.0.1'
    port = 12001

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
        padded_message = des.pad(message)
        encrypted_message = des.encrypt(message)
        print("Padded message:", padded_message)
        print("Encrypted message:", encrypted_message)
        client_socket.sendall(encrypted_message.encode())

    client_socket.close()

if __name__ == "__main__":
    main()