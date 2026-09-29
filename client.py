import socket
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

Host = "127.0.0.1"
Port = 5000

Client_S = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
Client_S.connect((Host,Port))

msg = "(SS,RFMP,v1.0,1)"

Client_S.send(msg.encode())

responese = Client_S.recv(4096).decode()

print("Received from server: ", responese)

server_public_key_text = responese[4:-1]

server_public_key = serialization.load_pem_public_key(
	server_public_key_text.encode()
)

# Generate client RSA key pair
client_private_key = rsa.generate_private_key(
	public_exponent=65537,
	key_size=2048
)

client_public_key = client_private_key.public_key()

#Generate AES session key
session_key = os.urandom(32)

print("Client RSA key pair generated.")
print("AES session key generated.")

encrypted_session_key = server_public_key.encrypt(
	session_key,
	padding.OAEP(
		mgf=padding.MGF1(algorithm=hashes.SHA256()),
		algorithm=hashes.SHA256(),
		label=None
	)
)

print("AES session key encrypted.")

client_public_key_bytes = client_public_key.public_bytes(
	encoding=serialization.Encoding.PEM,
	format=serialization.PublicFormat.SubjectPublicKeyInfo
)

encrypted_session_key_text = encrypted_session_key.hex()

username = "mubeen"

ec_packet = (
    b"(EC,AES,"
    + encrypted_session_key_text.encode()
    + b","
    + username.encode()
    + b":"
    + client_public_key_bytes
    + b")"
)

print("Ec packet created.")
Client_S.send(ec_packet)
while True:

    command = input("Enter the command: ")

    if command == "exit":
        break

    if command == "mkdir":
        directory_name = input("What do you want to name the directory: ")
        command_data_packet = "(CM,prompt," + command + " " + directory_name + ")"

    elif command == "cd":
        directory_name = input("What directory do you want to enter: ")
        command_data_packet = "(CM,prompt," + command + " " + directory_name + ")"
    
    elif command == "rmdir":
        directory_name = input("What directory do you want to remove: ")
        command_data_packet = "(CM,prompt," + command + " " + directory_name + ")"

    else:
        command_data_packet = "(CM,prompt," + command + ")"

    Client_S.send(command_data_packet.encode())

    response = Client_S.recv(4096).decode()

    print("Received from server:", response)
	
Client_S.close()

print("Client closed.")