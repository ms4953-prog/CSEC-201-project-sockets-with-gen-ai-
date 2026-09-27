import socket
import os
from cryptography.hazmat.primitives.asymmetric import rsa

Host = "127.0.0.1"
Port = 5000

Client_S = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
Client_S.connect((Host,Port))

msg = "(SS,RFMP,v1.0,1)"

Client_S.send(msg.encode())

responese = Client_S.recv(4096).decode()

print("Received from server: ", responese)

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


Client_S.close()

print("Client closed.")