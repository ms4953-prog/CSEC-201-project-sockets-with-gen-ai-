import socket
from cryptography.hazmat.primitives.asymmetric import rsa
Host = "127.0.0.1"
Port = 5000

Server_S = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
Server_S.bind((Host,Port))
Server_S.listen(1)

print("Server is wating for connection")

Client_S, Client_address = Server_S.accept()

print("A client connected: ", Client_address)

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

public_key = private_key.public_key()

msg = Client_S.recv(1024).decode()

print("Received from client: ", msg)

if msg == "(SS,RFMP,v1.0,0)":
    Client_S.send("(CC)".encode())

elif msg == "(SS,RFMP,v1.0,1)":
    Client_S.send("(cc,pubkey)".encode())

Client_S.close()
Server_S.close()

print("Server closed.")