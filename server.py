import socket
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
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

public_key_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

msg = Client_S.recv(1024).decode()

print("Received from client: ", msg)

if msg == "(SS,RFMP,v1.0,0)":
    Client_S.send("(CC)".encode())

elif msg == "(SS,RFMP,v1.0,1)":
    response = b"(CC," + public_key_bytes + b")"

    Client_S.send(response)

ec_packet = Client_S.recv(4096)
print("Received EC packet from client: ", ec_packet)

encrypted_session_key = bytes.fromhex(
    ec_packet.split(b",", 2)[2].split(b",mubeen:", 1)[0].decode()
)
print("Encrypted AES session key extracted.")

session_key = private_key.decrypt(
    encrypted_session_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

print("AES session key decrypted successfully.")

while True:

    command_data_packet = Client_S.recv(4096).decode()

    print("Received command packet:", command_data_packet)

    if command_data_packet == "":
        break

    Client_S.send("(SC)".encode())


Client_S.close()
Server_S.close()

print("Server closed.")