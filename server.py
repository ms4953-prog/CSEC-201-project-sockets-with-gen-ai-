import socket
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

def encrypt_data(plain_text: str, key: bytes) -> str:
    iv = os.urandom(16)
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(plain_text.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return (iv + ciphertext).hex()

def decrypt_data(hex_data: str, key: bytes) -> str:
    raw_data = bytes.fromhex(hex_data)
    iv = raw_data[:16]
    ciphertext = raw_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data.decode()

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

file_name = ""
while True:

    command_data_packet = Client_S.recv(4096).decode()

    print("Received command packet:", command_data_packet)

    if command_data_packet == "":
        break

    if command_data_packet.startswith("(CM,prompt,mkdir "):
        directory_name = command_data_packet[17:-1]
        print("Creating the directory:", directory_name)
        os.mkdir(directory_name)
        print("Created at:", os.path.abspath(directory_name))

    elif command_data_packet.startswith("(CM,prompt,cd "):
        directory_name = command_data_packet[14:-1]
        print("Changing directory to:", directory_name)
        os.chdir(directory_name)
        print("Current directory:", os.getcwd())
    
    elif command_data_packet.startswith("(CM,prompt,rmdir "):
        directory_name = command_data_packet[17:-1]
        print("Removing the directory:", directory_name)
        os.rmdir(directory_name)
        print("Directory removed.")

    elif command_data_packet.startswith("(CM,prompt,del "):
        file_name = command_data_packet[15:-1]
        print("Deleting the file:", file_name)
        os.remove(file_name)
        print("File deleted.")

    elif command_data_packet.startswith("(CM,prompt,ren "):
        names = command_data_packet[15:-1].split(" ")
        old_name = names[0]
        new_name = names[1]
        print("Renaming", old_name, "to", new_name)
        os.rename(old_name, new_name)
        print("File or directory renamed.")

    elif command_data_packet.startswith("(CM,openRead,"):
        file_name = command_data_packet[13:-1]
        print("Reading the file:", file_name)
        file = open(file_name, "r")
        file_data = file.read()
        file.close()
        print("File contents:", file_data)
        Client_S.send(file_data.encode())

    elif command_data_packet.startswith("(CM,openWrite,"):
        file_name = command_data_packet[14:-1]
        print("Opening the file for writing:", file_name)
        file = open(file_name, "w")
        file.close()
        print("File created.")

    elif command_data_packet.startswith("(DP,"):
        encrypted_text = command_data_packet[4:-1]
        text = decrypt_data(encrypted_text, session_key)
        print("Received data:", text)
        file = open(file_name, "w")
        file.write(text)
        file.close()
        print("Data written to file.")
    
    elif command_data_packet.startswith("(CM,prompt,ls)"):
        print("Listing directory contents:")
        contents = os.listdir(".")
        print("Contents:", contents)

    elif command_data_packet.startswith("(CM,prompt,pwd)"):
        print("Current working directory:")
        cwd = os.getcwd()
        print("Path:", cwd)

    elif command_data_packet.startswith("(CM,prompt,touch "):
        file_name = command_data_packet[17:-1]
        print("Creating empty file:", file_name)
        open(file_name, "a").close()
        print("File created.")

    elif command_data_packet.startswith("(CM,prompt,cat "):
        file_name = command_data_packet[15:-1]
        print("Displaying file contents for:", file_name)
        if os.path.exists(file_name):
            file = open(file_name, "r")
            file_data = file.read()
            file.close()
            print("File contents:", file_data)
        else:
            print("File does not exist.")

    elif command_data_packet.startswith("(CM,prompt,echo )"):
        text = command_data_packet[16:-1]
        print("Echo output:",text)
	

    Client_S.send("(SC)".encode())
Client_S.close()
Server_S.close()

print("Server closed.")