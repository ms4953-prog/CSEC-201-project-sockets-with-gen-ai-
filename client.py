import socket
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

# AES encryption
def encrypt_data(plain_text: str, key: bytes) -> str:
    iv = os.urandom(16)
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(plain_text.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return (iv + ciphertext).hex()

# AES decryption
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

# Caesar encryption
def caesar_encrypt(text,key):
    encrypted_text = ""
    for letter in text:
        encrypted_text = encrypted_text + chr(ord(letter) + key)
    return encrypted_text

# Caesar decryption
def caesar_decrypt(text,key):
    decrypted_text = ""
    for letter in text:
        decrypted_text = decrypted_text + chr(ord(letter) - key)
    return decrypted_text

Host = "127.0.0.1"
Port = 5000

Client_S = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
Client_S.connect((Host,Port))

print("0 - Non-secured")
print("1 - Secured")
secure_mode = input("Enter choice: ")

if secure_mode != "0" and secure_mode != "1":
    print("Invalid choice.")
    Client_S.close()
    exit()

# Start packet
msg = "(SS,RFMP,v1.0," + secure_mode + ")"
Client_S.send(msg.encode())

response = Client_S.recv(4096).decode()
print("Received from server: ", response)

algorithm = "None"
session_key = None

# Security setup
if secure_mode == "1":
    server_public_key_text = response[4:-1]

    server_public_key = serialization.load_pem_public_key(
        server_public_key_text.encode()
    )
    # Generate client RSA keys
    client_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    client_public_key = client_private_key.public_key()
    print("Client RSA key pair generated.")
    print("1 - AES")
    print("2 - Caesar")
    choice = input("Choose encryption: ")

    if choice == "1":
        algorithm = "AES"
        session_key = os.urandom(32)
        print("AES session key generated.")

    elif choice == "2":
        algorithm = "Caesar"
        session_key = b"10"
        print("Caesar key generated.")

    else:
        print("Invalid choice.")
        Client_S.close()
        exit()

    # RSA encrypt session key
    encrypted_session_key = server_public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    print("Session key encrypted.")

    client_public_key_bytes = client_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    encrypted_session_key_text = encrypted_session_key.hex()
    username = "mubeen"

    ec_packet = (
        b"(EC,"
        + algorithm.encode()
        + b","
        + encrypted_session_key_text.encode()
        + b","
        + username.encode()
        + b":"
        + client_public_key_bytes
        + b")"
    )

    print("EC packet created.")
    Client_S.send(ec_packet)

print("Commands: mkdir, cd, rmdir, del, ren, openRead, openWrite, ls, pwd, touch, cat, echo, exit")

while True:
    command = input("Enter the command: ")

    if command == "exit":
        Client_S.send("(CL)".encode())
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

    elif command == "del":
        file_name = input("What file do you want to delete: ")
        command_data_packet = "(CM,prompt," + command + " " + file_name + ")"

    elif command == "ren":
        old_name = input("What is the current name: ")
        new_name = input("What is the new name: ")
        command_data_packet = "(CM,prompt," + command + " " + old_name + " " + new_name + ")"

    elif command == "openRead":
        file_name = input("What file do you want to read: ")
        command_data_packet = "(CM,openRead," + file_name + ")"

        Client_S.send(command_data_packet.encode())
        response = Client_S.recv(4096).decode()

        if response.startswith("(EE,"):
            print("Received Exception from server:", response)

        elif secure_mode == "1" and algorithm == "AES":
            file_data = decrypt_data(response,session_key)
            print("File contents (Decrypted):", file_data)

        elif secure_mode == "1" and algorithm == "Caesar":
            caesar_key = int(session_key.decode())
            file_data = caesar_decrypt(response,caesar_key)
            print("File contents (Decrypted):", file_data)

        else:
            print("File contents:", response)
        continue

    elif command == "openWrite":
        file_name = input("What file do you want to write: ")
        command_data_packet = "(CM,openWrite," + file_name + ")"

        Client_S.send(command_data_packet.encode())
        response = Client_S.recv(4096).decode()
        print("Received from server:", response)

        if response.startswith("(EE,"):
            continue

        text = input("What do you want to write: ")
        if secure_mode == "1" and algorithm == "AES":
            text = encrypt_data(text,session_key)

        elif secure_mode == "1" and algorithm == "Caesar":
            caesar_key = int(session_key.decode())
            text = caesar_encrypt(text,caesar_key)
        packet = "(DP," + text + ")"
        Client_S.send(packet.encode())
        response = Client_S.recv(4096).decode()
        print("Received from server:", response)
        continue

    elif command == "touch":
        file_name = input("Enter the file name to create: ")
        command_data_packet = "(CM,prompt," + command + " " + file_name + ")"

    elif command == "cat":
        file_name = input("Enter the file name to display: ")
        command_data_packet = "(CM,prompt," + command + " " + file_name + ")"

    elif command == "echo":
        text = input("Enter text to display: ")
        command_data_packet = "(CM,prompt," + command + " " + text + ")"

    else:
        command_data_packet = "(CM,prompt," + command + ")"

    Client_S.send(command_data_packet.encode())
    response = Client_S.recv(4096).decode()
    if response.startswith("(EE,"):
        print("Received Exception from server:", response)
    else:
        print("Received from server:", response)

Client_S.close()
print("Client closed.")