import socket
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

# AES encryption
# AES is used in this function to encrypt text
def encrypt_data(plain_text: str, key: bytes) -> str:
    # this makes a random 16 byte for AES
    iv = os.urandom(16)
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(plain_text.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    # this makes the AES encryptor
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return (iv + ciphertext).hex()

# AES decryption
# in this fucction AES is decrypted
def decrypt_data(hex_data: str, key: bytes) -> str:
    raw_data = bytes.fromhex(hex_data)
    iv = raw_data[:16]
    ciphertext = raw_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    # this makes the AES decryptor
    decryptor = cipher.decryptor()
    # here the encrypted text gets decrypted
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data.decode()

# Caesar encryption
# this function encrypts texts using caesar shift
def caesar_encrypt(text,key):
    encrypted_text = ""
    # in line 40 it go through the letters in the text
    for letter in text:
        # here it moves the letter forward using caesar
        encrypted_text = encrypted_text + chr(ord(letter) + key)
    return encrypted_text

# Caesar decryption
# in this function it decrypts the caesar shift
def caesar_decrypt(text,key):
    decrypted_text = ""
    # it goes through the letter in the text
    for letter in text:
        # it moves the letters backwards using the same key it was moved forward
        decrypted_text = decrypted_text + chr(ord(letter) - key)
    return decrypted_text
# server ip
Host = "127.0.0.1"
# port number that the server uses
Port = 5000

# this makes tcp the socket for the client
Client_S = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# connects the client to the server
Client_S.connect((Host,Port))

# it gives the cilent to choose if they want secure or non secure connect
print("0 - Non-secured")
print("1 - Secured")
secure_mode = input("Enter choice: ")

# this if makes sure the client enters one of the options
if secure_mode != "0" and secure_mode != "1":
    print("Invalid choice.")
    # the socket is closed due to invalid choice
    Client_S.close()
    exit()

# Start packet
# this tells the server if the client wants secure connection or non secure
msg = "(SS,RFMP,v1.0," + secure_mode + ")"
# the starting packet is sent to the server
Client_S.send(msg.encode())

# this recieves the confirmation packet from the server
response = Client_S.recv(4096).decode()
print("Received from server: ", response)

algorithm = "None"
session_key = None

# Security setup
# does encryption if the security mode is selected by the client
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
    # gets client public key from the private key
    client_public_key = client_private_key.public_key()
    print("Client RSA key pair generated.")
    print("1 - AES")
    print("2 - Caesar")
    # it asks what encryption the user wants
    choice = input("Choose encryption: ")

    # client selectedd AES 
    if choice == "1":
        algorithm = "AES"
        session_key = os.urandom(32)
        print("AES session key generated.")

    # client selected caesar
    elif choice == "2":
        algorithm = "Caesar"
        # uses 10 as caesar key,  it is in bytes for RSA
        session_key = b"10"
        print("Caesar key generated.")

    # if user enters anything other than 1 or 2, client closes
    else:
        print("Invalid choice.")
        Client_S.close()
        exit()

    # RSA encrypt session key
    # RSA encrypts the session key with RSA public key
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
    # the username sent inside the EC packet
    username = "mubeen"

    # makes the encryption packet
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
# it shows all the commands the client can use
print("Commands: mkdir, cd, rmdir, del, ren, openRead, openWrite, ls, pwd, touch, cat, echo, exit")

# looped to keeping asking the client commands until the type "exit"
while True:
    command = input("Enter the command: ")

    # sends packet to close the client
    if command == "exit":
        Client_S.send("(End)".encode())
        break
    # makes a new directory 
    if command == "mkdir":
        directory_name = input("What do you want to name the directory: ")
        command_data_packet = "(CM,prompt," + command + " " + directory_name + ")"
    # sends the cd command to move into directory
    elif command == "cd":
        directory_name = input("What directory do you want to enter: ")
        command_data_packet = "(CM,prompt," + command + " " + directory_name + ")"
    # command to removes directory
    elif command == "rmdir":
        directory_name = input("What directory do you want to remove: ")
        command_data_packet = "(CM,prompt," + command + " " + directory_name + ")"
    # command to delete a file
    elif command == "del":
        file_name = input("What file do you want to delete: ")
        command_data_packet = "(CM,prompt," + command + " " + file_name + ")"
    # command to rename a file 
    elif command == "ren":
        old_name = input("What is the current name: ")
        new_name = input("What is the new name: ")
        command_data_packet = "(CM,prompt," + command + " " + old_name + " " + new_name + ")"
    # command to open a file and read it 
    elif command == "openRead":
        file_name = input("What file do you want to read: ")
        command_data_packet = "(CM,openRead," + file_name + ")"
        Client_S.send(command_data_packet.encode())
        response = Client_S.recv(4096).decode()
        # checks if the server sent an error
        if response.startswith("(EE,"):
            print("Received Exception from server:", response)
        else:
            # removes the SC part and gets the file data
            file_data = response[4:-1]
            if secure_mode == "1" and algorithm == "AES":
                file_data = decrypt_data(file_data,session_key)
                print("File contents (Decrypted):", file_data)
            elif secure_mode == "1" and algorithm == "Caesar":
                caesar_key = int(session_key.decode())
                file_data = caesar_decrypt(file_data,caesar_key)
                print("File contents (Decrypted):", file_data)
            else:
                print("File contents:", file_data)
        # goes back to asking for another command
        continue
    # command to make a file and write text in it 
    elif command == "openWrite":
        file_name = input("What file do you want to write: ")
        command_data_packet = "(CM,openWrite," + file_name + ")"

        Client_S.send(command_data_packet.encode())
        response = Client_S.recv(4096).decode()
        print("Received from server:", response)
        # checking if server sent an error 
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
        if response.startswith("(EE,"):
            print("Received Exception from server:", response)
        else:
            print("Received from server:", response)
        continue
    # this command makes a empty file
    elif command == "touch":
        file_name = input("Enter the file name to create: ")
        command_data_packet = "(CM,prompt," + command + " " + file_name + ")"
    # this command shows the content of a file 
    elif command == "cat":
        file_name = input("Enter the file name to display: ")
        command_data_packet = "(CM,prompt," + command + " " + file_name + ")"
    # sends  text to server and gets it back
    elif command == "echo":
        text = input("Enter text to display: ")
        command_data_packet = "(CM,prompt," + command + " " + text + ")"

    else:
        command_data_packet = "(CM,prompt," + command + ")"

    Client_S.send(command_data_packet.encode())
    response = Client_S.recv(4096).decode()
    # checks if exception packet was recieved from server
    if response.startswith("(EE,"):
        print("Received Exception from server:", response)
    # if no exception then it sends sucessfull response
    else:
        print("Received from server:", response)
# closes client after exit
Client_S.close()
print("Client closed.")