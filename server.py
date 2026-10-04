import socket
import os
import threading
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

Server_S = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
Server_S.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
Server_S.bind((Host,Port))
Server_S.listen(5)

print("Server is waiting for connection")

def handling_multiclient(Client_S, Client_address):

    print("A client connected: ", Client_address)

    # Server RSA keys
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Start packet
    msg = Client_S.recv(1024).decode()
    print("Received from client: ", msg)

    if msg == "(SS,RFMP,v1.0,0)":
        Client_S.send("(CC)".encode())
        secure_mode = 0
        algorithm = "None"
        session_key = None

    elif msg == "(SS,RFMP,v1.0,1)":
        response = b"(CC," + public_key_bytes + b")"
        Client_S.send(response)
        secure_mode = 1

        # Receive EC packet
        ec_packet = Client_S.recv(4096)
        print("Received EC packet from client: ", ec_packet)

        ec_parts = ec_packet.split(b",",3)
        algorithm = ec_parts[1].decode()

        encrypted_session_key = bytes.fromhex(
            ec_parts[2].decode()
        )

        # RSA decrypt session key
        session_key = private_key.decrypt(
            encrypted_session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        if algorithm == "AES":
            print("AES session key decrypted successfully.")

        elif algorithm == "Caesar":
            session_key = int(session_key.decode())
            print("Caesar key decrypted successfully.")

        else:
            Client_S.send("(EE,400,Invalid encryption algorithm)".encode())
            Client_S.close()
            return
        print("Encryption algorithm:", algorithm)

    else:
        Client_S.close()
        return

    current_directory = os.getcwd()
    file_name = ""

    while True:
        try:
            command_data_packet = Client_S.recv(4096).decode()

            if command_data_packet == "":
                print("Client disconnected.")
                break

            print("Received command packet:", command_data_packet)

            if command_data_packet == "(CL)":
                print("Client is closing the connection.")
                break

            if command_data_packet.startswith("(CM,prompt,mkdir "):
                directory_name = command_data_packet[17:-1]
                directory_path = os.path.join(current_directory,directory_name)
                print("Creating the directory:", directory_name)
                os.mkdir(directory_path)
                print("Directory created.")
                response = "(SC,Current directory: " + current_directory + ")"
                Client_S.send(response.encode())
                continue

            elif command_data_packet.startswith("(CM,prompt,cd "):
                directory_name = command_data_packet[14:-1]
                new_directory = os.path.join(current_directory,directory_name)
                new_directory = os.path.abspath(new_directory)
                if not os.path.isdir(new_directory):
                    raise FileNotFoundError            
                current_directory = new_directory
                print("Current directory:", current_directory)
                response = "(SC,Current directory: " + current_directory + ")"
                Client_S.send(response.encode())
                continue

            elif command_data_packet.startswith("(CM,prompt,rmdir "):
                directory_name = command_data_packet[17:-1]
                directory_path = os.path.join(current_directory,directory_name)
                print("Removing the directory:", directory_name)
                os.rmdir(directory_path)
                print("Directory removed.")
                response = "(SC,Current directory: " + current_directory + ")"
                Client_S.send(response.encode())
                continue

            elif command_data_packet.startswith("(CM,prompt,del "):
                file_name = command_data_packet[15:-1]
                file_path = os.path.join(current_directory,file_name)
                print("Deleting the file:", file_name)
                os.remove(file_path)
                print("File deleted.")
                response = "(SC,Current directory: " + current_directory + ")"
                Client_S.send(response.encode())
                continue

            elif command_data_packet.startswith("(CM,prompt,ren "):
                names = command_data_packet[15:-1].split(" ")
                old_name = names[0]
                new_name = names[1]
                old_path = os.path.join(current_directory,old_name)
                new_path = os.path.join(current_directory,new_name)
                print("Renaming", old_name, "to", new_name)
                os.rename(old_path,new_path)
                print("File or directory renamed.")
                response = "(SC,Current directory: " + current_directory + ")"
                Client_S.send(response.encode())
                continue

            elif command_data_packet.startswith("(CM,openRead,"):
                file_name = command_data_packet[13:-1]
                file_path = os.path.join(current_directory,file_name)
                print("Reading the file:", file_name)
                file = open(file_path,"r")
                file_data = file.read()
                file.close()
                print("File contents:", file_data)
                if secure_mode == 1:
                    if algorithm == "AES":
                        file_data = encrypt_data(file_data,session_key)
                    elif algorithm == "Caesar":
                        file_data = caesar_encrypt(file_data,session_key)
                Client_S.send(file_data.encode())
                continue

            elif command_data_packet.startswith("(CM,openWrite,"):
                file_name = command_data_packet[14:-1]
                file_name = os.path.join(current_directory,file_name)
                print("Opening the file for writing:", file_name)
                file = open(file_name,"w")
                file.close()
                print("File created.")
                response = "(SC,Current directory: " + current_directory + ")"
                Client_S.send(response.encode())
                continue

            elif command_data_packet.startswith("(DP,"):
                text = command_data_packet[4:-1]
                if secure_mode == 1:
                    if algorithm == "AES":
                        text = decrypt_data(text,session_key)
                    elif algorithm == "Caesar":
                        text = caesar_decrypt(text,session_key)
                print("Received data:", text)
                file = open(file_name,"w")
                file.write(text)
                file.close()
                print("Data written to file.")
                response = "(SC,Current directory: " + current_directory + ")"
                Client_S.send(response.encode())
                continue

            elif command_data_packet.startswith("(CM,prompt,ls)"):
                contents = os.listdir(current_directory)
                print("Contents:", contents)
                response = "(SC," + str(contents) + ")"
                Client_S.send(response.encode())
                continue

            elif command_data_packet.startswith("(CM,prompt,pwd)"):
                print("Current directory:", current_directory)
                response = "(SC," + current_directory + ")"
                Client_S.send(response.encode())
                continue

            elif command_data_packet.startswith("(CM,prompt,touch "):
                file_name = command_data_packet[17:-1]
                file_path = os.path.join(current_directory,file_name)
                print("Creating empty file:", file_name)
                open(file_path,"a").close()
                print("File created.")
                response = "(SC,Current directory: " + current_directory + ")"
                Client_S.send(response.encode())
                continue

            elif command_data_packet.startswith("(CM,prompt,cat "):
                file_name = command_data_packet[15:-1]
                file_path = os.path.join(current_directory,file_name)
                print("Displaying file contents for:", file_name)
                file = open(file_path,"r")
                file_data = file.read()
                file.close()
                print("File contents:", file_data)
                response = "(SC," + file_data + ")"
                Client_S.send(response.encode())
                continue

            elif command_data_packet.startswith("(CM,prompt,echo "):
                text = command_data_packet[16:-1]
                print("Echo output:", text)
                response = "(SC," + text + ")"
                Client_S.send(response.encode())
                continue

            else:
                error_packet = "(EE,400,Invalid command)"
                print("Sending Error Packet:", error_packet)
                Client_S.send(error_packet.encode())

        except FileNotFoundError:
            error_packet = "(EE,404,File or directory not found)"
            print("Sending Error Packet:", error_packet)
            Client_S.send(error_packet.encode())

        except FileExistsError:
            error_packet = "(EE,409,File or directory already exists)"
            print("Sending Error Packet:", error_packet)
            Client_S.send(error_packet.encode())

        except PermissionError:
            error_packet = "(EE,403,Permission denied)"
            print("Sending Error Packet:", error_packet)
            Client_S.send(error_packet.encode())

        except Exception as e:
            error_packet = "(EE,400," + str(e) + ")"
            print("Sending Error Packet:", error_packet)
            Client_S.send(error_packet.encode())

    Client_S.close()
    print("Client connection closed:", Client_address)

# Multithreading
while True:
    Client_S, Client_address = Server_S.accept()
    client_thread = threading.Thread(
        target=handling_multiclient,
        args=(Client_S,Client_address)
    )
    client_thread.start()
    print("New client thread started.")