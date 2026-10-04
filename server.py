import socket
import os
import threading
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

# AES encryption
# AES is used in this function to encrypt text
def encrypt_data(plain_text: str, key: bytes) -> str:
    # this makes a random 16 byte IV for AES
    iv = os.urandom(16)
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(plain_text.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    # this makes the AES encryptor
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return (iv + ciphertext).hex()

# AES decryption
# in this function AES encrypted text is decrypted
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
# this function encrypts text using caesar shift
def caesar_encrypt(text,key):
    encrypted_text = ""
    # it goes through every letter in the text
    for letter in text:
        # moves the letter forward using the caesar key
        encrypted_text = encrypted_text + chr(ord(letter) + key)
    return encrypted_text

# Caesar decryption
# this function decrypts the caesar shifted text
def caesar_decrypt(text,key):
    decrypted_text = ""
    # it goes through every letter in the encrypted text
    for letter in text:
        # moves the letter backwards using the same key
        decrypted_text = decrypted_text + chr(ord(letter) - key)
    return decrypted_text

# server ip
Host = "127.0.0.1"
# port number used by the server
Port = 5000

# this makes the tcp socket for the server
Server_S = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
Server_S.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
Server_S.bind((Host,Port))
# server starts listening for clients
Server_S.listen(5)

print("Server is waiting for connection")

# this function handles every client that connects
def handling_multiclient(Client_S, Client_address):
    print("A client connected: ", Client_address)

    # generates the server RSA keys
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # receives the start packet from the client
    msg = Client_S.recv(1024).decode()
    print("Received from client: ", msg)

    # client selected non secure mode
    if msg == "(SS,RFMP,v1.0,0)":
        Client_S.send("(CC)".encode())
        secure_mode = 0
        algorithm = "None"
        session_key = None

    # client selected secure mode
    elif msg == "(SS,RFMP,v1.0,1)":
        response = b"(CC," + public_key_bytes + b")"
        Client_S.send(response)
        secure_mode = 1

        # receives the encryption packet from the client
        ec_packet = Client_S.recv(4096)
        print("Received EC packet from client: ", ec_packet)

        ec_parts = ec_packet.split(b",",3)
        algorithm = ec_parts[1].decode()
        encrypted_session_key = bytes.fromhex(ec_parts[2].decode())

        # RSA decrypts the session key with the server private key
        session_key = private_key.decrypt(
            encrypted_session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # client selected AES
        if algorithm == "AES":
            print("AES session key decrypted successfully.")

        # client selected caesar
        elif algorithm == "Caesar":
            session_key = int(session_key.decode())
            print("Caesar key decrypted successfully.")

        # invalid encryption choice
        else:
            Client_S.send("(EE,400,Invalid encryption algorithm)".encode())
            Client_S.close()
            return

        print("Encryption algorithm:", algorithm)

    else:
        Client_S.close()
        return

    # saves the current directory for this client
    current_directory = os.getcwd()
    file_name = ""

    # keeps asking for commands until client closes
    while True:
        try:
            command_data_packet = Client_S.recv(4096).decode()

            # checks if client disconnected
            if command_data_packet == "":
                print("Client disconnected.")
                break

            print("Received command packet:", command_data_packet)

            # closes the client connection
            if command_data_packet == "(End)":
                print("Client is closing the connection.")
                break

            # makes a new directory
            if command_data_packet.startswith("(CM,prompt,mkdir "):
                directory_name = command_data_packet[17:-1]
                directory_path = os.path.join(current_directory,directory_name)
                print("Creating the directory:", directory_name)
                os.mkdir(directory_path)
                print("Directory created.")
                response = "(SC,Current directory: " + current_directory + ")"
                Client_S.send(response.encode())
                continue

            # moves into another directory
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

            # removes a directory
            elif command_data_packet.startswith("(CM,prompt,rmdir "):
                directory_name = command_data_packet[17:-1]
                directory_path = os.path.join(current_directory,directory_name)
                print("Removing the directory:", directory_name)
                os.rmdir(directory_path)
                print("Directory removed.")
                response = "(SC,Current directory: " + current_directory + ")"
                Client_S.send(response.encode())
                continue

            # deletes a file
            elif command_data_packet.startswith("(CM,prompt,del "):
                file_name = command_data_packet[15:-1]
                file_path = os.path.join(current_directory,file_name)
                print("Deleting the file:", file_name)
                os.remove(file_path)
                print("File deleted.")
                response = "(SC,Current directory: " + current_directory + ")"
                Client_S.send(response.encode())
                continue

            # renames a file or directory
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

            # opens a file and reads the content
            elif command_data_packet.startswith("(CM,openRead,"):
                file_name = command_data_packet[13:-1]
                file_path = os.path.join(current_directory,file_name)
                print("Reading the file:", file_name)

                file = open(file_path,"r")
                file_data = file.read()
                file.close()

                print("File contents:", file_data)

                # encrypts file before sending if secure mode is selected
                if secure_mode == 1:
                    if algorithm == "AES":
                        file_data = encrypt_data(file_data,session_key)
                    elif algorithm == "Caesar":
                        file_data = caesar_encrypt(file_data,session_key)

                response = "(SC," + file_data + ")"
                Client_S.send(response.encode())
                continue

            # makes a file so data can be written in it
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

            # DP contains the text that will be written in the file
            elif command_data_packet.startswith("(DP,"):
                text = command_data_packet[4:-1]

                # decrypts the data if secure mode is selected
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

            # shows everything inside the directory
            elif command_data_packet.startswith("(CM,prompt,ls)"):
                contents = os.listdir(current_directory)
                print("Contents:", contents)
                response = "(SC," + str(contents) + ")"
                Client_S.send(response.encode())
                continue

            # shows the current directory
            elif command_data_packet.startswith("(CM,prompt,pwd)"):
                print("Current directory:", current_directory)
                response = "(SC," + current_directory + ")"
                Client_S.send(response.encode())
                continue

            # makes an empty file
            elif command_data_packet.startswith("(CM,prompt,touch "):
                file_name = command_data_packet[17:-1]
                file_path = os.path.join(current_directory,file_name)
                print("Creating empty file:", file_name)
                open(file_path,"a").close()
                print("File created.")
                response = "(SC,Current directory: " + current_directory + ")"
                Client_S.send(response.encode())
                continue

            # shows the content of a file
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

            # sends the same text back to the client
            elif command_data_packet.startswith("(CM,prompt,echo "):
                text = command_data_packet[16:-1]
                print("Echo output:", text)
                response = "(SC," + text + ")"
                Client_S.send(response.encode())
                continue

            # invalid command
            else:
                error_packet = "(EE,400,Invalid command)"
                print("Sending Error Packet:", error_packet)
                Client_S.send(error_packet.encode())

        # file or directory cannot be found
        except FileNotFoundError:
            error_packet = "(EE,404,File or directory not found)"
            print("Sending Error Packet:", error_packet)
            Client_S.send(error_packet.encode())

        # file or directory already exists
        except FileExistsError:
            error_packet = "(EE,409,File or directory already exists)"
            print("Sending Error Packet:", error_packet)
            Client_S.send(error_packet.encode())

        # server does not have permission
        except PermissionError:
            error_packet = "(EE,403,Permission denied)"
            print("Sending Error Packet:", error_packet)
            Client_S.send(error_packet.encode())

        # catches any other error
        except Exception as e:
            error_packet = "(EE,400," + str(e) + ")"
            print("Sending Error Packet:", error_packet)
            Client_S.send(error_packet.encode())

    # closes client after they exit
    Client_S.close()
    print("Client connection closed:", Client_address)

# Multithreading
# keeps server running for more clients
while True:
    Client_S, Client_address = Server_S.accept()

    # makes a new thread for each client
    client_thread = threading.Thread(
        target=handling_multiclient,
        args=(Client_S,Client_address)
    )

    client_thread.start()
    print("New client thread started.")