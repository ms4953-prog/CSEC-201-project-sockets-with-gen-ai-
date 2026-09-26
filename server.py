import socket

Host = "127.0.0.1"
Port = 5000

Server_S = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
Server_S.bind((Host,Port))
Server_S.listen(1)

print("Server is wating for connection")

Client_S, Client_address = Server_S.accept()

print("A client connected: ", Client_address)

msg = Client_S.recv(1024).decode()

print("Received from client: ", msg)

if msg == "(SS,RFMP,v1.0,0)":
    Client_S.send("(CC)".encode())

Client_S.close()
Server_S.close()

print("Server closed.")