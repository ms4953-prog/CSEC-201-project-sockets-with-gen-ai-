import socket

Host = "127.0.0.1"
Port = 5000

Client_S = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
Client_S.connect((Host,Port))

msg = "(SS,RFMP,v1.0,1)"

Client_S.send(msg.encode())

responese = Client_S.recv(1024).decode()

print("Received from server: ", responese)


Client_S.close()

print("Client closed.")