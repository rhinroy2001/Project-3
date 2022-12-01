all: client_receiver client_sender server

client_receiver: client_receiver.c
	gcc -o client_receiver client_receiver.c
	
client_sender: client_sender.c
	gcc -lm -lcrypto -o client_sender client_sender.c

server: server.c
	gcc -lm -lcrypto -o server server.c
