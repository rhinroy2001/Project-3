CS 447 Project 3

This project is a simple implementation of an email server.
There are a total of three programs that can be run which are are the server, client_sender, and client_receiver.
The client_sender is used to send emails to the server over smtp.
The client_receiver is used to retrieve email from the server over http.
All processes accept a configuration file as a runtime command.
The server configuration file should have the format:
    [self_domain]
    SMTP_PORT=port#
    HTTP_PORT=port#

    [remote_domain]
    IP=ip_address
    PORT=port#
The client configuration files should have the format
    SERVER_IP=ip_address
    SERVER_PORT=port#
Instructions: run the make command in the terminal to compile all of the programs.
    Start the server process first, then start the client_sender process to send email to the server and start the client_receiver process to retrieve emails from the server.
    The server allows multiple client_sender processes to send email simultaneously.
    The server only allows one client_receiver process to retrieve emails at one time.