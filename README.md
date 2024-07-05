# Secure Communication using RSA with CBC 

## Project Overview
This project implements secure communication with RSA and CBC from an FTP client to an FTP server that support both IPv4 and IPv6 connections. The roject is for educational purposes only and uses small prime numbers to implement the RSA algorithm. The project can run cross platofrm acoss Windows, Mac and Linux operating systems. 

## Features
- **Encryption**: Implements RSA encryption with CBC for secure data transmission.
- **Cross-Platform**: Compatible with Unix-like systems and Windows.
- **IPv6 Support**: Ready for IPv6 networking alongside IPv4.

## Directory Structure
- `secure_client/` - Contains the client application code and related utilities.
- `secure_server/` - Contains the server application code and related utilities.
- `makefile` - Makefiles for building the client and server applications.

## Prerequisites
- GCC compiler (for Linux/macOS)
- MinGW or similar (for Windows)

## Usage

- clone the repo git clone https://github.com/jpmal22/RSAwithCBC-FTPClientandServer.git

### Building the Server

- The server uses a makefile to build the executable
- Navigate to the `secure_server` directory and run the following command in the command line: make or mingw32-make if using MinGW
- Run the executable file with the following arguments: executable file name and port number for the server to listen on for incomming connections
- Any ephemeral port number wil do
- Message will be displayed saying the server is listening on port #

Example:

secure_server.exe 1155

### Building the Client

- The client uses a makefile to build the executable 
- Navigate to the `secure_client` directory and run the following command in the command line: make or mingw32-make if using MinGW
- Run the executable file with the following arguments: executable file name, IP address, and port number the server is listening on
- The program is configured to run on IPV6 but can be amended to run on the IPV4 addressing scheme instead. 
- If using IPV6, IP address will be ::1 
- Message will be displayed if there is a succcessful connection to the server

Example for IPV6:

secure_client.exe ::1 1155

### Secure messaging usage

- The project only implemented secure messaging one way from the client to the server
- Once the client has succesfully connected to the server it will initiate sending the RSA public key from the server and the nonce/initialisation vector from the client
- Client will prompt the user to enter a message to send to the server and display the encrypted message and send to the server
- The server will display the encrypted message and then apply decryption and display the decrypted message
- User can continue to send messages until . is entered to close the client connection
- Server will remain listening on the port number until closed by the user

## Authors

Implementation of the RSA with CBC algorithm and integration with the FTP client and server: 

* **Paolo Alejandro** - https://github.com/jpmal22

Starter code files are by NH Reyes PHD, Massey University. Starter codes are the basic structure of the FTP client and Server. 


