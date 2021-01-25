
import socket
import random

# rsa encryption
def encrypt(public_key,secertkey):
    n,e=public_key
    m = secertkey
    c=(m**e)%n
    return c

# message encryption using substitution method
def messageencrypt(message, secertkey):
    ciphertext = ""
    for i in range(len(message)):
        letter = message[i]
        if (letter.isupper()):
            ciphertext = ciphertext+ chr((ord(letter) + secertkey - 65) % 26 + 65)
        elif (letter == ' '):
            ciphertext = ciphertext + ' '
        else:
            ciphertext =ciphertext + chr((ord(letter) + secertkey - 97) % 26 + 97)
    return ciphertext

# message decrypt using substitution method
def messagedecrypt(ciphertext, secertkey):
    plaintext= ""
    for i in range(len(ciphertext)):
        letter = ciphertext[i]
        if (letter.isupper()):
            plaintext = plaintext + chr((ord(letter) - secertkey - 65) % 26 + 65)
        elif (letter == ' '):
            plaintext = plaintext + ' '
        else:
            plaintext = plaintext + chr((ord(letter) - secertkey - 97) % 26 + 97)
    return plaintext


def client_program():
    host = socket.gethostname()  # as both code is running on same pc
    port = 5000  # socket server port number

    client_socket = socket.socket()  # instantiate
    client_socket.connect((host, port))  # connect to the server
    data = client_socket.recv(1024) #  receive publickey from client
    strings = data.decode('utf8')  # decode to unicode string
    public_key = eval(strings)  #change string  into  tuple
    secertkey = random.randint(100,999)
    encrypedkey = encrypt(public_key,secertkey)
    client_socket.send(str(encrypedkey).encode('utf8'))
    message = input(" -> ")  # take input

    while message.lower().strip() != 'bye':

        ciphertext = messageencrypt(message, secertkey)
        client_socket.send(ciphertext.encode())  # send message
        data = client_socket.recv(1024).decode()  # receive response
        message = messagedecrypt(data, secertkey)
        print("encrypted message " + str(data))
        print('Received from server: ' + message)  # show in terminal

        message = input(" -> ")  # again take input

    client_socket.close()  # close the connection


if __name__ == '__main__':
  client_program()