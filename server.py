import socket
import random

# Check if Input's are Prime
def prime_check(number):
    if (number == 2):
        return True
    elif ((number < 2) or ((number % 2) == 0)):
        return False
    elif (number > 2):
        for i in range(2, number):
            if not (number % i):
                return False
    return True

# random prime number less than z
def compute_E(z):
    while True :
        n = random.randint(2, z)
        check_n = prime_check(n)
        if(check_n == True):
           return n
           break

def publickey_privatekey():
    #  prime number for Rsa
    p = 827
    q = 673

    # compute n
    n = p * q

    # compute z
    z = (p - 1) * (q - 1)

    # compute e
    e = compute_E(z)


    # compute d
    d = 0
    x = 1
    while (d == 0):
        key = (e * x - 1) % z
        if ((key == 0) and (x != e)):
            d = x
            break
        x += 1

    return  n,e,d

# key decryption using rsa
def decrypt(private_key,ciphertext):
    n,d=private_key
    c = ciphertext
    m=(c**d)%n
    return m

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


def server_program():

    host = socket.gethostname()
    port = 5000
    server_socket = socket.socket()
    server_socket.bind((host, port))
    server_socket.listen(5)
    conn, address = server_socket.accept()
    print("Connection from: " + str(address))
    result = publickey_privatekey()
    publickey = (result[0],result[1])
    private_key = (result[0],result[2])
    data = publickey
    conn.send(str(data).encode('utf8')) # send data to the client
    keyrecv = 0
    while True:
        while (keyrecv == 0):
            # receive data stream. it won't accept data packet greater than 1024 bytes
            data = conn.recv(1024).decode()
            encryptedkey = int(data)
            secertkey = decrypt(private_key, encryptedkey)
            keyrecv = 1
        data = conn.recv(1024).decode()
        if not data:
            # if data is not received break
            break
        message = messagedecrypt(data,secertkey)
        print("encrypted message : " + str(data))
        print("from connected user: " + str(message))
        data = input(' -> ')
        ciphertext = messageencrypt(data,secertkey)
        conn.send(ciphertext.encode())  # send data to the client

    conn.close()  # close the connection


if __name__ == '__main__':
    server_program()