import socket
import threading 

def vigenere_encrypt(text, key):
    '''
    Encrypts the inputted text using the Vigenere cipher with a given key, handles both upper and lower case letters.

    Args:
        text (str): The text to be encrypted.
        key (str): The key used to encrypt the text (must be all uppercase or lowercase), the key is repeated if its
                   length is shorter than the inputted text. 
    
    Returns: 
        str: The encrypted message, alphabetic characters are encrypted using the Vigenere cipher with the provided 
             key while non-alphabetic characters remain the same. 
    '''
    encryptedMessage = ""
    for index, char in enumerate(text):
        if char.isalpha():
            shift = ord(key[index % len(key)].upper()) - ord('A')
            if char.islower():
                encryptedMessage += chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
            else:
                encryptedMessage += chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
        else:
            encryptedMessage += char
    return encryptedMessage 

def vigenere_decrypt(text, key):
    '''
    Decrypts the inputted text using the Vigenere cipher with a given key, handles both upper and lower case letters.
    
    Args:
        text (str): The text to be decrypted.
        key (str): The key used to decrypt the text (must be all uppercase or lowercase), the key is repeated if its 
                   length is shorter than the inputted text.

    Returns:
        str: The decrypted message, alphabetic characters are decrypted using the Vigenere cipher with the provided 
             key while non-alphabetic characters remain the same. 
    '''
    decryptedMessage = ""
    for index, char in enumerate(text):
        if char.isalpha():
            shift = ord(key[index % len(key)].upper()) - ord('A')
            if char.islower():
                decryptedMessage += chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
            else:
                decryptedMessage += chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
        else:
            decryptedMessage += char
    return decryptedMessage 

def server_communication(connection, key):
    '''
    Handles communication with the client using predefined answers for given questions.

    Args:
        connection (socket.socket): The socket connection to the client.
        key (str): The Vigenere cipher key for encryption and decryption.
    '''
    while True:
        try:
            encrypted_message = connection.recv(1024).decode()
            if not encrypted_message:
                print("Client disconnected.")
                break

            print(f"Encrypted question received: {encrypted_message}")
            decrypted_message = vigenere_decrypt(encrypted_message, key)
            print(f"Decrypted question: {decrypted_message}\n")

            answer = input("Enter your response: ")
            encrypted_answer = vigenere_encrypt(answer, key)
            connection.send(encrypted_answer.encode())
            print(f"Encrypted answer sent: {encrypted_answer}\n\n")
        except Exception as e:
            print(f"An error occurred: {e}")
            break

    connection.close()

def initialize_client_thread(connection, key):
    '''
    Initializes a thread to handle a client connection.

    Args:
        connection (socket.socket): The socket connection to the client.
        key (str): The Vigenere cipher key for encryption and decryption.
    '''
    client_thread = threading.Thread(target=server_communication, args=(connection, key))
    client_thread.start()

def main(host, port, key):
    '''
    Starts the server and waits for client connection.

    Args:
        host (str): The host IP address for the server.
        port (int): The port number the server listens on.
        key (str): The Vigenere cipher key for encryption and decryption.
    '''
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(10)
    print(f"Server is listening for connections")
    try:
        while True:
            connection, address = server_socket.accept()
            print(f"Connection established with {address}\n")
            initialize_client_thread(connection, key)
            
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        server_socket.close()

if __name__ == "__main__":
    main('127.0.0.1', 8000, "HELLO")
