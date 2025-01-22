import socket

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


def client_communication(connection, key):
    '''
    Handles communication with the server.

    Args:
        connection (socket.socket): The socket connection to the server.
        key (str): The Vigenere cipher key for encryption and decryption.
    '''
    while True:
        try:
            message = input("Enter your question: ")
            encrypted_message = vigenere_encrypt(message, key)
            connection.send(encrypted_message.encode())
            print(f"Encrypted question sent: {encrypted_message}\n")
            encrypted_answer = connection.recv(1024).decode()
            if not encrypted_answer:
                print("Server disconnected.")
                break
            print(f"Encrypted answer received: {encrypted_answer}")
            decrypted_answer = vigenere_decrypt(encrypted_answer, key)
            print(f"Decrypted answer: {decrypted_answer}\n\n")
        except Exception as e:
            print(f"An error occurred: {e}")
            break
    connection.close()

def main(host, port, key):
    '''
    Starts the client and connects to the server to manage communication.

    Args:
        host (str): The host IP address of the server.
        port (int): The port number to establish connections.
        key (str): The Vigenere cipher key for encryption and decryption.
    '''
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((host, port))
        print("Connected to the server.\n")
        client_communication(client_socket, key)
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        client_socket.close()

if __name__ == "__main__":
    main("127.0.0.1", 8000, "HELLO")
