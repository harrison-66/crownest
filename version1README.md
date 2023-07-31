# Password Manager with Homemade Encryption Algorithm - Version 1
This is Version 1 of a rudimentary password manager that uses a homemade encryption algorithm. The manager allows you to store and retrieve passwords for various services, secured with a master password. Even if someone resets the master password, the passwords stored in the manager will remain encrypted and safe.

## How It Works
The password manager is implemented in C++ and includes the following functionalities:

1. **Set Master Password**: If the master password is not already set, the program prompts you to set a new master password during the first run.

2. **Access Passwords**: You can access stored passwords for various services by providing the correct master password. The manager will unhash the passwords using a homemade encryption algorithm.

3. **Add a Password**: You can add passwords for new services to the manager. The passwords are encrypted using the homemade algorithm and then stored securely.

4. ***Print All Passwords***: For testing purposes, there is a hidden option(420) to print all stored passwords, but you need to enter the master password to access this functionality.

## Encryption Algorithm
The homemade encryption algorithm is based on simple mathematical operations to hash and unhash passwords. The algorithm includes the following steps:

- **Hashing**: The master password is hashed into a long integer value.

- **Salting**: A salt value is generated from the master password to provide additional security.

- **Encryption**: The password for each service is encrypted using XOR with the generated salt.

- **Decryption**: To retrieve the password, the encrypted value is XORed again with the salt.

## How to Use
1. Compile and run the C++ program.

2. If this is your first time running the program, you will be prompted to set a new master password.

3. After setting the master password, you can choose from the following options:

    - **Access Passwords (1)**: Enter the service for which you want to retrieve the password, and then provide the master password.
    - **Add a Password (2)**: Enter the service and the password you want to store, and then provide the master password.
    - **Exit (3)**: End the program.
Remember to keep your master password secure, as it's crucial for accessing the stored passwords.

### Note
This is Version 1 of the password manager and may have some rough spots. Future updates are planned to improve security, usability, and overall functionality. Always ensure you have backup copies of your passwords and the master password in a safe and secure location.

**Important**: This homemade encryption algorithm is not as secure as industry-standard encryption methods. For increased security, it is recommended to use well-established encryption libraries and algorithms.

Please feel free to contribute to the project or report any issues you encounter.
Contact me @ harrison.getches@colorado.edu
