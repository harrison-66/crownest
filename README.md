# Password Manager Project
This project is a simple command-line password manager written in C++. It allows users to create an account, store passwords for different services, and retrieve them securely. The passwords are encrypted and stored in an SQLite database, ensuring security for the user's sensitive information.

## Usage
### Compilation
To compile the project, use the following g++ command:

```shell
g++ -std=c++17 main.cpp User.cpp -lsqlite3 -o main
```
### Creating Tables
Before using the password manager, you need to create the necessary tables in the SQLite database. To do this, call the createUserTable() and createPasswordTable() functions. These functions create the 'users' and 'passwords' tables, respectively, to store user information and encrypted passwords.

### Creating a New User
To create a new user, run the password manager and select option 1 from the menu. You will be prompted to provide a unique username, a valid email address, and a master password. The master password is used to secure your account and should be something memorable yet strong.

### Signing In
After creating a user, you can sign in by selecting option 2 from the menu. Enter your username and master password to access your account.

### Adding a New Password
Once signed in, you can add passwords for different services. Choose option 1 from the menu and provide the service name, username, and password. The password will be encrypted and securely stored in the database.

### Viewing Specific Passwords
To view passwords for a specific service, select option 2 from the menu. Enter the service name, and the decrypted passwords associated with that service will be displayed.

### Viewing All Passwords
To view all stored passwords, select option 3 from the menu. The program will display the service name, associated username, and decrypted passwords for each entry.

### Deleting a Password (not implemented)
Option 4 from the menu is meant to delete a password entry, but this feature is not yet implemented.

### Exiting the Password Manager
Select option 5 from the menu to exit the password manager.

## Code Structure
The project consists of two main files:

[main.cpp](main.cpp): This file contains the main functionality of the password manager. It handles user interaction, input validation, and communication with the database.
[User.cpp](User.cpp): This file defines the User class and its methods. The class represents a user account and handles encryption and decryption of passwords.
The [User.hpp](User.hpp) header file is included in both files, defining the User class and the necessary libraries.

Note: The password manager is a basic implementation for educational purposes and may lack some advanced features typically found in commercial password managers. It is essential to follow best practices for password management and security.

Version 1 Markdown found [here](version1README.md)
