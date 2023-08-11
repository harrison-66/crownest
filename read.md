# Crownest
A robust C++ based password manager with a web interface using Crow. This project not only securely stores your passwords but also provides an intuitive web interface to manage them. With strong encryption provided by libsodium, you can ensure your passwords are safe.

## Features
- Secure Storage: Passwords are encrypted using libsodium before being stored, ensuring the highest level of security.
- Web Interface: Manage your passwords easily through a web interface powered by Crow.
- URL Decoding: Decode URL-encoded strings with ease.
- Password Data Struct: Organize your passwords with associated services and usernames.
- File Serving: Serve images and other files as needed.
## Dependencies
- [libsodium](https://libsodium.gitbook.io/doc/) - For encryption and decryption of passwords.
- [mini config parser](https://github.com/hyperrealm/libconfig) - For configuration parsing.
- [sqlite](https://www.sqlite.org/index.html) - Lightweight database for storing password data.
- [nlohmann json parser](https://github.com/nlohmann/json) - For handling JSON data.
- [Crow web server](https://github.com/CrowCpp/Crow) - For the web server and interface.
- [TailwindCSS](https://tailwindcss.com) - Tailwind CSS for styling
## Compilation & Installation
g++ compile command is as follows

```bash
g++ -std=c++11 -I./Crow/include -I/opt/homebrew/Cellar/asio/1.28.1/include crowServer.cpp User.cpp -lsqlite3 -lsodium -lpthread -o my_crow_app
```
*(Note: Ensure all dependencies are installed and paths are correctly specified before compilation.)*

## Usage
- Create a config.ini file containing a 64 character Hex string for encryption base (master_key)
- Run the compiled binary: ./my_crow_app
- Open your browser and navigate to the specified server address (e.g., localhost:port).
- Use the web interface to manage your passwords.
## Project Structure
- crowServer.cpp: Main server logic and Crow setup.
- crowFunctions.hpp: Essential functions related to Crow and other utilities.
- src folder: contains HTML, CSS, JS, and jpg/ico files
Contribution & Issues
Feel free to contribute to this project by submitting pull requests. If you encounter any issues, please open an issue on the project's GitHub repository.

### License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
