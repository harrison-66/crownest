#pragma once

#include <iostream>
#include <string>
#include <iomanip>
#include <fstream>
#include <regex>
#include <sodium.h>
#include <crow.h>
#include <crow/middlewares/session.h>
#include <crow/middlewares/cookie_parser.h>

#include "User.hpp"
#include "sql/sqlite3.h"

using namespace std;

//TODO need to get tailwind locally

struct PasswordData { // used to store data from sql query on passwords
    std::string service;
    std::string username;
    std::string encrypted_password;
};

std::string urlDecode(std::string str){
    std::string ret;
    char ch;
    int i, ii;
    for (i=0; i<str.length(); i++) {
        if(str[i] != '%'){
            if(str[i] == '+')
                ret += ' ';
            else
                ret += str[i];
        } else {
            sscanf(str.substr(i + 1, 2).c_str(), "%x", &ii);
            ch = static_cast<char>(ii);
            ret += ch;
            i = i + 2;
        }
    }
    return ret;
}

std::string encryptPassword(std::string password) { // encrypt the password
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    randombytes_buf(nonce, sizeof nonce);
    unsigned char encrypted[crypto_secretbox_MACBYTES + password.length()];
    std::string masterKey = getMasterKey();
    unsigned char key[crypto_secretbox_KEYBYTES];

    // Create a SHA-256 hash of the master key if it's not exactly 32 bytes long
    if (masterKey.size() != crypto_secretbox_KEYBYTES) {
        crypto_hash_sha256(key, (const unsigned char*)masterKey.c_str(), masterKey.size());
    } else {
        memcpy(key, masterKey.c_str(), crypto_secretbox_KEYBYTES);
    }
    if (crypto_secretbox_easy(encrypted, (const unsigned char *)password.c_str(), password.length(), nonce, key) != 0) {
        //panic! The library couldn't encrypt the password, this should never happen
        return "";
    }

    // concatenate the nonce and the cipher text
    std::string result(nonce, nonce + sizeof nonce);
    result += std::string(encrypted, encrypted + sizeof encrypted);

    return result;
}

std::string decryptPassword(std::string encrypted_string) { // decrypt the password
    if (encrypted_string.length() < crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES) {
        //panic! the encrypted password is not valid
        cerr << "Encrypted password is not valid" << endl;
        return "";
    }

    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    std::copy(encrypted_string.begin(), encrypted_string.begin() + crypto_secretbox_NONCEBYTES, nonce);

    unsigned char encrypted[encrypted_string.length() - crypto_secretbox_NONCEBYTES];
    std::copy(encrypted_string.begin() + crypto_secretbox_NONCEBYTES, encrypted_string.end(), encrypted);

    std::string masterKey = getMasterKey();
    unsigned char key[crypto_secretbox_KEYBYTES];

    // Create a SHA-256 hash of the master key if it's not exactly 32 bytes long
    if (masterKey.size() != crypto_secretbox_KEYBYTES) {
        crypto_hash_sha256(key, (const unsigned char*)masterKey.c_str(), masterKey.size());
    } else {
        memcpy(key, masterKey.c_str(), crypto_secretbox_KEYBYTES);
    }
    unsigned char decrypted[encrypted_string.length() - crypto_secretbox_NONCEBYTES - crypto_secretbox_MACBYTES];
    if (crypto_secretbox_open_easy(decrypted, encrypted, sizeof encrypted, nonce, key) != 0) {
        //panic! the decryption failed, maybe the password was tampered with
        return "";
    }

    return std::string(decrypted, decrypted + sizeof decrypted);
}

string escapeString(const string& input) {
    string escapedString;
    for (char c : input) {
        switch (c) {
            case '\'':
                escapedString += "''"; // Replace single quote with two single quotes
                break;
            case '\"':
                escapedString += "\\\""; // Replace double quote with backslash and double quote
                break;
            case '\\':
                escapedString += "\\\\"; // Replace backslash with double backslash
                break;
            case '\0':
                escapedString += "\\0"; // Replace null character with backslash and zero
                break;
            case '\b':
                escapedString += "\\b"; // Replace backspace with backslash and b
                break;
            case '\n':
                escapedString += "\\n"; // Replace newline with backslash and n
                break;
            case '\r':
                escapedString += "\\r"; // Replace carriage return with backslash and r
                break;
            case '\t':
                escapedString += "\\t"; // Replace tab with backslash and t
                break;
            case '\x1A':
                escapedString += "\\Z"; // Replace Ctrl+Z (substitute) with backslash and Z
                break;
            // Add more cases for other special characters if needed
            default:
                escapedString += c;
        }
    }
    return escapedString;
}

int currentUserID(string username){//* assumes username is safe, considering it is from session data after a safe login
    sqlite3 *db;
    int res = sqlite3_open("passwordManager.db", &db);
    if(res != SQLITE_OK){
        cout << "Error opening database" << endl;
        return -2;
    }
    const char* query = "SELECT id FROM users WHERE username = :username;";
    sqlite3_stmt *stmt; // prepared statement
    res = sqlite3_prepare_v2(db, query, -1, &stmt, NULL); // -1 means query is null terminated, stmt is the prepared statement
    if(res != SQLITE_OK){ // if there is an error
        cout << "Error preparing statement: " << sqlite3_errmsg(db) << endl;
        sqlite3_close(db);
        return -2;
    }
    res = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":username"), username.c_str(), -1, SQLITE_STATIC);
    if (res != SQLITE_OK) {
        cout << "Error binding username parameter: " << sqlite3_errmsg(db) << endl;
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -2;
    }
    res = sqlite3_step(stmt); // execute the prepared statement
    if(res == SQLITE_ROW){ // if there is a row, then the username exists
        int id = sqlite3_column_int(stmt, 0);
        sqlite3_finalize(stmt); // finalize the prepared statement
        sqlite3_close(db); // close the database
        return id; // return true
    }
    sqlite3_finalize(stmt); // finalize the prepared statement
    sqlite3_close(db);// close the database
    return -1; // return false
}

bool existingPassword(string service, string username){ // check if the password already exists for the user
    sqlite3 *db;
    int res = sqlite3_open("passwordManager.db", &db);
    if(res != SQLITE_OK){
        cout << "Error opening database" << endl;
        return false;
    }
    string query = "SELECT * FROM passwords WHERE service = :service AND username = :username;";
    sqlite3_stmt *stmt; // prepared statement
    res = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, NULL); // -1 means query is null terminated, stmt is the prepared statement
    if(res != SQLITE_OK){ // if there is an error
        cout << "Error preparing statement: " << sqlite3_errmsg(db) << endl;
        sqlite3_close(db);
        return false;
    }
    // Bind parameters to the prepared statement using named placeholders
    res = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":service"), service.c_str(), -1, SQLITE_STATIC);
    if (res != SQLITE_OK) {
        cout << "Error binding service parameter: " << sqlite3_errmsg(db) << endl;
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return false;
    }

    res = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":username"), username.c_str(), -1, SQLITE_STATIC);
    if (res != SQLITE_OK) {
        cout << "Error binding username parameter: " << sqlite3_errmsg(db) << endl;
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return false;
    }
    res = sqlite3_step(stmt); // execute the prepared statement
    if(res == SQLITE_ROW){ // if there is a row, then the username exists
        sqlite3_finalize(stmt); // finalize the prepared statement
        sqlite3_close(db); // close the database
        return true; // return true
    }
    sqlite3_finalize(stmt); // finalize the prepared statement
    sqlite3_close(db);// close the database
    return false; // return false
}

bool insertPassword(string mainUsername, string service, string username_, string password){ // add a password to the database
    string encrypted_password = encryptPassword(password);
    sqlite3 *db;
    int res = sqlite3_open("passwordManager.db", &db);
    if(res != SQLITE_OK){
        cout << "Error opening database" << endl;
        return false;
    }
    if(existingPassword(service, username_)){
        cout << "Password already exists for this service and username" << endl;
        return false;
    }
    string query = "INSERT INTO passwords (userID, service, username, encrypted_password) VALUES (:userID, :service, :username, :encrypted_password);";
    sqlite3_stmt *stmt; // prepared statement
    res = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, NULL); // -1 means query is null terminated, stmt is the prepared statement
    if(res != SQLITE_OK){ // if there is an error
        cout << "Error preparing statement: " << sqlite3_errmsg(db) << endl;
        sqlite3_close(db);
        return false;
    }
        // Bind parameters to the prepared statement using named placeholders
    res = sqlite3_bind_int(stmt, sqlite3_bind_parameter_index(stmt, ":userID"), currentUserID(mainUsername));
    if (res != SQLITE_OK) {
        cout << "Error binding userID parameter: " << sqlite3_errmsg(db) << endl;
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return false;
    }

    res = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":service"), service.c_str(), -1, SQLITE_STATIC);
    if (res != SQLITE_OK) {
        cout << "Error binding service parameter: " << sqlite3_errmsg(db) << endl;
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return false;
    }

    res = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":username"), username_.c_str(), -1, SQLITE_STATIC);
    if (res != SQLITE_OK) {
        cout << "Error binding username parameter: " << sqlite3_errmsg(db) << endl;
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return false;
    }

    res = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":encrypted_password"), encrypted_password.c_str(), -1, SQLITE_STATIC);
    if (res != SQLITE_OK) {
        cout << "Error binding encrypted_password parameter: " << sqlite3_errmsg(db) << endl;
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return false;
    }
    res = sqlite3_step(stmt); // execute the prepared statement
    if(res != SQLITE_DONE){ // if there is a row, then the username exists, and the password was not inserted
        cout << "Error inserting into database: " << sqlite3_errmsg(db) << endl;
        sqlite3_finalize(stmt); // finalize the prepared statement
        sqlite3_close(db); // close the database
        return false; // return false, as the password was not inserted
    }
    sqlite3_finalize(stmt); // finalize the prepared statement
    sqlite3_close(db);// close the database
    return true; // return true
}

bool createUserTable(){
    sqlite3 *db;
    int res = sqlite3_open("passwordManager.db", &db);
    if(res != SQLITE_OK){
        cout << "Error opening database" << endl;
        return false;
    }
    const char* userTableQuery = "CREATE TABLE IF NOT EXISTS users ("
                                "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                                "username TEXT NOT NULL,"
                                "email TEXT NOT NULL,"
                                "hash TEXT NOT NULL);";
    res = sqlite3_exec(db, userTableQuery, NULL, NULL, NULL);
    if(res != SQLITE_OK){
        cout << "Error creating table: " << sqlite3_errmsg(db) << endl;
        sqlite3_close(db);
        return false;
    }
    sqlite3_close(db);
    return true;
}

bool createPasswordTable(){
    sqlite3 *db;
    int res = sqlite3_open("passwordManager.db", &db);
    if(res != SQLITE_OK){
        cout << "Error opening database" << endl;
        return false;
    }
    const char* passwordTableQuery = "CREATE TABLE IF NOT EXISTS passwords (id INTEGER PRIMARY KEY AUTOINCREMENT,userID INTEGER NOT NULL,service TEXT NOT NULL,username TEXT NOT NULL,encrypted_password TEXT NOT NULL,FOREIGN KEY (userID) REFERENCES users (id));";
    res = sqlite3_exec(db, passwordTableQuery, NULL, NULL, NULL);
    if(res != SQLITE_OK){
        cout << "Error creating table: " << sqlite3_errmsg(db) << endl;
        sqlite3_close(db);
        return false;
    }
    sqlite3_close(db);
    return true;
}

bool usernameExists(string username){ // checks the Users table
    cout << username << endl;
    sqlite3 *db;
    int res = sqlite3_open("passwordManager.db", &db);
    if(res != SQLITE_OK){
        cout << "Error opening database" << endl;
        return false;
    }
    string query = "SELECT * FROM users WHERE username = :username;";
    sqlite3_stmt *stmt; // prepared statement
    res = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, NULL); // -1 means query is null terminated, stmt is the prepared statement
    if(res != SQLITE_OK){ // if there is an error
        cout << "Error preparing statement: " << sqlite3_errmsg(db) << endl;
        sqlite3_close(db);
        return false;
    }
    res = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":username"), username.c_str(), -1, SQLITE_STATIC);
    if (res != SQLITE_OK) {
        cout << "Error binding username parameter: " << sqlite3_errmsg(db) << endl;
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return false;
    }
    res = sqlite3_step(stmt); // execute the prepared statement
    if(res == SQLITE_ROW){ // if there is a row, then the username exists
        sqlite3_finalize(stmt); // finalize the prepared statement
        sqlite3_close(db); // close the database
        return true; // return true
    }
    sqlite3_finalize(stmt); // finalize the prepared statement
    sqlite3_close(db);// close the database
    return false; // return false
}

bool emailExists(string email){
    sqlite3 *db;
    int res = sqlite3_open("passwordManager.db", &db);
    if(res != SQLITE_OK){
        cout << "Error opening database" << endl;
        return false;
    }
    string query = "SELECT * FROM users WHERE email = :email;";
    sqlite3_stmt *stmt; // prepared statement
    res = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, NULL); // -1 means query is null terminated, stmt is the prepared statement
    if(res != SQLITE_OK){ // if there is an error
        cout << "Error preparing statement: " << sqlite3_errmsg(db) << endl;
        sqlite3_close(db);
        return false;
    }
    // Bind the parameter to the prepared statement using named placeholder
    res = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":email"), email.c_str(), -1, SQLITE_STATIC);
    if (res != SQLITE_OK) {
        cout << "Error binding email parameter: " << sqlite3_errmsg(db) << endl;
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return false;
    }
    res = sqlite3_step(stmt); // execute the prepared statement
    if(res == SQLITE_ROW){ // if there is a row, then the username exists
        sqlite3_finalize(stmt); // finalize the prepared statement
        sqlite3_close(db); // close the database
        return true; // return true
    }
    sqlite3_finalize(stmt); // finalize the prepared statement
    sqlite3_close(db);// close the database
    return false; // return false
}

bool validEmail(string email){ // regex check, found on stackoverflow
    const regex pattern("(\\w+)(\\.|_)?(\\w*)@(\\w+)(\\.(\\w+))+");
    return regex_match(email,pattern);
}

std::string hashPassword(const std::string& password) {
    // Generate a random salt
    unsigned char salt[crypto_pwhash_SALTBYTES];
    randombytes_buf(salt, sizeof(salt));

    // Hash the password
    std::vector<char> hash(crypto_pwhash_STRBYTES);
    if (crypto_pwhash_str(
            hash.data(), password.c_str(), password.length(),
            crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0) {
        std::cerr << "Error hashing password" << std::endl;
        return "";
    }

    // Construct the hash string by directly appending hash and salt
    std::string hash_str;
    hash_str.reserve(crypto_pwhash_STRBYTES + crypto_pwhash_SALTBYTES);
    hash_str.append(hash.data(), crypto_pwhash_STRBYTES);
    hash_str.append(reinterpret_cast<const char*>(salt), crypto_pwhash_SALTBYTES);

    return hash_str;
}

string crunchPass(string primary_pass){//! DEPRECATED, use hashPassword instead
    long hashed = 0; //! DO NOT USE, extremely insecure
    string reversed;
    int dig_count = 0;

    for (int i = 0; i < primary_pass.length(); i++){// Hash the user's input password and store it in the 'hashed' variable
        if(i != primary_pass.length() - 1){
            hashed += primary_pass[i] * primary_pass[i+1];
            hashed += primary_pass[i] * primary_pass[i] * primary_pass[i];
        }else{
            hashed += primary_pass[i] * primary_pass[0]; // arbitrary value for last dig mult
        }
    }
    while (hashed > 0){ // Convert the 'hashed' value into a string i guess
        int temp = 0;
        temp = hashed % 10;
        hashed = hashed / 10;
        char current = char(temp + 48);
        reversed += current;
        dig_count++;
    }
    // reverse the string, return as long
    string to_write;
    for (int i = (dig_count-1); i >= 0; i--){
        to_write += reversed[i];
    }
    return to_write;
} 

string printAllPasswords(string username){
    stringstream htmlOutput;
    sqlite3 *db;
    int res = sqlite3_open("passwordManager.db", &db);
    if(res != SQLITE_OK){
        cout << "Error opening database" << endl;
        return "<p>Error retrieving passwords</p>";
    }
    //escapeString(username);
    string query = "SELECT service, username, encrypted_password FROM passwords WHERE userID = :userID;";
    vector<PasswordData> passwordArray;
    sqlite3_stmt* stmt;
    res = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr);
    if (res != SQLITE_OK) {
        cout << "Error preparing query: " << sqlite3_errmsg(db) << endl;
        sqlite3_close(db);
        return "<p>Error retrieving passwords</p>";
    }
    // Bind parameters to the prepared statement using named placeholders
    res = sqlite3_bind_int(stmt, sqlite3_bind_parameter_index(stmt, ":userID"), currentUserID(username));
    if (res != SQLITE_OK) {
        cout << "Error binding parameter: " << sqlite3_errmsg(db) << endl;
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return "<p>Error retrieving passwords</p>";
    }
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        PasswordData password;
        password.service = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        password.username = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        password.encrypted_password = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));

        passwordArray.push_back(password);
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    // Close the database connection
    int i = 1;
    for (const auto& password : passwordArray) {
        /*htmlOutput << "<div id=\"card" << i << "\" class=\"bg-gray-900 rounded-lg shadow p-4 border-2 border-rose-900 hover:border-rose-700 mt-4\">\n";
        htmlOutput << "<h2 class=\"text-2xl text-gray-400 font-bold mb-1\">" << password.service << "</h2>\n";
        htmlOutput << "<p class=\"text-sm text-gray-400 mb-2\">" << password.username << "</p>\n";
        htmlOutput << "<div class=\"relative w-full\">\n";
        //htmlOutput << "<button data-service=\"" << password.service << "\" data-username=\"" << password.username << "\" class=\"delete-btn bg-red-500 hover:bg-red-700 text-white py-1 px-2 rounded\">Delete</button>\n";
        htmlOutput << "<div class=\"absolute inset-y-0 right-0 flex items-center px-2\">\n";
        htmlOutput << "<input class=\"hidden password-toggle\" id=\"toggle" << i << "\" type=\"checkbox\" />\n";
        htmlOutput << "<label class=\"bg-gray-300 hover:bg-gray-400 rounded px-2 py-1 text-sm text-gray-600 font-mono cursor-pointer password-label\" for=\"toggle" << i << "\">show</label>\n";
        htmlOutput << "</div>\n";
        htmlOutput << "<input class=\"appearance-none border-2 rounded w-full py-3 px-3 leading-tight border-gray-300 bg-gray-100 focus:outline-none focus:border-rose-900 focus:bg-white text-gray-700 pr-16 font-mono password-field\" id=\"password" << i << "\" type=\"password\" value=\"" << decryptPassword(password.encrypted_password) << "\" readonly/>\n";
        htmlOutput << "</div>\n";
        htmlOutput << "</div>\n";*/
        htmlOutput << "<div id=\"card" << i << "\" class=\"bg-gray-900 rounded-lg shadow p-4 border-2 border-rose-900 hover:border-rose-700 mt-4\">\n";

// Introducing a flex container for service, username, and delete button
        htmlOutput << "<div class=\"flex justify-between items-start mb-2\">\n";
        htmlOutput << "<div>\n";  // Container for service and username
        htmlOutput << "<h2 class=\"text-2xl text-gray-400 font-bold mb-1\">" << password.service << "</h2>\n";
        htmlOutput << "<p class=\"text-sm text-gray-400\"> User: " << password.username << "</p>\n";
        htmlOutput << "</div>\n";  // End of container for service and username
        htmlOutput << "<button data-service=\"" << password.service << "\" data-username=\"" << password.username << "\" class=\"delete-btn bg-red-500 hover:bg-red-700 text-white mt-1 py-1 px-2 rounded\">Delete</button>\n";
        htmlOutput << "</div>\n";  // End of flex container

        htmlOutput << "<div class=\"relative w-full\">\n";
        htmlOutput << "<div class=\"absolute inset-y-0 right-0 flex items-center px-2\">\n";
        htmlOutput << "<input class=\"hidden password-toggle\" id=\"toggle" << i << "\" type=\"checkbox\" />\n";
        htmlOutput << "<label class=\"bg-gray-300 hover:bg-gray-400 rounded px-2 py-1 text-sm text-gray-600 font-mono cursor-pointer password-label\" for=\"toggle" << i << "\">show</label>\n";
        htmlOutput << "</div>\n";
        htmlOutput << "<input class=\"appearance-none border-2 rounded w-full py-3 px-3 leading-tight border-gray-300 bg-gray-100 focus:outline-none focus:border-rose-900 focus:bg-white text-gray-700 pr-16 font-mono password-field\" id=\"password" << i << "\" type=\"password\" value=\"" << decryptPassword(password.encrypted_password) << "\" readonly/>\n";
        htmlOutput << "</div>\n";
        htmlOutput << "</div>\n";
        ++i;
    }
    
    return htmlOutput.str();
}


bool newUser(string username, string email, string hash){
    sqlite3 *db;
    int res = sqlite3_open("passwordManager.db", &db);
    if(res != SQLITE_OK){
        cout << "Error opening database" << endl;
        return false;
    } // db is open successfully
    //escapeString(username);
    //escapeString(email);
    string query = "INSERT INTO users (username, email, hash) VALUES (:username, :email, :hash);";
    sqlite3_stmt *stmt; // prepared statement
    res = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, NULL); // -1 means query is null terminated, stmt is the prepared statement
    if(res != SQLITE_OK){ // if there is an error
        cout << "Error preparing statement: " << sqlite3_errmsg(db) << endl;
        sqlite3_close(db);
        return false;
    }
        // Bind the parameters to the prepared statement using named placeholders
    res = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":username"), username.c_str(), -1, SQLITE_STATIC);
    if (res != SQLITE_OK) {
        cout << "Error binding username parameter: " << sqlite3_errmsg(db) << endl;
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return false;
    }

    res = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":email"), email.c_str(), -1, SQLITE_STATIC);
    if (res != SQLITE_OK) {
        cout << "Error binding email parameter: " << sqlite3_errmsg(db) << endl;
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return false;
    }

    res = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":hash"), hash.c_str(), -1, SQLITE_STATIC);
    if (res != SQLITE_OK) {
        cout << "Error binding hash parameter: " << sqlite3_errmsg(db) << endl;
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return false;
    }
    res = sqlite3_step(stmt); // execute the prepared statement
    if(res != SQLITE_DONE){ // if result is not done then there is an error
        cout << "Error inserting user: " << sqlite3_errmsg(db) << endl;
        sqlite3_finalize(stmt); // finalize the prepared statement
        sqlite3_close(db); // close the database
        return false; // return true
    }
    sqlite3_finalize(stmt); // finalize the prepared statement
    sqlite3_close(db);// close the database
    return true; // return true, since user was inserted
}


/*bool verifyLogin(const std::string& username, const std::string& password) {
    sqlite3* db;
    int res = sqlite3_open("passwordManager.db", &db);
    if (res != SQLITE_OK) {
        std::cout << "Error opening database" << std::endl;
        return false;
    }

    std::string query = "SELECT * FROM users WHERE username = ? AND hash = ?;";
    sqlite3_stmt* stmt; // prepared statement
    res = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, NULL);
    if (res != SQLITE_OK) {
        std::cout << "Error preparing statement: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_close(db);
        return false;
    }

    res = sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    if (res != SQLITE_OK) {
        std::cout << "Error binding username parameter: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return false;
    }

    std::string hashedPassword = crunchPass(password); // Hash the password before comparing
    res = sqlite3_bind_text(stmt, 2, hashedPassword.c_str(), -1, SQLITE_STATIC);
    if (res != SQLITE_OK) {
        std::cout << "Error binding password parameter: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return false;
    }

    res = sqlite3_step(stmt);
    if (res == SQLITE_ROW) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return true;
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return false;
}*/
bool verifyLogin(const std::string& username, const std::string& password) {
    sqlite3* db;
    int res = sqlite3_open("passwordManager.db", &db);
    if (res != SQLITE_OK) {
        std::cout << "Error opening database" << std::endl;
        return false;
    }
    //escapeString(username);
    std::string query = "SELECT hash FROM users WHERE username = ?;";
    sqlite3_stmt* stmt; // prepared statement
    res = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, NULL);
    if (res != SQLITE_OK) {
        std::cout << "Error preparing statement: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_close(db);
        return false;
    }

    res = sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    if (res != SQLITE_OK) {
        std::cout << "Error binding username parameter: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return false;
    }

    res = sqlite3_step(stmt);
    if (res == SQLITE_ROW) {
        const unsigned char* storedHash = sqlite3_column_text(stmt, 0); // Assuming the hash column is at index 0
        std::string storedHashStr(reinterpret_cast<const char*>(storedHash));
        
        bool loginVerified = verifyPassword(password, storedHashStr);
        
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return loginVerified;
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return false;
}

bool deletePassword(string service, string username, string mainUsername){ //* assumes username is safe, considering it is from session data after a safe login
    sqlite3 *db;
    int res = sqlite3_open("passwordManager.db", &db);
    if(res != SQLITE_OK){
        cout << "Error opening database" << endl;
        return false;
    }
    //escapeString(service);
    //escapeString(username);
    string query = "DELETE FROM passwords WHERE userID = :userID AND service = :service AND username = :username;";
    sqlite3_stmt *stmt; // prepared statement
    res = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, NULL); // -1 means query is null terminated, stmt is the prepared statement
    if(res != SQLITE_OK){ // if there is an error
        cout << "Error preparing statement" << endl;
        sqlite3_close(db);
        return false;
    }
        // Bind parameters to the prepared statement using named placeholders
    res = sqlite3_bind_int(stmt, sqlite3_bind_parameter_index(stmt, ":userID"), currentUserID(mainUsername));
    if (res != SQLITE_OK) {
        cout << "Error binding userID parameter" << endl;
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return false;
    }
    res = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":service"), service.c_str(), -1, SQLITE_STATIC);
    if (res != SQLITE_OK) {
        cout << "Error binding service parameter" << endl;
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return false;
    }
    res = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":username"), username.c_str(), -1, SQLITE_STATIC);
    if (res != SQLITE_OK) {
        cout << "Error binding username parameter" << endl;
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return false;
    }
    res = sqlite3_step(stmt); // execute the prepared statement
    if(res != SQLITE_DONE){ // if there is a row, then the username exists
        cerr << "Error deleting from database" << endl;
        sqlite3_finalize(stmt); // finalize the prepared statement
        sqlite3_close(db); // close the database
        return false; // return true
    }
    sqlite3_finalize(stmt); // finalize the prepared statement
    sqlite3_close(db);// close the database
    return true; // return false
}