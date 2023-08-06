#pragma once

#include <iostream>
#include <string>
#include <iomanip>
#include <fstream>
#include <regex>
#include <sodium.h>

#include "User.hpp" 
#include "sql/sqlite3.h"

using namespace std;

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

string crunchPass(string primary_pass){
    long hashed = 0;
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

bool newUser(string username, string email, string hash){
    sqlite3 *db;
    int res = sqlite3_open("passwordManager.db", &db);
    if(res != SQLITE_OK){
        cout << "Error opening database" << endl;
        return false;
    } // db is open successfully
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