// First major update -> Adding classes, and allowing for multiple users.
// g++17 compile command: g++ -std=c++17 main.cpp User.cpp -lsqlite3 -o main

#include <iostream>
#include <string>
#include <iomanip>
#include <fstream>
#include <regex>

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

int main(){
    createUserTable();
    createPasswordTable();
    User current = User();
    bool signedIn = false;
    while(!signedIn){
        cout << "Welcome to the Password Manager!" << endl;
        cout << "1. Create a new user\n2. Sign-in" << endl;
        int choice;
        cin >> choice;
        if(choice == 1){
            cout << "Enter a username: ";
            string username;
            cin >> username;
            if(username.length() > 20){
                cout << "Username too long" << endl;
                return 1;
            }
            if(usernameExists(username)){
                cout << "Username already exists" << endl;
                return 1;
            }
            cout << "Enter your email: ";
            string email;
            cin >> email;
            if(emailExists(email)){
                cout << "Email already exists" << endl;
                return 1;
            }
            if(!validEmail(email)){
                cout << "Invalid email" << endl;
                return 1;
            }
            cout << "Enter a master password: ";
            string master;
            cin >> master;
            string hash = crunchPass(master);
            if(!newUser(username, email, hash)){
                cout << "Error creating user" << endl;
                return 1;
            }
        }else if(choice == 2){
            cout << "Enter your username: ";
            string username;
            cin >> username;
            if(!usernameExists(username)){
                cout << "Username does not exist" << endl;
                return 1;
            }
            cout << "Enter your master password: ";
            string master;
            cin >> master;
            current = User(username, master);
            if(current.verifyUser()){
                signedIn = true;
            }else{
                cout << "Invalid username or password" << endl;
                return 1;
            }
        }else{
            cout << "Invalid choice" << endl;
            return 1;
        }
    }
    while(1){ // main loop, access has been verified, and current user object instantiated
        cout << "1. Add a new password\n2. View a specific password\n3. View all passwords\n4. Delete a password\n5. Exit" << endl;
        int choice;
        cin >> choice;
        if(choice == 1){
            cout << "Enter the service: ";
            string service;
            cin >> service;
            cout << "Enter the username: ";
            string username;
            cin >> username;
            cout << "Enter the password: ";
            string password;
            cin >> password;
            service = escapeString(service);
            username = escapeString(username);
            password = escapeString(password);
            current.addPassword(service, username, password);
        }else if(choice == 2){
            cout << "Enter the service: ";
            string service;
            cin >> service;
            service = escapeString(service);
            current.getServicePasswords(service);
        }else if(choice == 3){
            current.printAllPasswords();
        }else if(choice == 4){
            cout << "Enter the service: ";
            string service;
            cin >> service;
            cout << "Enter the username: ";
            string username;
            cin >> username;
            service = escapeString(service);
            username = escapeString(username);
            current.deletePassword(service, username);
        }else if(choice == 5){
            return 0;
        }else{
            cout << "Invalid choice" << endl;
            cin.clear();
        }
    }
    return 0;
}