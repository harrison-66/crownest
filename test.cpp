#include <iostream>
#include <string>
#include <iomanip>
#include <fstream>
#include <regex>

// g++17 command: g++ -std=c++17 test.cpp -lsqlite3 -o test

//#include "User.hpp" 
#include "sql/sqlite3.h"

using namespace std;

void showUsersTable() {
    sqlite3* db;
    int result = sqlite3_open("passwordManager.db", &db);

    if (result != SQLITE_OK) {
        std::cerr << "Error opening the database: " << sqlite3_errmsg(db) << std::endl;
        return;
    }

    std::string selectQuery = "SELECT * FROM users;";

    result = sqlite3_exec(
        db,
        selectQuery.c_str(),
        [](void* data, int argc, char** argv, char** colName) -> int {
            // This callback function will be called for each row returned by the query
            // Here, we'll print the user details for each row
            std::cout << "User ID: " << argv[0] << ", "
                      << "Username: " << argv[1] << ", "
                      << "Email: " << argv[2] << ", "
                      << "Code: " << argv[3] << std::endl;
            return 0;
        },
        nullptr,
        0
    );

    if (result != SQLITE_OK) {
        std::cerr << "Error retrieving users: " << sqlite3_errmsg(db) << std::endl;
    }

    sqlite3_close(db);
}

void showPasswordsTable(){
    sqlite3* db;
    int result = sqlite3_open("passwordManager.db", &db);

    if (result != SQLITE_OK) {
        std::cerr << "Error opening the database: " << sqlite3_errmsg(db) << std::endl;
        return;
    }

    std::string selectQuery = "SELECT * FROM passwords;";

    result = sqlite3_exec(
        db,
        selectQuery.c_str(),
        [](void* data, int argc, char** argv, char** colName) -> int {
            // This callback function will be called for each row returned by the query
            // Here, we'll print the user details for each row
            std::cout << "Password ID: " << argv[0] << ", "
                      << "User ID: " << argv[1] << ", "
                      << "Service: " << argv[2] << ", "
                      << "Username: " << argv[3] << ", "
                      << "Encrypted Password: " << argv[4] << std::endl;
            return 0;
        },
        nullptr,
        0
    );

    if (result != SQLITE_OK) {
        std::cerr << "Error retrieving passwords: " << sqlite3_errmsg(db) << std::endl;
    }

    sqlite3_close(db);
}

void dropPasswordsTable(){
    sqlite3 *db;
    int res = sqlite3_open("passwordManager.db", &db);
    if(res != SQLITE_OK){
        cout << "Error opening database" << endl;
        return;
    }
    const char* dropTableQuery = "DROP TABLE IF EXISTS passwords;";
    res = sqlite3_exec(db, dropTableQuery, NULL, NULL, NULL);
    if(res != SQLITE_OK){
        cout << "Error dropping table: " << sqlite3_errmsg(db) << endl;
        sqlite3_close(db);
        return;
    }
    sqlite3_close(db);
    return;
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


int main(){ // just need a query to print the user database
    showUsersTable();
    cout << endl;
    showPasswordsTable();

    return 0;
}