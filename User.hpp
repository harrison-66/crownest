#pragma once

#include <iostream>
#include <string>
#include <iomanip>
#include <string>

#include "sql/sqlite3.h"

using namespace std;

bool verifyPassword(const std::string& password, const std::string& hash_str);
long generateSalt(string primary_pass);
long stringToLong(string toConvert);
bool allowAccess(string username, string master);
int selectCallback(void* data, int argc, char** argv, char** azColName);
class User{ //* this class doesnt insert into the database, it just holds the data for the active user
    public:
        User();
        User(string username, string master);
        int getUserID();
        bool verifyUser();
        bool existingPassword(string service, string username);
        void addPassword(string service, string username, string password);
        string decryptPassword(string encrypted_string);
        string encryptPassword(string password);
        void getServicePasswords(string service);
        void printAllPasswords();
        bool deletePassword(string service, string username);


    private:
        string username;
        string email;
        string master;
        int userID;
};