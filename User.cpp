#include "User.hpp"
#include <iostream>
#include <vector>

using namespace std;

const long SALT_KEY = 2384589059374561;

struct PasswordData {
    std::string service;
    std::string username;
    std::string encrypted_password;
};

// Callback function to process each row of the result
/*int selectCallback(void* data, int argc, char** argv, char** azColName) {
    vector<PasswordData>* passwordArray = static_cast<vector<PasswordData>*>(data);

    PasswordData password;
    password.user_id = atoi(argv[0]);
    password.service = argv[1];
    password.username = argv[2];
    password.encrypted_password = argv[3];
    passwordArray->push_back(password);

    return 0;
}*/


long generateSalt(string primary_pass){
    long salt = 1;
    for (int i = 0; i < primary_pass.length(); i++){
        salt *= primary_pass[i];
    }
    salt = SALT_KEY ^ salt;
    return salt;
}

long stringToLong(string toConvert){
    long return_value = 0;
    long dig_count = 1;
    for(int i = (toConvert.length()-1); i >=0; i--){
        long temp = long(toConvert[i] - 48);
        temp *= dig_count;
        dig_count *= 10;
        return_value += temp;
    }
    return return_value;
}

bool allowAccess(string username, string master){ // first get the hash from the database
    string checker;
    long hashed = 0;
    int dig_count = 0;
    string hash_check = "";
    sqlite3 *db;
    int res = sqlite3_open("passwordManager.db", &db);
    if(res != SQLITE_OK){
        cout << "Error opening database" << endl;
        return false;
    }
    string query = "SELECT hash FROM users WHERE username = '" + username + "';";
    sqlite3_stmt *stmt; // prepared statement
    res = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, NULL); // -1 means query is null terminated, stmt is the prepared statement
    if(res != SQLITE_OK){ // if there is an error
        cout << "Error preparing statement: " << sqlite3_errmsg(db) << endl;
        sqlite3_close(db);
        return false;
    }
    res = sqlite3_step(stmt); // execute the prepared statement
    if(res == SQLITE_ROW){ // if there is a row, then the username exists
        checker = (char*)sqlite3_column_text(stmt, 0); // get the hash
        sqlite3_finalize(stmt); // finalize the prepared statement
        sqlite3_close(db); // close the database
    }
    else{
        sqlite3_finalize(stmt); // finalize the prepared statement
        sqlite3_close(db);// close the database
        return false; // return false
    }
    for (int i = 0; i < master.length(); i++){// Hash the user's input password and store it in the 'hashed' variable
        if(i != master.length() - 1){
            hashed += master[i] * master[i+1];
            hashed += master[i] * master[i] * master[i];
        }else{
            hashed += master[i] * master[0]; // arbitrary value for last dig mult
        }
    }
    while (hashed > 0){ // Convert the 'hashed' value into a string 'hash_check' for comparison
        int temp = 0;
        temp = hashed % 10;
        hashed = hashed / 10;
        char current = char(temp + 48);
        hash_check += current;
        dig_count++;
    }
    for (int i = 0; i < dig_count; i++){
        if(checker[i] != hash_check[dig_count-i - 1]){
            return false;
        }
    }
    return true;
}

User::User(){
    this->username = "";
    this->email = "";
    this->master = "";
    this->userID = -1;
}

User::User(string username, string master){
    this->username = username;
    this->master = master;
    this->email = "";
    // need to query users to find the UserID
    sqlite3 *db;
    int res = sqlite3_open("passwordManager.db", &db);
    if(res != SQLITE_OK){
        cout << "Error opening database" << endl;
        return;
    }
    string query = "SELECT id FROM users WHERE username = '" + username + "';";
    sqlite3_stmt *stmt; // prepared statement
    res = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, NULL); // -1 means query is null terminated, stmt is the prepared statement
    if(res != SQLITE_OK){ // if there is an error
        cout << "Error preparing statement: " << sqlite3_errmsg(db) << endl;
        sqlite3_close(db);
        return;
    }
    res = sqlite3_step(stmt); // execute the prepared statement
    if(res == SQLITE_ROW){ // if there is a row, then the username exists
        this->userID = sqlite3_column_int(stmt, 0); // get the userID
        sqlite3_finalize(stmt); // finalize the prepared statement
        sqlite3_close(db); // close the database
    }
    else{
        sqlite3_finalize(stmt); // finalize the prepared statement
        sqlite3_close(db);// close the database
        return; // return false
    }
}

bool User::verifyUser(){
    return allowAccess(this->username, this->master);
}

bool User::existingPassword(string service, string username){
    sqlite3 *db;
    int res = sqlite3_open("passwordManager.db", &db);
    if(res != SQLITE_OK){
        cout << "Error opening database" << endl;
        return false;
    }
    string query = "SELECT * FROM passwords WHERE service = '" + service + "' AND username = '" + username + "';";
    sqlite3_stmt *stmt; // prepared statement
    res = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, NULL); // -1 means query is null terminated, stmt is the prepared statement
    if(res != SQLITE_OK){ // if there is an error
        cout << "Error preparing statement: " << sqlite3_errmsg(db) << endl;
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

void User::addPassword(string service, string username_, string password){
    string encrypted_password = encryptPassword(password);
    sqlite3 *db;
    int res = sqlite3_open("passwordManager.db", &db);
    if(res != SQLITE_OK){
        cout << "Error opening database" << endl;
        return;
    }
    if(existingPassword(service, username_)){
        cout << "Password already exists for this service and username" << endl;
        return;
    }
    string query = "INSERT INTO passwords (userID, service, username, encrypted_password) VALUES (" + to_string(this->userID) + ", '" + service + "', '" + username_ + "', '" + encrypted_password + "');";
    sqlite3_stmt *stmt; // prepared statement
    res = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, NULL); // -1 means query is null terminated, stmt is the prepared statement
    if(res != SQLITE_OK){ // if there is an error
        cout << "Error preparing statement: " << sqlite3_errmsg(db) << endl;
        sqlite3_close(db);
        return;
    }
    res = sqlite3_step(stmt); // execute the prepared statement
    if(res != SQLITE_DONE){ // if there is a row, then the username exists
        cout << "Error inserting into database: " << sqlite3_errmsg(db) << endl;
        sqlite3_finalize(stmt); // finalize the prepared statement
        sqlite3_close(db); // close the database
        return; // return true
    }
    sqlite3_finalize(stmt); // finalize the prepared statement
    sqlite3_close(db);// close the database
    return; // return false
}

string User::decryptPassword(string encrypted_string){
    long encrypted = stringToLong(encrypted_string);
    long salt = generateSalt(this->master);
    long to_decode = encrypted ^ salt; // XOR the encrypted string with the salt to get the original value
    string pass_out;
    while(to_decode > 0){
        int temp = to_decode % 100;
        to_decode = to_decode / 100;
        pass_out += char(temp + 32);
    }
    string give_to_user;
    for (int i = (pass_out.length()-1); i >= 0; i--){
        give_to_user += pass_out[i];
    }
    return give_to_user;
}

string User::encryptPassword(string password){
    long salt = generateSalt(this->master);
    long digit_count = 1;
    long num_pass = 0;
    for (int i = (password.length()-1); i >= 0; i--){
        int temp = password[i] - 32;
        num_pass += (temp * digit_count);
        digit_count = digit_count * 100;
    }
    long salted = num_pass ^ salt; //! store this value
    return to_string(salted); // return the encrpted password
}

int User::getUserID(){
    return this->userID;
}

void User::getServicePasswords(string service){

}
void User::printAllPasswords(){
    cout << "Printing all passwords for user: " << this->username << endl;
    sqlite3 *db;
    int res = sqlite3_open("passwordManager.db", &db);
    if(res != SQLITE_OK){
        cout << "Error opening database" << endl;
        return;
    }
    string query = "SELECT service, username, encrypted_password FROM passwords WHERE userID = " + to_string(this->userID) + ";";
    vector<PasswordData> passwordArray;
    sqlite3_stmt* stmt;
    res = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr);
    if (res != SQLITE_OK) {
        cout << "Error preparing query: " << sqlite3_errmsg(db) << endl;
        sqlite3_close(db);
        return;
    }
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        PasswordData password;
        password.service = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        password.username = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        password.encrypted_password = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));

        passwordArray.push_back(password);
    }
    cout << "Password array size: " << passwordArray.size() << endl;
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    // Close the database connection
    for (const auto& password : passwordArray) {
        cout << "Service: " << password.service << ", Username: " << password.username << ", Decrypted Password: " << decryptPassword(password.encrypted_password) << endl;
    }
}
