#include "User.hpp"
#include <iostream>
#include <vector>
#include <string>
#include <sodium.h>
#include "mini/ini.h"

using namespace std;

const long SALT_KEY = 2384589059374561; // arbitrary value for salt key

struct PasswordData { // used to store data from sql query on passwords
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

std::string getMasterKey(){
    mINI::INIFile file("config.ini");
    mINI::INIStructure ini;
    file.read(ini);
    std::string ret = ini.get("Keys").get("master_key");
    return ret;
}

// Verify a password against its hash
bool verifyPassword(const std::string& password, const std::string& hash_str) {


    // Extract the salt from the hash string
    unsigned char salt[crypto_pwhash_SALTBYTES];
    std::string salt_str = hash_str.substr(hash_str.length() - crypto_pwhash_SALTBYTES);
    if (salt_str.length() != crypto_pwhash_SALTBYTES) {
        std::cerr << "Invalid hash format" << std::endl;
        return false;
    }
    std::copy(salt_str.begin(), salt_str.end(), salt);

    // Verify the password
    if (crypto_pwhash_str_verify(hash_str.c_str(), password.c_str(), password.length()) != 0) {
        std::cerr << "crypto_pwhash_str_verify returned: " << crypto_pwhash_str_verify(hash_str.c_str(), password.c_str(), password.length()) << std::endl;
        return false;
    }

    return true;
}

long generateSalt(string primary_pass){ // generate a salt value based on the user's password
    long salt = 1;
    for (int i = 0; i < primary_pass.length(); i++){
        salt *= primary_pass[i];
    }
    salt = SALT_KEY ^ salt;
    return salt;
}

long stringToLong(string toConvert){ // convert a string to a longeeee
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

bool allowAccess(string username, string master){ //!deprecated check if the user's password is correct
    cerr << "Deprecated function called" << endl;
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
    string query = "SELECT hash FROM users WHERE username = :username;";
    sqlite3_stmt *stmt; // prepared statement
    res = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, NULL); // -1 means query is null terminated, stmt is the prepared statement
    if(res != SQLITE_OK){ // if there is an error
        cout << "Error preparing statement: " << sqlite3_errmsg(db) << endl;
        sqlite3_close(db);
        return false;
    }
    // Bind the parameter to the prepared statement using named placeholder
    res = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":username"), username.c_str(), -1, SQLITE_STATIC);
    if (res != SQLITE_OK) {
        std::cout << "Error binding username parameter: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_finalize(stmt);
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

User::User(){ // default constructor, used when user class initiated, so scope is higher
    this->username = "";
    this->email = "";
    this->master = "";
    this->userID = -1;
}

User::User(string username, string master){ // constructor
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
    string query = "SELECT id FROM users WHERE username = :username;";
    sqlite3_stmt *stmt; // prepared statement
    res = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, NULL); // -1 means query is null terminated, stmt is the prepared statement
    if(res != SQLITE_OK){ // if there is an error
        cout << "Error preparing statement: " << sqlite3_errmsg(db) << endl;
        sqlite3_close(db);
        return;
    }
    // Bind the parameter to the prepared statement using named placeholder
    res = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":username"), username.c_str(), -1, SQLITE_STATIC);
    if (res != SQLITE_OK) {
        cout << "Error binding username parameter: " << sqlite3_errmsg(db) << endl;
        sqlite3_finalize(stmt);
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

bool User::verifyUser(){ // verify the user's password (class method)
    return allowAccess(this->username, this->master);
}

bool User::existingPassword(string service, string username){ // check if the password already exists for the user
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

void User::addPassword(string service, string username_, string password){ // add a password to the database
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
    string query = "INSERT INTO passwords (userID, service, username, encrypted_password) VALUES (:userID, :service, :username, :encrypted_password);";
    sqlite3_stmt *stmt; // prepared statement
    res = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, NULL); // -1 means query is null terminated, stmt is the prepared statement
    if(res != SQLITE_OK){ // if there is an error
        cout << "Error preparing statement: " << sqlite3_errmsg(db) << endl;
        sqlite3_close(db);
        return;
    }
        // Bind parameters to the prepared statement using named placeholders
    res = sqlite3_bind_int(stmt, sqlite3_bind_parameter_index(stmt, ":userID"), this->userID);
    if (res != SQLITE_OK) {
        cout << "Error binding userID parameter: " << sqlite3_errmsg(db) << endl;
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return;
    }

    res = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":service"), service.c_str(), -1, SQLITE_STATIC);
    if (res != SQLITE_OK) {
        cout << "Error binding service parameter: " << sqlite3_errmsg(db) << endl;
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return;
    }

    res = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":username"), username_.c_str(), -1, SQLITE_STATIC);
    if (res != SQLITE_OK) {
        cout << "Error binding username parameter: " << sqlite3_errmsg(db) << endl;
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return;
    }

    res = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":encrypted_password"), encrypted_password.c_str(), -1, SQLITE_STATIC);
    if (res != SQLITE_OK) {
        cout << "Error binding encrypted_password parameter: " << sqlite3_errmsg(db) << endl;
        sqlite3_finalize(stmt);
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

std::string User::encryptPassword(std::string password) { // encrypt the password
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

std::string User::decryptPassword(std::string encrypted_string) { // decrypt the password
    if (encrypted_string.length() < crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES) {
        //panic! the encrypted password is not valid
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

int User::getUserID(){ // getter for querying the database
    return this->userID;
}

void User::getServicePasswords(string service){
    sqlite3 *db;
    int res = sqlite3_open("passwordManager.db", &db);
    if(res != SQLITE_OK){
        cout << "Error opening database" << endl;
        return;
    }
    string query = "SELECT username, encrypted_password FROM passwords WHERE userID = :userID AND service = :service;";
    vector<PasswordData> passwordArray;
    sqlite3_stmt* stmt;
    res = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr);
    if (res != SQLITE_OK) {
        cout << "Error preparing query: " << sqlite3_errmsg(db) << endl;
        sqlite3_close(db);
        return;
    }

    // Bind parameters to the prepared statement
    res = sqlite3_bind_int(stmt, sqlite3_bind_parameter_index(stmt, ":userID"), this->userID);
    if (res != SQLITE_OK) {
        cout << "Error binding parameter: " << sqlite3_errmsg(db) << endl;
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return;
    }
    
    res = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":service"), service.c_str(), -1, SQLITE_STATIC);
    if (res != SQLITE_OK) {
        cout << "Error binding parameter: " << sqlite3_errmsg(db) << endl;
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        PasswordData password;
        password.service = service;
        password.username = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        password.encrypted_password = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));

        passwordArray.push_back(password);
    }
    cout << "Password array size: " << passwordArray.size() << endl;
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    // Close the database connection
    cout << "Passwords stored for " << service << ":" << endl;
    for (const auto& password : passwordArray) {
        cout << "Username: " << password.username << "| Decrypted Password: " << decryptPassword(password.encrypted_password) << endl;
    }
    return;
}


void User::printAllPasswords(){
    cout << "Printing all passwords for user: " << this->username << endl;
    sqlite3 *db;
    int res = sqlite3_open("passwordManager.db", &db);
    if(res != SQLITE_OK){
        cout << "Error opening database" << endl;
        return;
    }
    string query = "SELECT service, username, encrypted_password FROM passwords WHERE userID = :userID;";
    vector<PasswordData> passwordArray;
    sqlite3_stmt* stmt;
    res = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr);
    if (res != SQLITE_OK) {
        cout << "Error preparing query: " << sqlite3_errmsg(db) << endl;
        sqlite3_close(db);
        return;
    }
    // Bind parameters to the prepared statement using named placeholders
    res = sqlite3_bind_int(stmt, sqlite3_bind_parameter_index(stmt, ":userID"), this->userID);
    if (res != SQLITE_OK) {
        cout << "Error binding parameter: " << sqlite3_errmsg(db) << endl;
        sqlite3_finalize(stmt);
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
        cout << "Service: " << password.service << "| Username: " << password.username << "| Decrypted Password: " << decryptPassword(password.encrypted_password) << endl;
    }
    return;
}

bool User::deletePassword(string service, string username){
    sqlite3 *db;
    int res = sqlite3_open("passwordManager.db", &db);
    if(res != SQLITE_OK){
        cout << "Error opening database" << endl;
        return false;
    }
    string query = "DELETE FROM passwords WHERE userID = :userID AND service = :service AND username = :username;";
    sqlite3_stmt *stmt; // prepared statement
    res = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, NULL); // -1 means query is null terminated, stmt is the prepared statement
    if(res != SQLITE_OK){ // if there is an error
        cout << "Error preparing statement: " << sqlite3_errmsg(db) << endl;
        sqlite3_close(db);
        return false;
    }
        // Bind parameters to the prepared statement using named placeholders
    res = sqlite3_bind_int(stmt, sqlite3_bind_parameter_index(stmt, ":userID"), this->userID);
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
    res = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":username"), username.c_str(), -1, SQLITE_STATIC);
    if (res != SQLITE_OK) {
        cout << "Error binding username parameter: " << sqlite3_errmsg(db) << endl;
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return false;
    }
    res = sqlite3_step(stmt); // execute the prepared statement
    if(res != SQLITE_DONE){ // if there is a row, then the username exists
        cout << "Error deleting from database: " << sqlite3_errmsg(db) << endl;
        sqlite3_finalize(stmt); // finalize the prepared statement
        sqlite3_close(db); // close the database
        return false; // return true
    }
    sqlite3_finalize(stmt); // finalize the prepared statement
    sqlite3_close(db);// close the database
    cout << "Password for " << service << " deleted successfully" << endl;
    return true; // return false
}