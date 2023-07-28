#include <iostream>
#include <string>
#include <iomanip>
#include <fstream>

using namespace std;

const long SALT_KEY = 2384589059374561;

int split(string input_string, char seperator, string arr[], int arr_size){
    int output = 1; // declare output to be 1, as there will always be at least 1 split (0 edge-case handled in line 20)
    int j = 0; // index for array (could literally be output -1, I use j because it's easier to read)
    int length = input_string.length(); // get length for edge-case handling, as well as for loop length
    if(length == 0){return 0;} // if string has no chars, return 0 (only case when default output is not wanted)
    string strOut = ""; // declare string to be outputted into array
    for (int i = 0; i < length; i++){ // for each char in the string 
        if (input_string[i] == seperator){ // if the char is the seperator
            output++; // incremement split count to output
            if (output > arr_size){ // if output is greater than arr_size, return -1 (per markdown)
                arr[j] = strOut; // add previous string to array at index of j (for coderunner)
                return -1;
            } 
            arr[j] = strOut; // add previous string to array at index of j
            strOut = ""; // reset string to be outputted
            j++; // increase the index of the array for next entry
        }else{ // if char is not the seperator
            strOut += input_string[i]; // add char to string to be outputted
        }
    }
    arr[j] = strOut; // ONCE FOR LOOP FINISHED, add last string to array at index of j (as it will not be added in the loop)
    return output; // return output, array is passed by reference so it will be changed in main
}

//! meant for one user, although a user class could add some multiuser functionality
bool allowAccess(string primary_pass){ //* algo to check primary password and allow unhashing access for other pass
    long hashed = 0;
    int dig_count = 0;
    string checker;
    ifstream hash_file;
    string hash_check;
    hash_file.open("onewayhashed.txt");
    if (hash_file.fail()){
        cout << "Primary password is not currently stored in this directory, try editing filepaths!\n";
        return false;
    }else{
        getline(hash_file, checker);
        hash_file.close();
        for (int i = 0; i < primary_pass.length(); i++){// Hash the user's input password and store it in the 'hashed' variable
            if(i != primary_pass.length() - 1){
                hashed += primary_pass[i] * primary_pass[i+1];
                hashed += primary_pass[i] * primary_pass[i] * primary_pass[i];
            }else{
                hashed += primary_pass[i] * primary_pass[0]; // arbitrary value for last dig mult
            }
        }
    } //* ATP we have hashed the users input into a long, and have the hashed check value as a string; now we need to compare them
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

bool masterSet(){
    ifstream hash_file;
    string checker;
    hash_file.open("onewayhashed.txt");
    if (hash_file.fail()){
        cout << "Primary password is not currently stored in this directory, try editing filepaths!\n";
        return true; // so that the user cannot set a new password
    }else{
        getline(hash_file, checker);
        hash_file.close();
        if(checker == ""){
            return false;
        }else{
            return true;
        }
    }
}

void newMasterPass(string primary_pass){
    ifstream hash_file;
    string reversed;
    long hashed = 0;
    int dig_count = 0;
    if(masterSet()){
        cout << "Primary password already exists! Future releases may have password resetting using SMS...\n";
        return;
    }
    for (int i = 0; i < primary_pass.length(); i++){// Hash the user's input password and store it in the 'hashed' variable
        if(i != primary_pass.length() - 1){
            hashed += primary_pass[i] * primary_pass[i+1];
            hashed += primary_pass[i] * primary_pass[i] * primary_pass[i];
        }else{
            hashed += primary_pass[i] * primary_pass[0]; // arbitrary value for last dig mult
        }
    }
    while (hashed > 0){ // Convert the 'hashed' value into a string 'hash_check' for comparison
        int temp = 0;
        temp = hashed % 10;
        hashed = hashed / 10;
        char current = char(temp + 48);
        reversed += current;
        dig_count++;
    }
    // reverse the string and write it to the file
    string to_write;
    for (int i = (dig_count-1); i >= 0; i--){
        to_write += reversed[i];
    }
    ofstream hash_file1;
    hash_file1.open("onewayhashed.txt");
    hash_file1 << to_write;
    hash_file1.close();
    cout << "Your primary password has been set!\n";
    return;
}

long generateSalt(string primary_pass){
    long salt = 1;
    for (int i = 0; i < primary_pass.length(); i++){
        salt *= primary_pass[i];
    }
    salt = SALT_KEY ^ salt;
    return salt;
}
bool existingPW(string service){
    ifstream dataFile;
    dataFile.open("data.txt");
        if(dataFile.fail()){
            cout << "Storage file failed to open, ensure filepaths are correct!\n";
            return false;
        }else{
            string test;
            while(!dataFile.eof()){
                string temparr[2];
                getline(dataFile, test);
                split(test, '|', temparr, 2);
                if (temparr[0] == service){
                    return true;
                }
            }
            dataFile.close();
            return false;
        }
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

void accessPassword(string service, string primary_pass){
    if (allowAccess(primary_pass)!= true){
        cout << "Access denied --> Incorrect primary password\n";
        return;
    }else{
        ifstream dataFile;
        string salted;
        dataFile.open("data.txt");
        if(dataFile.fail()){
            cout << "Storage file failed to open, ensure filepaths are correct!\n";
            return;
        }else{
            while(!dataFile.eof()){
                string temparr[2];
                getline(dataFile, salted);
                split(salted, '|', temparr, 2);
                if (temparr[0] == service){
                    long encrypted = stringToLong(temparr[1]);
                    long salt = generateSalt(primary_pass);
                    long to_decode = encrypted ^ salt; //! isnt working because salted is a string, NEEDS TO BE A LONG
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
                    cout << "Your stored password for " << service << " is: " << give_to_user << endl;
                    dataFile.close();
                    break;
                }
                cout << "Password not found within database!\n";
            }
            dataFile.close();
        }
    }
    return;
}

// for each letter (reversed), get ascii, subract 32 to make it 2 digits, then push into one long
void addPassword(string service, string primary_pass, string pass){
    if (allowAccess(primary_pass) == true){
        if(existingPW(service)){
            cout << "You already have a password saved for this service.\n";
            accessPassword(service, primary_pass);
            return;
        }
        long salt = generateSalt(primary_pass);
        long digit_count = 1;
        long num_pass = 0;
        for (int i = (pass.length()-1); i >= 0; i--){
            int temp = pass[i] - 32;
            num_pass += (temp * digit_count);
            digit_count = digit_count * 100;
        }
        long salted = num_pass ^ salt; //! store this value
        ofstream storage;
        storage.open("data.txt", ios_base::app);
        if (storage.fail()){
            cout << "Storage file failed to open, ensure filepaths are correct!\n";
            return;
        }else{ 
            storage << service << "|" << salted << "\n";
            storage.close();
        }
    }else{
        cout << "Access denied --> Incorrect Primary Password!\n";
    }
    return;
}

string straightpw(string garbage, string primary_pass){
    long encrypted = stringToLong(garbage);
    long salt = generateSalt(primary_pass);
    long to_decode = encrypted ^ salt; //! isnt working because salted is a string, NEEDS TO BE A LONG
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

void printList(string primary_pass){
    if (allowAccess(primary_pass)!= true){
        cout << "Access denied --> Incorrect primary password\n";
        return;
    }else{
        ifstream dataFile;
        string printer;
        dataFile.open("data.txt");
        if(dataFile.fail()){
            cout << "Storage file failed to open, ensure filepaths are correct!\n";
            return;
        }else{
            while(!dataFile.eof()){
                string temparr[2];
                getline(dataFile, printer);
                split(printer, '|', temparr, 2);
                if(temparr[0] != ""){
                    cout << "Your password for " << temparr[0] << " is " << straightpw(temparr[1], primary_pass) << endl; 
                }
            }
            dataFile.close();
        }
    }
    return;
}

int main(){
    if(!masterSet()){
        string master;
        cout << "Welcome to your Password Manager\n";
        cout << "Enter your new master password here: ";
        cin >> master;
        newMasterPass(master);
    }
    string master;
    cout << "Welcome to your Password Manager\n";
    cout << "Enter the master password here: ";
    cin >> master;
    if(allowAccess(master)){
        cout << "Access Confirmed" << endl;
        while(1){
            int sw = 0;
            cout << "What would you like to do? (1 - Access Passwords | 2 - Add a Password | 3 - Exit):\n";
            cin >> sw;
            string service = "";
            string pass = "";
            switch(sw){
                case 1:
                    cout << "For what service?: ";
                    cin >> service;
                    accessPassword(service, master);
                    break;
                case 2:
                    cout << "For what service?: ";
                    cin >> service;
                    cout << "What is the password?: ";
                    cin >> pass;
                    addPassword(service, master, pass);
                    break;
                case 3:
                    return 0;
                case 420:
                    cout << "Printing all Passwords:\n" << endl;
                    printList(master);
                    break;
                default:
                    cout << "Not an option! run that shit back and try again." << endl;
                    cin.clear(); // clear bad input flag
                    cin.ignore(numeric_limits<streamsize>::max(), '\n');
                    break;
            }
        }
    }else{
        cout << "Access Denied --> Incorrect Master Password\n";
    }
    return 0;
}


