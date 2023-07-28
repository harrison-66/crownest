#pragma once

#include <iostream>
#include <string>
#include <iomanip>
#include <fstream>

#include "sql/sqlite3.h"

class User{ //* this class doesnt insert into the database, it just holds the data for the active user
    public:
        User(string& username, string& email, long& hash);
        
        
        }
    private:
        string username;
        string email;
        long hash;
};