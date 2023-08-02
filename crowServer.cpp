#include <iostream>
#include <string>
#include <fstream>
#include <streambuf>
#include <crow.h>
#include <crow/middlewares/session.h>
#include <crow/middlewares/cookie_parser.h>
#include "User.hpp"
#include "sql/sqlite3.h"
#include "crowFunctions.hpp"

#include <crow.h>
#include "nlohmann/json.hpp"

using json = nlohmann::json;

// g++ command: g++ -std=c++11 -I./Crow/include -I/opt/homebrew/Cellar/asio/1.28.1/include crowServer.cpp User.cpp -lsqlite3 -lpthread -o my_crow_app

using namespace std;
using namespace crow;

// Function to read the HTML file for the front-end
std::string readHTMLFile(const std::string& filename) {
    std::ifstream file(filename);
    if (!file) {
        return "Error: File not found.";
    }
    return std::string(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
}

int main() {
    createUserTable();
    createPasswordTable();
    User current = User();
    // Set up the Crow server
    //SimpleApp app;

    using Session = crow::SessionMiddleware<crow::InMemoryStore>;

    // Writing your own store is easy
    // Check out the existing ones for guidelines

    // Make sure the CookieParser is registered before the Session
    crow::App<crow::CookieParser, Session> app{Session{
      // customize cookies
        crow::CookieParser::Cookie("session").max_age(/*one day*/ 24 * 60 * 60).path("/"),10,crow::InMemoryStore{}}};

    // Endpoint for the main page
    CROW_ROUTE(app, "/")([]() {
        return readHTMLFile("src/index.html");
    });

    CROW_ROUTE(app, "/home").methods(HTTPMethod::Get)([&app](const crow::request& req){
        
        auto& session = app.get_context<Session>(req);
        // Retrieve user data from session if available
        string username_ = session.get("user", "Not Found");
        cout << "in home" << endl;
        //string username = user.getUsername();
        if (username_.empty()) {
            return crow::response(401, "Unauthorized");
        }
        std::string htmlContent = readHTMLFile("src/home.html");
        // Replace a placeholder in the HTML content with the username
        size_t placeholderPos = htmlContent.find("{{USERNAME}}");
        if (placeholderPos != std::string::npos) {
            htmlContent.replace(placeholderPos, strlen("{{USERNAME}}"), username_);
        }

        return crow::response(htmlContent);

        //return readHTMLFile("src/home.html");
    });

    CROW_ROUTE(app, "/login-style.css")([]() {
        return readHTMLFile("src/login-style.css");
    });


// Endpoint for user registration (register route)
    CROW_ROUTE(app, "/register").methods(HTTPMethod::Post)([](const crow::request& req) {
        // Parse the JSON data from the request body
        auto json_data = crow::json::load(req.body);
        if (!json_data) {
            crow::json::wvalue response_data;
            response_data["success"] = false;
            response_data["error"] = "Invalid JSON data";
            return crow::response(400, response_data);
        }

        // Extract the registration data from the JSON payload
        std::string username = json_data["username"].s();
        std::string email = json_data["email"].s();
        std::string password = json_data["password"].s();

        // Validate the registration data
        if (username.length() > 20) {
            crow::json::wvalue response_data;
            response_data["success"] = false;
            response_data["error"] = "Username too long";
            return crow::response(400, response_data);
        }
        if (usernameExists(username)) {
            crow::json::wvalue response_data;
            response_data["success"] = false;
            response_data["error"] = "Username already exists";
            return crow::response(400, response_data);
        }
        if (emailExists(email)) {
            crow::json::wvalue response_data;
            response_data["success"] = false;
            response_data["error"] = "Email already exists";
            return crow::response(400, response_data);
        }
        if (!validEmail(email)) {
            crow::json::wvalue response_data;
            response_data["success"] = false;
            response_data["error"] = "Invalid email";
            return crow::response(400, response_data);
        }

        // Hash the password before storing it in the database
        std::string hash = crunchPass(password);

        // Insert the user data into the database
        if (!newUser(username, email, hash)) {
            crow::json::wvalue response_data;
            response_data["success"] = false;
            response_data["error"] = "Error creating user";
            return crow::response(500, response_data);
        }

        // Registration successful
        crow::json::wvalue response_data;
        response_data["success"] = true;
        return crow::response(200, response_data);
    });

    CROW_ROUTE(app, "/login").methods(HTTPMethod::Post)([&app](const crow::request& req) {
        // Parse the JSON data from the request body
        auto json_data = crow::json::load(req.body);
        if (!json_data) {
            return crow::response(400, "Invalid JSON data");
        }

        // Extract the username and password from the JSON data
        std::string username = json_data["username"].s();
        std::string password = json_data["password"].s();

        // Verify the login credentials in the database
        if (verifyLogin(username, password)) {
            // Login successful
            auto& session = app.get_context<Session>(req);
            session.set("user", username);
            session.set("pass", password);
            crow::json::wvalue response_data;
            response_data["success"] = true;
            return crow::response(200, response_data);
        } else {
            // Login failed
            crow::json::wvalue response_data;
            response_data["success"] = false;
            return crow::response(401, response_data);
        }
    });

    CROW_ROUTE(app, "/login.js")
    ([]() {
        // Read the contents of login.js file
        ifstream file("src/login.js");
        if (!file.is_open()) {
            return crow::response(404, "Not found");
        }

        stringstream buffer;
        buffer << file.rdbuf();
        file.close();

        // Return the contents of login.js with appropriate MIME type
        response response(buffer.str());
        response.add_header("Content-Type", "application/javascript");
        return response;
    });
    // Start the server on port 8080
    app.port(8080).multithreaded().run();

    return 0;
}
