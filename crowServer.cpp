#include <iostream>
#include <string>
#include <fstream>
#include <streambuf>
#include <crow.h>
#include <crow/middlewares/session.h>
#include <crow/middlewares/cookie_parser.h>
#include "sql/sqlite3.h"
#include "crowFunctions.hpp"

#include "User.hpp"
#include "nlohmann/json.hpp"

using json = nlohmann::json;

// g++ command: g++ -std=c++11 -I./Crow/include -I/opt/homebrew/Cellar/asio/1.28.1/include crowServer.cpp -lsqlite3 -lsodium -lpthread -o my_crow_app

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

crow::response serve_image(const std::string& path)
{
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open())
    {
        return crow::response(404);
    }

    std::vector<char> buffer((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();
    crow::response resp;
    resp.code = 200;
    resp.set_header("Content-Type", "image/png");
    resp.body = std::string(buffer.begin(), buffer.end());
    return resp;
}

crow::response serve_file(const std::string& path, const std::string& mime_type)
{
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open())
    {
        return crow::response(404);
    }

    std::vector<char> buffer((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();
    crow::response resp;
    resp.code = 200;
    resp.set_header("Content-Type", mime_type);
    resp.body = std::string(buffer.begin(), buffer.end());
    return resp;
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
        if (username_.empty()) {
            return crow::response(401, "Unauthorized");
        }
        std::string htmlContent = readHTMLFile("src/home.html");
        // Replace a placeholder in the HTML content with the username
        size_t placeholderPos = htmlContent.find("{{USERNAME}}");
        if (placeholderPos != std::string::npos) {
            htmlContent.replace(placeholderPos, strlen("{{USERNAME}}"), username_);
        }
        string passwordTable = printAllPasswords(username_);
        placeholderPos = htmlContent.find("<div class=\"hidden\">{{PASSWORDS}}</div>");
        if (placeholderPos != std::string::npos) {
            htmlContent.replace(placeholderPos, strlen("<div class=\"hidden\">{{PASSWORDS}}</div>"), passwordTable);
        }

        return crow::response(htmlContent);

        //return readHTMLFile("src/home.html");
    });

    CROW_ROUTE(app, "/insert_password").methods(HTTPMethod::Post)([&app](const crow::request& req){
        auto& session = app.get_context<Session>(req);
        // Retrieve user data from session if available
        string mainUsername = session.get("user", "Not Found");
        if (mainUsername.empty()) {
            return crow::response(401, "Unauthorized");
        }
        // Parse the form data from req.body
        std::map<std::string, std::string> form_data;
        std::string key, value;
        std::istringstream iss(req.body);
        while (std::getline(iss, key, '=') && std::getline(iss, value, '&')) {
            form_data[key] = urlDecode(value);
        }

        // Retrieve the fields from the form data
        string service = form_data["service"];
        string username_ = form_data["username"];
        string password = form_data["password"];

        // Use the fields to call your function
        if(!insertPassword(mainUsername, service, username_, password)){
            return crow::response(500, "Error inserting password");
        }
        std::string htmlContent = readHTMLFile("src/home.html");

        // Replace a placeholder in the HTML content with the username
        size_t placeholderPos = htmlContent.find("{{USERNAME}}");
        if (placeholderPos != std::string::npos) {
            htmlContent.replace(placeholderPos, strlen("{{USERNAME}}"), mainUsername);
        }
        std::string alertHTML ="<div class='p-4 text-green-900 bg-green-100 border border-green-200 rounded-md'>"
        "  <div class='flex justify-between flex-wrap'>"
        "    <div class='w-0 flex-1 flex'>"
        "      <div class='mr-3 pt-1'>"
        "        <!-- svg icon -->"
        "      </div>"
        "      <div>"
        "        <h4 class='text-md leading-6 font-medium'>"
        "          Password Saved Succesfully!"
        "        </h4>"
        "        <p class='text-sm'>"
        "          Your Password has been encrypted and stored in the database."
        "        </p>"
        "        <div class='flex mt-3'>"
        "          <button type='button' onclick='location.href=\"/home\"' class='w-full inline-flex justify-center rounded-md border border-transparent shadow-sm px-4 py-2 bg-green-700 text-base font-medium text-white hover:bg-green-800 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500 sm:w-auto sm:text-sm'>"
        "            Return to Nest"
        "          </button>"
        "        </div>"
        "      </div>"
        "    </div>"
        "    <!-- Close button -->"
        "  </div>"
        "</div>";
        size_t alertPos = htmlContent.find("<div class=\"hidden\">{{ALERT}}</div>");
        if (alertPos != std::string::npos) {
            htmlContent.replace(alertPos, strlen("<div class=\"hidden\">{{ALERT}}</div>"), alertHTML);
        }

        return crow::response(htmlContent);
    });

    CROW_ROUTE(app, "/delete_password").methods("POST"_method)([&app](const crow::request& req) {
        // Get data from request
        auto& session = app.get_context<Session>(req);
        // Retrieve user data from session if available
        string mainUsername = session.get("user", "Not Found");
        if (mainUsername.empty()) {
            return crow::response(401, "Unauthorized");
        }


        auto json = crow::json::load(req.body);
        if (!json)
            return crow::response(400, "Invalid request data");

        std::string service = json["service"].s();
        std::string username = json["username"].s();

        // Assuming you have a deletePassword function
        if(!deletePassword(service, username, mainUsername)) {
            return crow::response(500, "Error deleting password");
        }

        std::string htmlContent = readHTMLFile("src/home.html");
        
        // Replace a placeholder in the HTML content with the username
        size_t placeholderPos = htmlContent.find("{{USERNAME}}");
        if (placeholderPos != std::string::npos) {
            htmlContent.replace(placeholderPos, strlen("{{USERNAME}}"), mainUsername);
        }

        std::string alertHTML ="<div class='p-4 text-red-900 bg-red-100 border border-red-200 rounded-md'>"
        "  <div class='flex justify-between flex-wrap'>"
        "    <div class='w-0 flex-1 flex'>"
        "      <div class='mr-3 pt-1'>"
        "        <!-- svg icon -->"
        "      </div>"
        "      <div>"
        "        <h4 class='text-md leading-6 font-medium'>"
        "          Password Deleted Succesfully!"
        "        </h4>"
        "        <p class='text-sm'>"
        "          Password has been deleted from the database permanently."
        "        </p>"
        "        <div class='flex mt-3'>"
        "          <button type='button' onclick='location.href=\"/home\"' class='w-full inline-flex justify-center rounded-md border border-transparent shadow-sm px-4 py-2 bg-red-700 text-base font-medium text-white hover:bg-red-800 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500 sm:w-auto sm:text-sm'>"
        "            Return to Nest"
        "          </button>"
        "        </div>"
        "      </div>"
        "    </div>"
        "    <!-- Close button -->"
        "  </div>"
        "</div>";

        size_t alertPos = htmlContent.find("<div class=\"hidden\">{{ALERT}}</div>");
        if (alertPos != std::string::npos) {
            htmlContent.replace(alertPos, strlen("<div class=\"hidden\">{{ALERT}}</div>"), alertHTML);
        }

        return crow::response(htmlContent);
    });


    

    CROW_ROUTE(app, "/login-style.css")([]() {
        return readHTMLFile("src/login-style.css");
    });

    CROW_ROUTE(app, "/about")([]() {
        return readHTMLFile("src/about.html");
    });

    CROW_ROUTE(app, "/favicon.ico")
    ([] {
        return serve_file("src/favicon.ico", "image/x-icon");
    });

    CROW_ROUTE(app, "/favicon-black.ico")
    ([] {
        return serve_file("src/favicon-black.ico", "image/x-icon");
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
        std::string hash = hashPassword(password);

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
        std::string htmlContent = readHTMLFile("src/index.html");
        return crow::response(htmlContent);
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
            //session.set("pass", password);
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

    CROW_ROUTE(app, "/crowArt/black/-_v4.png")
    ([] {
        return serve_image("crowArt/black/-_v4.png");
    });
    
    CROW_ROUTE(app, "/crowArt/white/-_V3.png")
    ([] {
        return serve_image("crowArt/white/-_V3.png");
    });
    // Serving /crowArt/black/-_V1.png
    CROW_ROUTE(app, "/crowArt/black/-_V1.png")
    ([] {
        return serve_image("crowArt/black/-_V1.png");
    });

    CROW_ROUTE(app, "/crowArt/red/red-_v2.png")
    ([] {
        return serve_image("crowArt/red/red-_v2.png");
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

    CROW_ROUTE(app, "/logout").methods(HTTPMethod::Get)([&app](const crow::request& req) {
        auto& session = app.get_context<Session>(req);
        session.remove("user");
        return readHTMLFile("src/index.html");
    });



    // Start the server on port 8080
    app.port(8080).multithreaded().run();

    return 0;
}
