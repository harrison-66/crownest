#include <iostream>
#include <string>
#include <fstream>
#include <streambuf>
#include <crow.h>
#include "User.hpp"

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
    // Set up the Crow server
    SimpleApp app;

    // Endpoint for the main page
    CROW_ROUTE(app, "/")([]() {
        return readHTMLFile("src/index.html");
    });

    // Endpoint to handle form submission and user actions
    CROW_ROUTE(app, "/action")
        .methods("POST"_method)([](const request& req) {
        // Get the form parameters from the request
        const auto username = req.url_params.get("username");
        const auto password = req.url_params.get("password");

        // You can now use the 'username' and 'password' values to perform user actions
        // For example, you can create a new user or sign in the existing user here.

        // Sample response for now, you can modify this according to your project's logic
        // For simplicity, we are just returning a success message.
        return "Action successful!";
    });

    // Start the server on port 8080
    app.port(8080).multithreaded().run();

    return 0;
}
