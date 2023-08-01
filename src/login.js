// Function to handle the login form submission
function handleLogin(event) {
    event.preventDefault();

    // Get the form data
    const formData = new FormData(event.target);
    const username = formData.get("username");
    const password = formData.get("password");

    // Send the login data to the server using a POST request
    fetch("/login", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify({ username: username, password: password }),
    })
    .then((response) => response.json())
    .then((data) => {
        if (data.success) {
            // Login successful, redirect to home page or do whatever you need to do.
            window.location.href = "home";
        } else {
            // Login failed, show an error message or handle it as per your requirement.
            alert("Invalid username or password.");
        }
    })
    .catch((error) => {
        console.error("Error logging in:", error);
    });
}
function registerUser() {
    const username = document.getElementById("usernameReg").value;
    const password = document.getElementById("passwordReg").value;
    const email = document.getElementById("emailReg").value;

    // Create the registration data object
    const registrationData = {
        username: username,
        email: email,
        password: password,
    };
    // Send a POST request to the server to register the user
    fetch("/register", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify(registrationData),
    })
    .then((response) => response.json())
    .then((data) => {
    if (data.success) {
        // Registration successful, redirect to login page
        window.location.href = "index.html";
    } else {
        // Registration failed, handle the error
        alert("Registration Error: " + data.error);
    }
    })
    .catch((error) => {
        console.error("Error registering user:", error);
    });
}

  // Add event listener to the registration form
    document.getElementById("registerForm").addEventListener("submit", registerUser);
// Add event listener to the login form
document.getElementById("loginForm").addEventListener("submit", handleLogin);

