<?php
// Database connection
$servername = "localhost";
$username = "root";
$password = "";
$dbname = "user_auth";

$conn = new mysqli($servername, $username, $password, $dbname);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Get form inputs
$username_or_email = $_POST['username_or_email'];
$password = $_POST['password'];

// Validate inputs
if (empty($username_or_email) || empty($password)) {
    die("Both fields are required.");
}

// Check if username or email exists
$sql = "SELECT * FROM users WHERE username = ? OR email = ?";
$stmt = $conn->prepare($sql);
$stmt->bind_param("ss", $username_or_email, $username_or_email);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows == 0) {
    die("Invalid credentials.");
}

$user = $result->fetch_assoc();

// Verify password
if (password_verify($password, $user['password'])) {
    // Start session and redirect to dashboard
    session_start();
    $_SESSION['user_id'] = $user['id'];
    $_SESSION['username'] = $user['username'];
    header("Location: dashboard.php");
} else {
    die("Invalid credentials.");
}

$stmt->close();
$conn->close();
?>
