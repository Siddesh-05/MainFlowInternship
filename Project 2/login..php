<?php
session_start();
require_once 'db.php';

if (isset($_POST['login'])) {
    $username_or_email = $_POST['username_or_email'];
    $password = $_POST['password'];

    // Validate inputs
    if (empty($username_or_email) || empty($password)) {
        echo "All fields are required.";
        exit();
    }

    // Retrieve user data
    $stmt = $conn->prepare("SELECT * FROM users WHERE email = ? OR username = ?");
    $stmt->bind_param("ss", $username_or_email, $username_or_email);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows == 0) {
        echo "User does not exist.";
        exit();
    }

    $user = $result->fetch_assoc();
    if (password_verify($password, $user['password'])) {
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];
        header('Location: dashboard.php');
    } else {
        echo "Incorrect username/email or password.";
    }
}
?>
