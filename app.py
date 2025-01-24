import re
import hashlib


# Function to load breached passwords from a file
def load_breached_passwords(file_path):
    try:
        with open(file_path, "r") as file:
            return set(line.strip() for line in file)
    except FileNotFoundError:
        print(f"Error: Breached passwords file '{file_path}' not found.")
        return set()


# Function to hash a password using SHA-1
def hash_password(password):
    return hashlib.sha1(password.encode("utf-8")).hexdigest()


# Function to check password strength
def check_password_strength(password, breached_passwords):
    # Define strength levels
    strength = 0
    feedback = []

    # Check if password is in breached database
    hashed_password = hash_password(password)
    if hashed_password in breached_passwords:
        feedback.append("This password has been found in a database of breached passwords. Avoid using it!")
        return {
            "strength_level": "Breached",
            "feedback": feedback
        }

    # Check length
    if len(password) < 8:
        feedback.append("Password is too short. Use at least 8 characters.")
    else:
        strength += 1

    # Check for uppercase letters
    if not re.search(r"[A-Z]", password):
        feedback.append("Add at least one uppercase letter.")
    else:
        strength += 1

    # Check for lowercase letters
    if not re.search(r"[a-z]", password):
        feedback.append("Add at least one lowercase letter.")
    else:
        strength += 1

    # Check for digits
    if not re.search(r"\d", password):
        feedback.append("Add at least one number.")
    else:
        strength += 1

    # Check for special characters
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        feedback.append("Add at least one special character (e.g., @, #, $, etc.).")
    else:
        strength += 1

    # Check for common patterns
    common_patterns = ["12345", "password", "qwerty", "abc123"]
    if any(pattern in password.lower() for pattern in common_patterns):
        feedback.append("Avoid using common patterns like '12345' or 'password'.")
    else:
        strength += 1

    # Assess overall strength
    if strength < 3:
        strength_level = "Weak"
    elif strength < 5:
        strength_level = "Moderate"
    else:
        strength_level = "Strong"

    # Provide results
    return {
        "strength_level": strength_level,
        "feedback": feedback
    }


# Main function
if __name__ == "__main__":
    print("Welcome to the Enhanced Password Strength Checker!")
    # Load breached passwords from file
    breached_passwords_file = "breached_passwords.txt"
    breached_passwords = load_breached_passwords(breached_passwords_file)

    if not breached_passwords:
        print("Warning: No breached passwords loaded. Skipping breach check.")

    # Input password
    password = input("Enter a password to check: ")
    result = check_password_strength(password, breached_passwords)

    print(f"\nPassword Strength: {result['strength_level']}")
    if result['feedback']:
        print("Suggestions to improve your password:")
        for suggestion in result['feedback']:
            print(f"- {suggestion}")
    else:
        print("Your password is strong! Great job!")
