import re

def assess_password_strength(password):
    length_score = len(password) // 8  # Score based on password length
    uppercase_score = 1 if re.search("[A-Z]", password) else 0  # Score for uppercase letters
    lowercase_score = 1 if re.search("[a-z]", password) else 0  # Score for lowercase letters
    digit_score = 1 if re.search("[0-9]", password) else 0  # Score for digits
    special_char_score = 1 if re.search("[^A-Za-z0-9]", password) else 0  # Score for special characters

    total_score = length_score + uppercase_score + lowercase_score + digit_score + special_char_score

    # Feedback based on total score
    if total_score < 3:
        return "Weak"
    elif total_score < 5:
        return "Moderate"
    else:
        return "Strong"

def main():
    password = input("Enter your password: ")
    strength = assess_password_strength(password)
    print("Password strength:", strength)

if __name__ == "__main__":
    main()
