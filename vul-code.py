import os
import pickle
import hashlib

# --- Hardcoded API key ---
API_KEY = "12345-very-secret-key"  # ❌ Hardcoded secret

# --- Weak hashing example ---
def hash_password(password):
    # ❌ MD5 is insecure
    return hashlib.md5(password.encode()).hexdigest()

# --- Insecure file handling (Path Traversal) ---
def read_user_file(filename):
    # ❌ No sanitization, can read arbitrary files
    with open(f"/tmp/{filename}", "r") as f:
        return f.read()

# --- Insecure deserialization ---
def load_data(file_path):
    # ❌ Untrusted pickle load
    with open(file_path, "rb") as f:
        data = pickle.load(f)
    return data

# Example usage
if __name__ == "__main__":
    print("Hashed password:", hash_password("mypassword"))

    # Reading user-controlled file (Path Traversal)
    try:
        print(read_user_file("../../etc/passwd"))
    except Exception as e:
        print("Error:", e)

    # Loading pickle (potential code execution)
    try:
        load_data("user_data.pkl")
    except Exception as e:
        print("Error:", e)
