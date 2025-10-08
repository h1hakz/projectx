# hardcoded_secret.py (VULNERABLE)
# Demonstrates hardcoded API keys and passwords in source

API_KEY = "AKIAFAKEEXAMPLEKEY12345"   # <-- hardcoded secret (bad)
DB_PASSWORD = "SuperSecretPassword"   # <-- hardcoded credential (bad)

def connect_to_service():
    # Pretend to use the API key / password
    print("Using API_KEY:", API_KEY)
    print("Using DB_PASSWORD:", DB_PASSWORD)
    # Real code would call an API or DB here; we intentionally do not.

if __name__ == "__main__":
    connect_to_service()
