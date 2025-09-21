# Secure vs Vulnerable GraphQL Injection API Demo

1. **vulnerable_graphql_injection.py** – demonstrates a GraphQL resolver vulnerable to GraphQL injection (exposes sensitive fields without authorization).  
2. **secure_graphql_injection.py** – demonstrates a secure GraphQL resolver that hides sensitive fields for unauthorized users.

---

## Requirements

- Python 3.9+
- Install dependencies:

```bash
pip3 install -r requirements.txt
```

### Running
#### Start the vulnerable API
```bash
python vulnerable_graphql_injection.py
```


It will start at: http://127.0.0.1:5002/graphql

#### Start the secure API
```bash
python secure_graphql_injection.py
```

It will start at: http://127.0.0.1:5003/graphql


### Testing GraphQL Injection

#### Vulnerable API
```bash
curl -s -X POST http://127.0.0.1:5002/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"query($n:String!){user(name:$n){name secret}}","variables":{"n":"alice"}}'
```

Expected: returns "secret": "alice_secret" even for unauthorized users.

#### Secure API (unauthorized user)
```bash
curl -s -X POST http://127.0.0.1:5003/graphql \
  -H "Content-Type: application/json" \
  -H "X-Role: guest" \
  -d '{"query":"query($n:String!){user(name:$n){name secret}}","variables":{"n":"alice"}}'
```

Expected: returns "secret": null (unauthorized users cannot access sensitive fields).

#### Secure API (authorized user)
```bash
curl -s -X POST http://127.0.0.1:5003/graphql \
  -H "Content-Type: application/json" \
  -H "X-Role: admin" \
  -d '{"query":"query($n:String!){user(name:$n){name secret}}","variables":{"n":"alice"}}'
```

Expected: returns the actual secret for "alice".

GraphQL Introspection

You can inspect the schema:
```bash
curl -s -X POST http://127.0.0.1:5002/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name } } }"}' | jq .

```