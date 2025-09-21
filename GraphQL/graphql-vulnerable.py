from flask import Flask, request, jsonify
import graphene

# Simulated sensitive data
SECRETS = {
    "alice": "alice_secret",
    "bob": "bob_secret"
}

class UserType(graphene.ObjectType):
    name = graphene.String()
    secret = graphene.String()  # Sensitive field

class Query(graphene.ObjectType):
    # Vulnerable: exposes secret field without authorization
    user = graphene.Field(UserType, name=graphene.String(required=True))

    def resolve_user(self, info, name):
        # No authorization check
        if name in SECRETS:
            return UserType(name=name, secret=SECRETS[name])
        return None

schema = graphene.Schema(query=Query)

app = Flask(__name__)

@app.route("/graphql", methods=["POST"])
def graphql_endpoint():
    data = request.get_json(force=True)
    result = schema.execute(data.get("query"), variable_values=data.get("variables"))
    response = {"data": result.data}
    if result.errors:
        response["errors"] = [str(e) for e in result.errors]
    return jsonify(response)

@app.route("/health")
def health():
    return jsonify({"status": "vulnerable GraphQL injection API running"})

if __name__ == "__main__":
    print("Vulnerable GraphQL injection API running at http://127.0.0.1:5002/graphql")
    app.run(port=5002)
