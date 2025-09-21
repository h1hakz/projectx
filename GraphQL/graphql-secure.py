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
    user = graphene.Field(UserType, name=graphene.String(required=True))

    def resolve_user(self, info, name):
        # Secure: hide secret field from unauthorized users
        user_role = info.context.get("role", "guest")  # In real apps, get from auth
        secret = SECRETS.get(name) if user_role == "admin" else None
        if name in SECRETS:
            return UserType(name=name, secret=secret)
        return None

schema = graphene.Schema(query=Query)

app = Flask(__name__)

@app.route("/graphql", methods=["POST"])
def graphql_endpoint():
    # For demonstration, we fake role based on header
    role = request.headers.get("X-Role", "guest")
    data = request.get_json(force=True)
    result = schema.execute(
        data.get("query"),
        variable_values=data.get("variables"),
        context={"role": role}
    )
    response = {"data": result.data}
    if result.errors:
        response["errors"] = [str(e) for e in result.errors]
    return jsonify(response)

@app.route("/health")
def health():
    return jsonify({"status": "secure GraphQL injection API running"})

if __name__ == "__main__":
    print("Secure GraphQL injection API running at http://127.0.0.1:5003/graphql")
    app.run(port=5003)
