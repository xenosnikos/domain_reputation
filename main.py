from flask import Flask
from flask_restful import Api

from controllers.domain_reputation import DomainReputation

app = Flask(__name__)
api = Api(app)

api.add_resource(DomainReputation, "/v2/domainReputation")

if __name__ == "__main__":
    app.run()
