from flask import Flask
from flask_restful import Api
from dotenv import load_dotenv

from controllers.domain_reputation import DomainReputation

app = Flask(__name__)
api = Api(app)
load_dotenv()

api.add_resource(DomainReputation, "/v2/domain-reputation")

if __name__ == "__main__":
    app.run()
