from flask import Flask

from config import Config
from database.db import close_db, init_db
from routes.api import api_bp
from routes.dashboard import dashboard_bp


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    init_db(app)
    app.teardown_appcontext(close_db)

    app.register_blueprint(dashboard_bp)
    app.register_blueprint(api_bp, url_prefix="/api")


    return app


app = create_app()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
