import uuid

from flask import Flask, g, jsonify, request, send_from_directory

from flask_compress import Compress

from flask_cors import CORS

from mongo_database import (
    adp_get_results,
    create_token,
    delete_token,
    get_token,
    get_tokens,
    get_user,
    vespa_get_results,
)

from sample_importer import (
    SampleSpreadsheetImporter,
    SpreadsheetImportError,
)

import yaml

# Load YAML data from secrets file
with open("config.yaml", "r") as stream:
    try:
        yaml_data = yaml.safe_load(stream)
        api_key = yaml_data["mongo"]["API_KEY"]
    except yaml.YAMLError as exc:
        print(exc)


def is_valid_uuid4(uuid_str):
    try:
        uuid_obj = uuid.UUID(uuid_str, version=4)
        return (
            str(uuid_obj) == uuid_str
        )  # Verify that the string representation matches the original input
    except ValueError:
        return False


compress = Compress()


def create_app(in_dev_mode=False):
    app = Flask(__name__, static_folder="./static")
    app.config["in_dev_mode"] = in_dev_mode
    app.config["JSON_SORT_KEYS"] = False
    CORS(app, supports_credentials=True)
    print("SERVER IN DEVELOPMENT MODE: {}".format(in_dev_mode))

    def authorize_token():
        """
        Authenticate a user based on the provided token in the HTTP request.

        This function checks for the presence of a JSON Web Token (JWT) in the
        "Authorization" header or in the cookie named "jwt_token". If a valid JWT
        is found, the user identity is extracted using the 'verify_jwt_token' function,
        and if successful, the user is attached to the global request context
        ('g.user').

        If no valid JWT is found, the function checks for an alternative token format
        in the "Authorization" header, specifically in the format
        "X-API-TOKEN <token_id>". If a valid UUID4 'token_id' is provided,
        the corresponding user is retrieved using the 'get_token' function,
        and if successful, the user is attached to the global request context.

        Parameters:
        None

        Returns:
        None: If the authentication is successful and the user is attached to the
            request context.

        Raises:
        jsonify: If authentication fails, appropriate error messages are returned as
                JSON responses along with a 401 (Unauthorized) status code.
        """

        token = request.headers.get("Authorization")

        if not token:
            return jsonify(error="Authorization token not found."), 401

        if token and token.startswith("X-API-TOKEN"):
            token_id = token.split()[-1]
            if not is_valid_uuid4(token_id):
                return jsonify(error="You did not provide a valid token."), 401

            user = get_token(token_id)
            if not user:
                return jsonify(error="Invalid token."), 401
            g.user = user
        else:
            return jsonify(error="Invalid Authorization header."), 401

    @app.before_request
    def before_request():
        """Call the middleware to authorize before each request"""
        authorize_token()

    @app.errorhandler(401)
    def unauthorized_error(error):
        """Custom error handler for 401 Unauthorized"""
        return jsonify(error="Unauthorized"), 401

    @app.route("/api/static_files/<string:file_name>", methods=["GET"])
    def send_static(file_name):
        """
        Serve a static file from the 'static' directory.

        This route is designed to handle GET requests for static files located
        in the 'static' directory. The route parameter 'file_name' specifies
        the name of the file to be served. The function ensures that the file
        is sent as an attachment.

        Args:
            file_name (str): The name of the static file to be served.

        Returns:
            flask.Response: A Flask Response object representing the static file.
            If the file is found in the 'static' directory, it is served with an
            'attachment' disposition.

        Raises:
            werkzeug.exceptions.NotFound: If the specified file is not found in the
                                          'static' directory.

        Notes:
            - The route is accessible at "/api/static_files/<file_name>".
        """
        return send_from_directory("./static", file_name, as_attachment=True)

    @app.route("/token/login", methods=["GET"])
    def login():  # pylint: disable=unused-variable
        """
        Perform user authentication and generate JWT tokens for login.

        This route handles HTTP POST requests for user login. It expects JSON payload
        containing "username" and "password" parameters. Upon successful authentication,
        it generates access and refresh tokens using the 'create_access_token' and
        'create_refresh_token' functions.

        CSRF protection is applied if 'JWT_COOKIE_CSRF_PROTECT' is set to True. The CSRF
        protection cookies are set using 'set_access_cookies' and 'set_refresh_cookies'
        functions.

        Args:
            None

        Returns:
            tuple: A tuple containing the Flask Response and the HTTP status code.
                The response includes a JSON object with "login" set to True and
                additional user information like "uids" and "uuid".

        """
        username = request.headers.get("X-USERNAME")
        pgroups = request.headers.get("X-PGROUPS")

        if not username:
            return jsonify({"msg": "Missing username parameter"}), 200

        uids = [pgroup.split('p')[-1] for pgroup in pgroups.split()]
        uuid = []
        for account in uids:
            try:
                eaccount = "e" + account
                user = get_user(eaccount, api_key)
                uuid.append(user)
            except Exception as e:
                return jsonify({"msg": e}), 200

        resp = jsonify(
            {
                "login": True,
                "uids": uids,
                "uuid": uuid,
            }
        )
        return resp, 200


    @app.route("/api/token/create", methods=["POST"])
    def create_new_token():
        pgroup = request.json.get("pgroup")
        purpose = request.json.get("purpose")
        token = create_token(pgroup=pgroup, purpose=purpose)
        return token

    @app.route("/api/token/revoke/<string:token>", methods=["DELETE"])
    def delete_api_token(token):
        """Delete the token to revoke access to API"""
        deleted = delete_token(token)
        return deleted

    @app.route("/api/tokens/<string:pgroup>", methods=["GET"])
    def get_pgroup_tokens(pgroup):
        """Get the UUID4 API tokens for a specific pgroup"""
        tokens = get_tokens(pgroup)
        return tokens

    @app.route("/api/upload", methods=["POST"])
    def upload():  # pylint: disable=unused-variable
        """Upload the xls/xlsx spreadsheet for validation with pydantic models"""
        inputfile = request.files["file"]
        try:
            model = SampleSpreadsheetImporter().import_spreadsheet(
                inputfile, as_data_blob=True, validator_app=True
            )
            is_valid = True
            msg = "Your spreadsheet is valid."
            table_headers = list(model[0].keys())
        except SpreadsheetImportError as e:
            model = []
            is_valid = False
            msg = f"Your spreadsheet is not valid. {e}"
            table_headers = []

        # Try to assign colors puck by puck
        model_tmp = model.copy()

        if is_valid:
            last_puck_name = None
            colors = ["odd", "even"]

            for row in model_tmp:
                puck_name = row["puckname"]
                if puck_name != last_puck_name:
                    last_puck_name = puck_name
                    # Swap two colors
                    color_swap = colors.pop()
                    colors = [color_swap] + colors
                row["color"] = colors[0]
            model = model_tmp

        return (
            jsonify(
                {
                    "isSpreadsheetValid": is_valid,
                    "model": model,
                    "msg": msg,
                    "tableHeaders": table_headers,
                }
            ),
            200,
        )

    @app.route("/api/query", methods=["POST"])
    def query_mongo():
        """
        Perform a MongoDB query based on user permissions and specified parameters.

        This route handles HTTP POST requests for querying MongoDB data. It first checks
        with the DUO API to ensure that the user identified by the JWT has permission to
        view the specified eaccount. The request payload is expected to contain the
        "user_account", "after", and "before" parameters.

        Args:
            None

        Returns:
            tuple: A tuple containing the Flask Response and the HTTP status code.
                The response includes the MongoDB query results.

        Raises:
            werkzeug.exceptions.BadRequest:
                If the request JSON payload is missing the "user_account" parameter.
        """
        user_account = request.json.get("user_account", None)
        after = request.json.get("after", None)
        before = request.json.get("before", None)
        if not (after or before):
            docs = adp_get_results(user_account=user_account)
        else:
            docs = adp_get_results(
                user_account=user_account, after=after, before=before
            )
        resp = docs
        return resp, 200

    @app.route("/api/results", methods=["POST"])
    def api_query_mongo():
        user = getattr(g, "user", None)
        if not user:
            return "Unauthorized", 401
        user_account = "e" + user.strip("p")
        after = request.json.get("after", None)
        before = request.json.get("before", None)
        if not (after or before):
            docs = adp_get_results(user_account=user_account)
        else:
            docs = adp_get_results(
                user_account=user_account, after=after, before=before
            )
        resp = docs
        return resp, 200

    @app.route("/api/vespa", methods=["GET", "POST"])
    def vespa_query_mongo():
        user_account = request.json.get("user_account", None)
        docs = vespa_get_results(user_account=user_account)
        resp = docs
        return resp, 200

    compress.init_app(app)

    return app


if __name__ == "__main__":
    print("Starting Server in Development Mode")
    app = create_app(False)  # start app in dev mode
    app.run()
