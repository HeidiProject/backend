import uuid

from flask import Flask, g, jsonify, request, send_from_directory

from flask_compress import Compress

from flask_cors import CORS

from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    create_refresh_token,
    get_jwt_identity,
    jwt_required,
    set_access_cookies,
    set_refresh_cookies,
    unset_jwt_cookies,
)

import ldap

from mongo_database import (
    adp_get_results,
    create_token,
    delete_token,
    get_token,
    get_tokens,
    get_user,
    vespa_get_results,
)

import psi_active_directory

from sample_importer import (
    SampleSpreadsheetImporter,
    SpreadsheetImportError,
)

import yaml


# Load YAML data from secrets file
with open("config.yaml", "r") as stream:
    try:
        yaml_data = yaml.safe_load(stream)
        jwt_secret_key = yaml_data["mongo"]["JWT_SECRET_KEY"]
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

    # Adjust NGINX_prefix for production deployment
    # Don't inlclude trailing or following '/'
    NGINX_location_prefix = "auth"

    # Configure application to store JWTs in cookies
    app.config["JWT_TOKEN_LOCATION"] = ["cookies"]

    # Configure application to use "None" -
    # by default this becomes "Lax" if not provided
    app.config["JWT_COOKIE_SAMESITE"] = "None"

    # Only allow JWT cookies to be sent over https.
    # In production, this should likely be True
    if app.config["in_dev_mode"]:
        app.config["JWT_COOKIE_SECURE"] = False
    else:
        app.config["JWT_COOKIE_SECURE"] = True

    # Set the cookie paths, so that you are only sending your access token
    # cookie to the access endpoints, and only sending your refresh token
    # to the refresh endpoint. Technically this is optional, but it is in
    # your best interest to not send additional cookies in the request if
    # they aren't needed.
    if app.config["in_dev_mode"]:
        app.config["JWT_ACCESS_COOKIE_PATH"] = "/api/"
    else:
        app.config["JWT_ACCESS_COOKIE_PATH"] = f"/{NGINX_location_prefix}/api/"
    app.config["JWT_REFRESH_COOKIE_PATH"] = "/token/refresh"

    # Enable csrf double submit protection. See this for a thorough
    # explanation: http://www.redotheweb.com/2015/11/09/api-security.html
    app.config["JWT_COOKIE_CSRF_PROTECT"] = True

    # Set the secret key to sign the JWTs with
    app.config["JWT_SECRET_KEY"] = jwt_secret_key

    jwt = JWTManager()
    jwt.init_app(app)

    # By default, the CRSF cookies will be called csrf_access_token and
    # csrf_refresh_token, and in protected endpoints we will look for the
    # CSRF token in the 'X-CSRF-TOKEN' header. You can modify all of these
    # with various app.config options. Check the options page for details.

    def verify_jwt_token(jwt_token):
        if jwt_token == app.config["JWT_SECRET_KEY"]:
            return True
        else:
            return False

    def authenticate_token():
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
        jwt_token = None
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            jwt_token = auth_header.split(" ")[1]
        else:
            jwt_cookie = request.cookies.get("jwt_token")
            if jwt_cookie:
                jwt_token = jwt_cookie

        if jwt_token and verify_jwt_token(jwt_token):
            user = get_jwt_identity()
            if user:
                g.user = user
                return

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
        """Call the middleware to authenticate before each request"""
        authenticate_token()

    @app.errorhandler(401)
    def unauthorized_error(error):
        """Custom error handler for 401 Unauthorized"""
        return jsonify(error="Unauthorized"), 401

    @app.route("/api/static_files/<string:file_name>", methods=["GET"])
    @jwt_required()
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
            - This function requires a valid JSON Web Token (JWT) for authentication.
              The '@jwt_required()' decorator enforces this requirement.
        """
        return send_from_directory("./static", file_name, as_attachment=True)

    @app.route("/token/login", methods=["POST"])
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

        Raises:
            werkzeug.exceptions.BadRequest: If the request JSON payload is missing
                                            the "username" or "password" parameters.
            werkzeug.exceptions.Unauthorized: If the authentication fails due to an
                                            invalid username or password.
        """
        username = request.json.get("username", None)
        password = request.json.get("password", None)

        if not username:
            return jsonify({"msg": "Missing username parameter"}), 200
        if not password:
            return jsonify({"msg": "Missing password parameter"}), 200

        try:
            auth = psi_active_directory.User(
                username, password
            )  # pylint: disable=unused-variable
        except (
            ldap.INVALID_CREDENTIALS
        ) as e:  # pylint: disable=unused-variable,no-member
            return jsonify({"msg": f"Wrong username or password. {e}"}), 200

        uids = []
        for group in auth.pgroups:
            uids.append(group.split("p")[-1])

        uuid = []
        for account in uids:
            try:
                eaccount = "e" + account
                user = get_user(eaccount, api_key)
                uuid.append(user)
            except Exception as e:
                return jsonify({"msg": e}), 200

        # Create the tokens we will be sending back to the user
        access_token = create_access_token(
            identity={"username": username, "uids": uids, "uuid": uuid}
        )
        refresh_token = create_refresh_token(
            identity={"username": username, "uids": uids, "uuid": uuid}
        )

        # Set the JWTs and the CSRF double submit protection cookies in this response
        resp = jsonify(
            {
                "login": True,
                "uids": uids,
                "uuid": uuid,
            }
        )
        set_access_cookies(resp, access_token)
        set_refresh_cookies(resp, refresh_token)
        return resp, 200

    @app.route("/token/refresh", methods=["POST"])
    @jwt_required(refresh=True)
    def refresh():  # pylint: disable=unused-variable
        """
        Create the new access token and set the access JWT and
        CSRF double submit protection cookies in this response
        """
        current_user = get_jwt_identity()
        access_token = create_access_token(identity=current_user)
        resp = jsonify({"refresh": True})
        set_access_cookies(resp, access_token)
        return resp, 200

    @app.route("/token/logout", methods=["POST"])
    def logout():  # pylint: disable=unused-variable
        """
        Because the JWTs are stored in an httponly cookie now, we cannot
        log the user out by simply deleting the cookie in the frontend.
        We need the backend to send us a response to delete the cookies
        in order to logout. unset_jwt_cookies is a helper function to do this.
        """
        resp = jsonify({"logout": True})
        unset_jwt_cookies(resp)
        return resp, 200

    @app.route("/api/token/create", methods=["POST"])
    @jwt_required()
    def create_new_token():
        pgroup = request.json.get("pgroup")
        purpose = request.json.get("purpose")
        token = create_token(pgroup=pgroup, purpose=purpose)
        return token

    @app.route("/api/token/revoke/<string:token>", methods=["DELETE"])
    @jwt_required()
    def delete_api_token(token):
        """Delete the token to revoke access to API"""
        deleted = delete_token(token)
        return deleted

    @app.route("/api/tokens/<string:pgroup>", methods=["GET"])
    @jwt_required()
    def get_pgroup_tokens(pgroup):
        """Get the UUID4 API tokens for a specific pgroup"""
        tokens = get_tokens(pgroup)
        return tokens

    @app.route("/api/upload", methods=["POST"])
    @jwt_required()
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
    @jwt_required()
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
            werkzeug.exceptions.Unauthorized:
                If the JWT user does not have permission to view the specified eaccount.
            werkzeug.exceptions.NotFound:
                If no account is selected in the request payload.
            werkzeug.exceptions.Unauthorized:
                If the JWT user does not have permission for the selected account.
        """
        user = get_jwt_identity()
        selected_account = request.json.get("user_account", None)
        if selected_account.strip("e") in user["uids"]:
            user_account = selected_account
        elif selected_account == "":
            return "No account was selected", 200
        else:
            return "No permissions for selected account", 401
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
    @jwt_required()
    def vespa_query_mongo():
        user = get_jwt_identity()
        selected_account = request.json.get("user_account", None)
        if selected_account.strip("e") in user["uids"]:
            user_account = selected_account
        elif selected_account == "":
            return "No account was selected", 200
        else:
            return "No permissions for selected account", 401
        docs = vespa_get_results(user_account=user_account)
        resp = docs
        return resp, 200

    compress.init_app(app)

    return app


if __name__ == "__main__":
    print("Starting Server in Development Mode")
    app = create_app(False)  # start app in dev mode
    app.run()
