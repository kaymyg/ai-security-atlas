# Web-app patterns, Python (Flask/Django/FastAPI style).
import os
import random
import secrets
import ssl

import httpx
import jwt
import requests

DEBUG = True  # expect[VIBE017] Django settings shipped with debug on
WTF_CSRF_ENABLED = False  # expect[VIBE053]
CSRF_COOKIE_SECURE = True  # safe[VIBE053]


def tls(url, session, ctx):
    requests.get(url, verify=False)  # expect[VIBE016]
    session.verify = False  # expect[VIBE016]
    httpx.Client(verify=False)  # expect[VIBE016]
    requests.get(url, verify=True)  # safe[VIBE016]
    requests.get(url, verify="/etc/ssl/internal-ca.pem")  # safe[VIBE016]
    ctx.verify_mode = ssl.CERT_NONE  # expect[VIBE016] verification off via ssl module


def paths_and_fetches(request, UPLOAD_DIR, API_URL, safe_join, secure_filename, name):
    open("uploads/" + request.args["f"])  # expect[VIBE018]
    open(os.path.join(UPLOAD_DIR, request.files["f"].filename))  # expect[VIBE018]
    open(safe_join(UPLOAD_DIR, secure_filename(name)))  # safe[VIBE018]
    filename = request.args["f"]
    open(filename)  # miss[VIBE018] tainted value from the line above
    requests.get(request.args["url"])  # expect[VIBE019]
    httpx.get(request.json["webhook"])  # expect[VIBE019]
    requests.get(API_URL, params={"q": request.args["q"]})  # noisy[VIBE019] fixed host, user data only in params
    requests.get(f"{API_URL}/health", timeout=5)  # safe[VIBE019]


def tokens(chars):
    reset_token = str(random.randint(100000, 999999))  # expect[VIBE050]
    api_key = "".join(random.choice(chars) for _ in range(32))  # expect[VIBE050]
    token = secrets.token_urlsafe(32)  # safe[VIBE050]
    shuffle_seed = random.random()  # safe[VIBE050] not a secret
    otp = str(random.SystemRandom().randint(0, 999999))  # safe[VIBE050] SystemRandom is a CSPRNG
    return reset_token, api_key, token, shuffle_seed, otp


def auth(app, token, key, CORS, CORSMiddleware):
    jwt.decode(token, options={"verify_signature": False})  # expect[VIBE051]
    jwt.decode(token, key, algorithms=["HS256"])  # safe[VIBE051]
    app.add_middleware(CORSMiddleware, allow_origins=["*"])  # expect[VIBE052]
    CORS(app, origins=["https://app.example.com"])  # safe[VIBE052]
    CORS(app)  # expect[VIBE052] Flask-CORS allows every origin by default
    app.run(debug=True)  # expect[VIBE017]
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")  # safe[VIBE017]


@csrf_exempt  # expect[VIBE053]
def webhook(request):
    # TODO: add authentication before launch  expect[VIBE054]
    # TODO: validate the payload signature  expect[VIBE054]
    # TODO: rename this function  safe[VIBE054]
    # TODO: update the docs about the authentication flow  noisy[VIBE054] a docs chore, not a missing check
    return "ok"
