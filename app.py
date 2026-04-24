"""
OAuth 2.0 Token Capture Lab
============================
Manual OAuth flow using requests — no authlib dependency.
Shows every step explicitly, perfect for educational demo.
"""

from flask import Flask, redirect, request, session, url_for, render_template
from dotenv import load_dotenv
import requests
import os
import secrets
import urllib.parse

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "supersecretkey123")
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = False

# ── Google OAuth Config ────────────────────────────────────────
CLIENT_ID     = os.getenv("GOOGLE_CLIENT_ID")
CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
REDIRECT_URI  = os.getenv("REDIRECT_URI", "http://localhost:5000/callback")

GOOGLE_AUTH_URL  = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO  = "https://www.googleapis.com/oauth2/v3/userinfo"
GOOGLE_REVOKE    = "https://oauth2.googleapis.com/revoke"

print("APP STARTING...")

# ── Routes ─────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login')
def login():
    """
    STEP 1: Build Google OAuth URL manually and redirect user.
    We generate a state token ourselves for CSRF protection.
    """
    scope_type = request.args.get('scope', 'minimal')

    # Generate and store state token in session
    state = secrets.token_urlsafe(32)
    session.clear()
    session['oauth_state'] = state
    session['scope_type'] = scope_type

    # Choose scopes based on scenario
    if scope_type == 'full':
        scope = ' '.join([
            'openid',
            'email',
            'profile',
            'https://www.googleapis.com/auth/drive.readonly',
            'https://www.googleapis.com/auth/calendar.readonly',
            'https://www.googleapis.com/auth/gmail.readonly',
        ])
    else:
        scope = 'openid email profile'

    # Build the Google OAuth URL manually
    params = {
        'client_id':     CLIENT_ID,
        'redirect_uri':  REDIRECT_URI,
        'response_type': 'code',
        'scope':         scope,
        'state':         state,
        'access_type':   'offline',
        'prompt':        'consent',
    }

    auth_url = GOOGLE_AUTH_URL + '?' + urllib.parse.urlencode(params)

    print(f"\n[STEP 1] Redirecting to Google OAuth...")
    print(f"[STATE]  {state}")
    print(f"[SCOPE]  {scope}\n")

    return redirect(auth_url)


@app.route('/callback')
def callback():
    """
    STEP 2: Google redirects here with authorization code.
    We manually verify state, then exchange code for token.
    """

    # Get params from Google's redirect
    returned_state = request.args.get('state')
    code           = request.args.get('code')
    error          = request.args.get('error')

    if error:
        return f"<h2>OAuth Error: {error}</h2><a href='/'>Go back</a>"

    # ── CSRF State Check ──────────────────────────────────────
    stored_state = session.get('oauth_state')

    print(f"\n[STEP 2] Callback received")
    print(f"[STATE CHECK] stored={stored_state} | returned={returned_state}")

    if not stored_state or stored_state != returned_state:
        return """
            <h2 style='color:red'>State Mismatch — CSRF check failed</h2>
            <p>Session may have expired. <a href='/'>Try again</a></p>
        """

    # ── Exchange Code for Token ───────────────────────────────
    print(f"[STEP 3] Exchanging authorization code for token...")

    token_response = requests.post(GOOGLE_TOKEN_URL, data={
        'code':          code,
        'client_id':     CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'redirect_uri':  REDIRECT_URI,
        'grant_type':    'authorization_code',
    })

    token_data = token_response.json()

    if 'error' in token_data:
        return f"<h2>Token Error: {token_data}</h2><a href='/'>Go back</a>"

    access_token  = token_data.get('access_token')
    expires_in    = token_data.get('expires_in')
    scope         = token_data.get('scope')
    refresh_token = token_data.get('refresh_token', 'Not granted')

    # !! THE MOMENT — token is now captured !!
    print("\n" + "="*60)
    print("🚨 TOKEN CAPTURED")
    print("="*60)
    print(f"ACCESS TOKEN  : {access_token}")
    print(f"EXPIRES IN    : {expires_in} seconds")
    print(f"SCOPE         : {scope}")
    print(f"REFRESH TOKEN : {refresh_token}")
    print("="*60 + "\n")

    # ── Use Token to Fetch User Info ──────────────────────────
    print("[STEP 4] Calling Google UserInfo API with stolen token...")

    userinfo_response = requests.get(
        GOOGLE_USERINFO,
        headers={'Authorization': f'Bearer {access_token}'}
    )
    userinfo = userinfo_response.json()

    print(f"[USERINFO] {userinfo}\n")

    # Store everything in session
    session['access_token']  = access_token
    session['expires_in']    = expires_in
    session['scope']         = scope
    session['refresh_token'] = refresh_token
    session['userinfo']      = userinfo

    return redirect(url_for('dashboard'))


@app.route('/dashboard')
def dashboard():
    if 'access_token' not in session:
        return redirect(url_for('index'))

    return render_template('dashboard.html',
        access_token  = session.get('access_token'),
        expires_in    = session.get('expires_in'),
        scope         = session.get('scope'),
        scope_type    = session.get('scope_type'),
        refresh_token = session.get('refresh_token'),
        userinfo      = session.get('userinfo')
    )


@app.route('/revoke')
def revoke():
    access_token = session.get('access_token')

    if not access_token:
        return redirect(url_for('index'))

    # Call Google revocation endpoint
    revoke_response = requests.post(
        GOOGLE_REVOKE,
        params={'token': access_token},
        headers={'Content-Type': 'application/x-www-form-urlencoded'}
    )
    revoke_status = revoke_response.status_code

    # Try to use the dead token
    dead_response = requests.get(
        GOOGLE_USERINFO,
        headers={'Authorization': f'Bearer {access_token}'}
    )
    dead_status = dead_response.status_code

    partial_token = access_token[:20] + "..."
    session.clear()

    return render_template('revoked.html',
        revoke_status = revoke_status,
        dead_status   = dead_status,
        access_token  = partial_token
    )


if __name__ == '__main__':
    app.run(debug=True, port=5000)