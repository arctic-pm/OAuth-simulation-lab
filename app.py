"""
OAuth 2.0 Token Capture Lab
============================
Manual OAuth flow using requests — no authlib dependency.
Shows every step explicitly, perfect for educational demo.
"""

from flask import Flask, redirect, request, session, url_for, render_template
from dotenv import load_dotenv
import base64
from email import message_from_bytes
import requests
import os
import secrets
import urllib.parse
import time

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
    session['token_captured_at'] = int(time.time())
    session['expires_in']    = expires_in
    session['scope']         = scope
    session['refresh_token'] = refresh_token
    session['userinfo']      = userinfo

    return redirect(url_for('dashboard'))


@app.route('/dashboard')
@app.route('/dashboard')
def dashboard():
    if 'access_token' not in session:
        return redirect(url_for('index'))

    # Calculate actual remaining seconds
    captured_at = session.get('token_captured_at', int(time.time()))
    expires_in  = session.get('expires_in', 3599)
    elapsed     = int(time.time()) - captured_at
    remaining   = max(0, int(expires_in) - elapsed)

    return render_template('dashboard.html',
        access_token  = session.get('access_token'),
        expires_in    = remaining,          # ← now dynamic
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


def decode_base64_url(data):
    """Decode base64url encoded Gmail body data."""
    if not data:
        return ""
    # Fix padding
    padding = 4 - len(data) % 4
    if padding != 4:
        data += '=' * padding
    try:
        decoded = base64.urlsafe_b64decode(data)
        return decoded.decode('utf-8', errors='replace')
    except Exception:
        return "[Could not decode content]"


def get_auth_headers():
    """Get authorization headers from session token."""
    token = session.get('access_token')
    if not token:
        return None
    return {'Authorization': f'Bearer {token}'}


# ── Gmail Routes ───────────────────────────────────────────────

@app.route('/api/emails')
def api_emails():
    """Fetch list of recent emails."""
    headers = get_auth_headers()
    if not headers:
        return {'error': 'No token in session'}, 401

    response = requests.get(
        'https://gmail.googleapis.com/gmail/v1/users/me/messages',
        headers=headers,
        params={'maxResults': 50}
    )

    if response.status_code != 200:
        return {'error': f'Gmail API error: {response.status_code}', 'detail': response.json()}, response.status_code

    data = response.json()
    return {'messages': data.get('messages', [])}


@app.route('/api/email/<message_id>')
def api_email(message_id):
    """Fetch and decode a specific email."""
    headers = get_auth_headers()
    if not headers:
        return {'error': 'No token in session'}, 401

    response = requests.get(
        f'https://gmail.googleapis.com/gmail/v1/users/me/messages/{message_id}',
        headers=headers,
        params={'format': 'full'}
    )

    if response.status_code != 200:
        return {'error': f'Gmail API error: {response.status_code}'}, response.status_code

    msg = response.json()
    payload = msg.get('payload', {})
    headers_list = payload.get('headers', [])

    # Extract subject and sender
    subject = next((h['value'] for h in headers_list if h['name'] == 'Subject'), '(No Subject)')
    sender  = next((h['value'] for h in headers_list if h['name'] == 'From'), '(Unknown Sender)')

    # Extract body — check parts first, then direct body
    body = ""
    parts = payload.get('parts', [])

    if parts:
        for part in parts:
            if part.get('mimeType') == 'text/plain':
                body = decode_base64_url(part.get('body', {}).get('data', ''))
                break
        if not body:
            # Try HTML part as fallback
            for part in parts:
                if part.get('mimeType') == 'text/html':
                    body = decode_base64_url(part.get('body', {}).get('data', ''))
                    break
    else:
        body = decode_base64_url(payload.get('body', {}).get('data', ''))

    # Handle nested multipart
    if not body and parts:
        for part in parts:
            subparts = part.get('parts', [])
            for sp in subparts:
                if sp.get('mimeType') == 'text/plain':
                    body = decode_base64_url(sp.get('body', {}).get('data', ''))
                    break

    return {
        'subject': subject,
        'from':    sender,
        'body':    body or '[No readable content found]'
    }


# ── Drive Routes ───────────────────────────────────────────────

@app.route('/api/files')
def api_files():
    """Fetch list of Drive files."""
    headers = get_auth_headers()
    if not headers:
        return {'error': 'No token in session'}, 401

    response = requests.get(
        'https://www.googleapis.com/drive/v3/files',
        headers=headers,
        params={'fields': 'files(id,name,mimeType,modifiedTime)', 'pageSize': 10}
    )

    if response.status_code != 200:
        return {'error': f'Drive API error: {response.status_code}', 'detail': response.json()}, response.status_code

    return response.json()


@app.route('/api/download/<file_id>')
def api_download(file_id):
    """Download a file from Drive."""
    headers = get_auth_headers()
    if not headers:
        return {'error': 'No token in session'}, 401

    # First get file metadata for name and type
    meta = requests.get(
        f'https://www.googleapis.com/drive/v3/files/{file_id}',
        headers=headers,
        params={'fields': 'name,mimeType'}
    ).json()

    filename = meta.get('name', 'download')
    mime     = meta.get('mimeType', 'application/octet-stream')

    # Google Workspace files need export instead of direct download
    export_types = {
        'application/vnd.google-apps.document':     ('application/pdf', 'pdf'),
        'application/vnd.google-apps.spreadsheet':  ('text/csv', 'csv'),
        'application/vnd.google-apps.presentation': ('application/pdf', 'pdf'),
    }

    if mime in export_types:
        export_mime, ext = export_types[mime]
        dl = requests.get(
            f'https://www.googleapis.com/drive/v3/files/{file_id}/export',
            headers=headers,
            params={'mimeType': export_mime}
        )
        filename = f"{filename}.{ext}"
    else:
        dl = requests.get(
            f'https://www.googleapis.com/drive/v3/files/{file_id}',
            headers=headers,
            params={'alt': 'media'}
        )

    from flask import Response
    return Response(
        dl.content,
        mimetype=mime,
        headers={'Content-Disposition': f'attachment; filename="{filename}"'}
    )


# ── Calendar Routes ────────────────────────────────────────────

@app.route('/api/events')
def api_events():
    """Fetch upcoming calendar events."""
    headers = get_auth_headers()
    if not headers:
        return {'error': 'No token in session'}, 401

    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()

    response = requests.get(
        'https://www.googleapis.com/calendar/v3/calendars/primary/events',
        headers=headers,
        params={
            'maxResults':  5,
            'orderBy':     'startTime',
            'singleEvents': True,
            'timeMin':     now,
        }
    )

    if response.status_code != 200:
        return {'error': f'Calendar API error: {response.status_code}', 'detail': response.json()}, response.status_code

    data = response.json()
    events = []

    for e in data.get('items', []):
        start = e.get('start', {})
        end   = e.get('end', {})
        events.append({
            'summary':  e.get('summary', '(No Title)'),
            'start':    start.get('dateTime', start.get('date', 'N/A')),
            'end':      end.get('dateTime',   end.get('date',   'N/A')),
            'location': e.get('location', ''),
        })

    return {'events': events}

if __name__ == '__main__':
    app.run(debug=True, port=5000)