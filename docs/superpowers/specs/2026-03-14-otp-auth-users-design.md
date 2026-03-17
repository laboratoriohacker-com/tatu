# OTP Authentication & User Management — Design Spec

> **Date:** 2026-03-14
> **Author:** Julio Melo + Claude
> **Status:** Approved

## Overview

Replace the shared-password login with per-user email OTP authentication, add a User model with three roles (admin/editor/viewer), and build a Users management section in the Settings page.

## Auth Flow

### Email OTP Login (replaces shared password)

1. User enters email on login page
2. Backend validates email exists and is active, generates 6-digit OTP, stores with 5-minute expiry, sends via SMTP
3. User enters OTP code
4. Backend verifies code, sets session cookie with user id + role

### Session

Same `itsdangerous` signed cookie (`tatu_session`, 24h expiry). Payload changes from `{authenticated: true}` to `{user_id, role, email}`.

### Bootstrap Admin

On app startup, if no users exist and `TATU_ADMIN_EMAIL` is set, create an admin user with that email. No password — auth is OTP-only.

## User Model

```
User:
  id: UUID (PK)
  email: str (unique)
  name: str
  role: str (admin | editor | viewer)
  active: bool (default false, set true on invite acceptance)
  created_at: datetime
  invited_by: UUID | null (FK to User.id)
```

## OTP Code Model

```
OtpCode:
  id: UUID (PK)
  user_id: UUID (FK to User.id)
  code: str (6-digit numeric)
  expires_at: datetime (5 minutes from creation)
  used: bool (default false)
```

## Roles & Permissions

| Action | Admin | Editor | Viewer |
|---|---|---|---|
| View dashboard (all pages) | Yes | Yes | Yes |
| Edit rules (mode, action, content) | Yes | Yes | No |
| Clone rules to custom | Yes | Yes | No |
| Create/revoke API keys | Yes | Yes | No |
| Manage users (invite, roles, deactivate) | Yes | No | No |
| View users list | Yes | Yes | No |
| Export audit log | Yes | Yes | Yes |

### Implementation

- `require_role(*roles)` FastAPI dependency — checks session cookie role
- Existing `require_dashboard_auth` modified to load user from session and attach to request state
- Frontend stores role in auth state, shows/hides UI elements accordingly
- Backend enforces permissions regardless of frontend

## User Management (Settings > Users)

### Admin capabilities
- View all users (table: name, email, role, active, created date)
- Invite new user (enter email + name + role) → sends invitation email
- Change user role (dropdown)
- Deactivate/reactivate users

### Editor capabilities
- View users list (read-only)

### Viewer
- Cannot see Users section

### Invitation Flow

1. Admin enters email, name, role on Users page
2. Backend creates user with `active=false`, generates invite token (URL-safe, 24h expiry via itsdangerous)
3. Sends email with link: `{frontend_url}/accept-invite?token=xxx`
4. User clicks link → account becomes `active=true` → redirected to login
5. User logs in with email OTP

## SMTP Configuration

Environment variables (added to Settings and .env.example):

```
# SMTP (required for OTP and invitations)
TATU_SMTP_HOST=localhost
TATU_SMTP_PORT=1025
TATU_SMTP_USER=
TATU_SMTP_PASSWORD=
TATU_SMTP_USE_TLS=false
TATU_SMTP_FROM=noreply@tatu.local

# Bootstrap admin (required on first run)
TATU_ADMIN_EMAIL=admin@example.com
```

### Local Development

Mailpit service in docker-compose for local email testing:

```yaml
mailpit:
  image: axllent/mailpit
  ports:
    - "1025:1025"   # SMTP
    - "8025:8025"   # Web UI
```

Defaults (localhost:1025, no auth, no TLS) work with Mailpit out of the box.

### Email Sending

Uses `aiosmtplib` for async SMTP. New dependency in requirements.txt.

## API Changes

### Modified Endpoints

- `POST /api/v1/auth/login` — Now takes `{email}`, sends OTP, returns `{message: "otp_sent"}`
- `require_dashboard_auth` — Now loads user from session, attaches to request state

### New Endpoints

- `POST /api/v1/auth/verify-otp` — Takes `{email, code}`, verifies OTP, sets session cookie with user_id + role
- `GET /api/v1/auth/accept-invite` — Takes `?token=xxx`, activates user, redirects to login
- `GET /api/v1/users` — List users (admin + editor only)
- `POST /api/v1/users/invite` — Invite user with email + name + role (admin only)
- `PUT /api/v1/users/{id}` — Update user role (admin only)
- `DELETE /api/v1/users/{id}` — Deactivate user (admin only)

## Frontend Changes

### Login Page

Two-step form:
1. Enter email → "Send Code" button
2. Enter 6-digit OTP → "Verify" button
3. On success, session cookie set, redirect to dashboard

### Settings Page

Add "Users" section below API Keys:
- Users table: Name, Email, Role, Status, Created
- Invite button (admin only) → inline form with email, name, role fields
- Role dropdown on each row (admin only)
- Deactivate button (admin only)

### Auth State

`useAuth` hook now returns `{user: {id, email, name, role}, isAuthenticated}` instead of just `{isAuthenticated}`. Role used for conditional UI rendering.

### Accept Invite Page

New route `/accept-invite` — reads token from query string, calls backend, shows success/error, links to login.

## Backend New Files

- `backend/app/models/user.py` — User model
- `backend/app/models/otp_code.py` — OtpCode model
- `backend/app/schemas/user.py` — UserCreate, UserInvite, UserResponse, UserUpdate
- `backend/app/schemas/auth.py` — Modified: LoginRequest (email only), OtpVerifyRequest, new responses
- `backend/app/services/email_service.py` — send_otp_email, send_invite_email
- `backend/app/services/otp_service.py` — create_otp, verify_otp
- `backend/app/services/user_service.py` — create_user, list_users, invite_user, update_role, deactivate
- `backend/app/routers/users.py` — Users CRUD router
- `backend/app/routers/auth.py` — Modified: OTP login flow

## Frontend New Files

- `frontend/src/pages/AcceptInvite.tsx` — Invite acceptance page

## Migration Notes

This is a breaking change to the auth system. The shared `TATU_DASHBOARD_PASSWORD` is replaced by `TATU_ADMIN_EMAIL`. Existing sessions will be invalidated. The `.env.example` must be updated with all new variables.
