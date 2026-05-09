# RESTO PRO v5 — Render Free + Supabase PostgreSQL

This package replaces the old browser `localStorage` data layer with a central Supabase PostgreSQL backend.

## Required Render environment variables

```text
NODE_VERSION=20
NODE_ENV=production
JWT_SECRET=<long random secret, 32+ chars>
DATABASE_URL=<Supabase Transaction Pooler URL, port 6543>
OCR_ENABLED=true
```

Do not use the Supabase Direct URL on Render Free if it shows the IPv4 warning. Use the Transaction Pooler URL.

Correct shape:

```text
postgresql://postgres.PROJECTREF:YOUR_PASSWORD@aws-0-REAL-REGION.pooler.supabase.com:6543/postgres
```

Wrong shape:

```text
postgresql://postgres:YOUR_PASSWORD@db.PROJECTREF.supabase.co:5432/postgres
postgresql://postgres.PROJECTREF:YOUR_PASSWORD@aws-0-xxxxx.pooler.supabase.com:6543/postgres
```

## Default first login

```text
owner@resto.com
owner123
```

Change it immediately after first login.

## What changed

- Frontend no longer seeds owner user.
- Frontend no longer stores restaurant data in localStorage.
- Browser stores only the JWT token and language/theme preferences.
- All restaurant data is persisted in Supabase `app_state` table.
- Socket.IO requires JWT authentication.
- API routes require JWT except login, health, and password reset request.
- Passwords are hashed using bcrypt on the server.
- Password reset requests store a hashed proposed password, not plaintext.
- Security headers, CORS support, rate limiting, input validation, and generic error handling are added.
