# Deploying to Render (free shareable URL)

This session's sandbox can't reach Render's API directly (its outbound network is restricted
to an allowlist that doesn't include hosting providers), so this deploy has to happen from
your own browser -- but it's a one-time, ~10 minute setup after that, and every future
`git push` auto-redeploys.

## 0. Prerequisite: the code needs to be on GitHub first

Render deploys from a GitHub repo, so finish the GitHub push (see the main README/earlier
instructions) before starting this.

## 1. Generate a real ENCRYPTION_KEY

This has to be a real Fernet key, not just any random string - generate one locally:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Copy the output somewhere safe. You'll paste it into Render in step 3. **If you ever lose
this key, every stored mailbox credential becomes unrecoverable** - it's not something Render
can regenerate for you.

## 2. Create the Blueprint

- Go to [dashboard.render.com](https://dashboard.render.com) -> **New** -> **Blueprint**.
- Connect your GitHub account if you haven't, then pick the `IETD-System` repo.
- Render reads `render.yaml` (already in this repo) and shows you two resources it's about to
  create: a free Postgres database (`ietds-db`) and a free web service (`ietds`). Click **Apply**.

## 3. Fill in the secrets Render can't generate for you

`render.yaml` marks a few environment variables as needing a manual value (`sync: false`).
On the `ietds` service's **Environment** tab, set:

| Key | Value |
|---|---|
| `ENCRYPTION_KEY` | the Fernet key from step 1 |
| `GMAIL_CLIENT_ID` | from Google Cloud Console (see `docs/oauth-setup.md`) |
| `GMAIL_CLIENT_SECRET` | from Google Cloud Console |
| `GMAIL_REDIRECT_URI` | `https://<your-service>.onrender.com/mailboxes/oauth/gmail/callback` - Render shows you the exact `.onrender.com` URL once the service is created; also add this same URL as an authorized redirect URI in the Google Cloud Console |

`SECRET_KEY` and `DATABASE_URL` are filled in automatically by the blueprint - leave those alone.

## 4. Grant yourself super admin on the hosted deployment

Render's dashboard has a **Shell** tab for the web service - open it and run:

```bash
flask --app wsgi:app create-super-admin you@gmail.com
```

(register that account in the hosted app first, then run this - same as local).

## 5. Share the URL

Render gives you a URL like `https://ietds.onrender.com` - that's what you share with end
users. Every future `git push` to the branch Render is watching triggers an automatic rebuild
and redeploy - no manual redeploy step needed.

## Free tier limits worth knowing

- The free web service spins down after ~15 minutes idle and takes ~30-60 seconds to wake up
  on the next request. Fine for demoing to people who know to wait a moment on the first load;
  annoying for "always instant." Paid plans remove this.
- The free Postgres database expires after 90 days on Render's free tier (Render will email you
  before that happens) - back up your data before then, or upgrade the database plan.
- Free web services get limited monthly hours - fine for a project demo, worth checking Render's
  current limits if this gets real ongoing traffic.
