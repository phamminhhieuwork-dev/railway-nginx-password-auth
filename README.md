# Railway Nginx Password Auth

[![Deploy on Railway](https://railway.com/button.svg)](https://railway.com/deploy/nginx-password-auth)

A lightweight nginx-based reverse proxy with HTTP Basic Authentication, designed for deployment on Railway and other container platforms.

## 🚀 Quick Deploy

**Option 1: One-Click Railway Template**
Click the "Deploy on Railway" button above for instant deployment with auto-configured settings.

**Option 2: Manual Setup**
Follow the instructions below for custom configuration.

## Features

- 🔒 **Secure by Default** - Requires Basic Authentication unless explicitly disabled
- 🚀 **WebSocket Support** - Full support for WebSocket connections
- 🐳 **Docker Ready** - Built on Alpine Linux for minimal footprint
- ⚡ **Railway Optimized** - Designed specifically for Railway deployments
- 🔧 **Environment Configurable** - Easy setup via environment variables
- 🐛 **Debug Friendly** - Clear error messages for faster troubleshooting

## Environment Variables

| Variable           | Required | Description                                         | Example                     |
| ------------------ | -------- | --------------------------------------------------- | --------------------------- |
| `ORIGIN`           | ✅       | The upstream URL to proxy to                        | `https://myapp.railway.app` |
| `BASIC_AUTH`       | ✅\*     | Username and password in `username:password` format | `admin:mysecretpass`        |
| `BASIC_AUTH_REALM` | ❌       | Authentication realm message                        | `"Restricted Area"`         |
| `ALLOW_NO_AUTH`    | ❌       | Set to `"true"` to disable auth requirement         | `"true"`                    |

\*Required by default for security. Set `ALLOW_NO_AUTH=true` to make it optional.

## Use Cases

### Protecting Development/Staging Environments

```bash
# Protect your staging app with basic auth (using Railway private networking)
ORIGIN=http://myapp.railway.internal:3000
BASIC_AUTH=dev:staging123
BASIC_AUTH_REALM="Staging Environment"
```

### Adding Auth to Public APIs

```bash
# Add authentication layer to an existing API
ORIGIN=https://api.myservice.com
BASIC_AUTH=client:api-key-here
```

## Troubleshooting

### Common Issues

**"ORIGIN env var is required" error:**

- Make sure you've set the `ORIGIN` environment variable
- Verify the URL format includes protocol (http:// or https://)

**"BASIC_AUTH is required for security" error:**

- Set `BASIC_AUTH=username:password` to enable authentication
- Or set `ALLOW_NO_AUTH=true` to disable the auth requirement

**"BASIC_AUTH must be in 'username:password' format" error:**

- Ensure your `BASIC_AUTH` value contains exactly one colon
- Format: `username:password`

**"Failed to create htpasswd file" error:**

- Check that your password doesn't contain special characters that might cause issues
- Try a simpler password to test

**502 Bad Gateway:**

- Check that your `ORIGIN` URL is accessible
- Verify the upstream service is running
- Ensure network connectivity between proxy and origin

**"Invalid nginx configuration" error:**

- Check the container logs for specific nginx configuration errors
- Verify that all environment variables are set correctly

### Logs

View container logs to debug issues:

```bash
docker logs <container-id>
```

On Railway, check the deployment logs in your project dashboard.

## Quick Start

### Local Development

1. **Build the Docker image:**

   ```bash
   docker build -t nginx-revproxy .
   ```

2. **Run with Basic Auth (default behavior):**

   ```bash
   docker run -p 8080:80 \
     -e ORIGIN="http://host.docker.internal:3000" \
     -e BASIC_AUTH="admin:supersecret" \
     nginx-revproxy
   ```

3. **Run without authentication (requires explicit override):**
   ```bash
   docker run -p 8080:80 \
     -e ORIGIN="http://host.docker.internal:3000" \
     -e ALLOW_NO_AUTH="true" \
     nginx-revproxy
   ```

## Logging and OAuth callback secrets

The Google OAuth callback (`/api/auth/callback/google`) carries a one-time `code` and a `state` in its query string.
To keep them out of Railway logs:

- `access_log` uses the `safe_access` format: method, **path only** (`$uri`, no query), status, bytes, latency (`rt=`),
  upstream status (`us=`), the Referer with its query stripped, and `auth=0|1` (whether an Authorization header was
  sent, never its value).
- nginx cannot redact `error_log`: every request-scoped entry (upstream refused, timeout, DNS failure, ...) includes the
  request line and upstream URL with the query. Errors for the exact callback location are therefore discarded
  (`error_log /dev/null emerg;` inside that location). A callback failure is still visible as status / `us=` / `rt=` in the
  access log, and the underlying cause (DNS, upstream down) shows up in the error log for other paths, whose URLs carry no
  OAuth secrets.
- Residual risk: request-scoped `error_log` entries of *other* locations still contain their own query strings.

Test (Python 3, standard library only; synthetic canary values):

```
python3 tests/oauth_log_redaction.py --mode docker --template nginx.conf.template        # real image, as in CI
python3 tests/oauth_log_redaction.py --mode local --nginx "$(which nginx)" --template nginx.conf.template
```

## License

MIT License - feel free to use this in your projects!

## Client IP forwarded to the app (rate limiting)
nginx sends the app exactly ONE address in `X-Forwarded-For`: the right-most entry of the incoming header (the address the
Railway edge appended for the connection it received), validated as an IPv4/IPv6 literal, else `$remote_addr`. Client-supplied
entries to its left are discarded. This lets meeting-ai (Better Auth) rate-limit per client instead of one shared bucket.
It is only safe while the Railway edge always appends or overwrites `X-Forwarded-For` and meeting-ai has no ingress other than
this proxy. Tested by `tests/client_ip_normalization.py`. The access log carries `cip=<forwarded client IP>`.

