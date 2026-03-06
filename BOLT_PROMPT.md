# Bolt Prompt — App Events Dashboard

Build a standalone **Next.js 14 (App Router)** page for an **App Events** feature. The backend API is running at `https://omcard.net`. Use **TypeScript**, **Tailwind CSS**, and **shadcn/ui** components. Dark mode default.

---

## Authentication

Use **Supabase Auth**. The user is already logged in — you just need the auth wrapper.

```
NEXT_PUBLIC_SUPABASE_URL=https://hgyjczknusozraefgnmq.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=sb_publishable__T1Zafy4IjFJkoPcFXHEUQ_VKqWScJd
NEXT_PUBLIC_API_URL=https://omcard.net
```

All API calls use: `Authorization: Bearer <supabase_access_token>`

---

## App Events Page (`/dashboard/events`)

Build a single page with **3 tabs**: Events Feed, Setup Integration, Alert Rules.

---

### Tab 1: Events Feed

Filterable, paginated table of application events.

**Columns:** Timestamp, Source, Event (badge), Severity (color badge), Meta (expandable JSON), IP

**Filters row:**
- Server dropdown (from `GET /v1/servers`)
- Source text input
- Event type dropdown
- Severity dropdown: info, warning, error
- Search input (q)
- Date range picker (since / until)

**Pagination:** limit/offset with "Load more" or page numbers

**API:** `GET /v1/app-events?server_id=uuid&source=auth-service&event=login_failed&severity=warning&q=searchtext&since=2026-01-01T00:00:00Z&until=2026-01-02T00:00:00Z&limit=50&offset=0`

**Response:**
```json
{
  "items": [
    {
      "id": 1,
      "server_id": "uuid",
      "source": "auth-service",
      "event": "login_failed",
      "severity": "warning",
      "meta": {"user_id": "123", "ip": "1.2.3.4", "reason": "wrong_password"},
      "ip": "1.2.3.4",
      "created_at": "2026-01-01T00:00:00Z"
    }
  ],
  "total": 150
}
```

**Severity badge colors:** info=blue, warning=yellow, error=red

**Meta column:** Show first 2-3 keys inline as small badges, click to expand full JSON in a popover or sheet.

**Auto-refresh:** Poll every 15 seconds for new events.

---

### Tab 2: Setup Integration — ServerNotify AI Assistant

This is the main way users set up event tracking. It uses an **AI-powered wizard** where the user describes events in plain language and gets back ready-to-paste code.

The product name is **ServerNotify**.

#### Wizard UI — Conversational Step-by-Step Flow

Show a card-based wizard with a clean conversational flow. Each step appears after the previous one is answered (like a chat/form hybrid — all visible on the same page, scrolling down as they progress). Completed steps collapse to a summary line with a green checkmark and can be clicked to edit.

Header: **"ServerNotify Integration Assistant"**

---

#### Step 1: Select Your Framework

Show a grid of framework/language cards (3x2 grid) with icons. User clicks one.

Options:
- **Python** (Flask / Django / FastAPI)
- **Node.js** (Express / Next.js / NestJS)
- **PHP** (Laravel)
- **Ruby** (Rails)
- **Go** (net/http)
- **cURL** (Any language)

Each card has a subtle icon and label. Selected card gets a highlighted border/ring.

When completed, collapse to: "Framework: Python"

---

#### Step 2: Describe Your Event

Show a **text input** (large textarea) with placeholder:

> "Describe what you want to track, e.g. 'user failed to login with wrong password' or 'payment completed successfully'"

The user types a plain-language description in **English or Arabic** — anything works.

Below the input, show a "Generate" button.

When the user clicks Generate, call the AI endpoint:

**API:** `POST /v1/events/generate`

```json
{
  "description": "user failed to login with wrong password",
  "platforms": ["python"]
}
```

The `platforms` array is set based on Step 1 selection. Map:
- Python → `["python"]`
- Node.js → `["node"]`
- PHP → `["php"]`
- Ruby → `["ruby"]`
- Go → `["go"]`
- cURL → `["curl"]`

**Response:**
```json
{
  "event_name": "login_failed",
  "display_name": "Login Failed",
  "category": "Authentication",
  "description": "Failed login attempt with incorrect password",
  "severity": "warning",
  "suggested_source": "auth-service",
  "parameters": [
    {"name": "user_id", "type": "String", "description": "User identifier", "example": "usr_123", "required": true},
    {"name": "ip", "type": "String", "description": "Client IP address", "example": "192.168.1.1", "required": true},
    {"name": "reason", "type": "String", "description": "Failure reason", "example": "wrong_password", "required": true},
    {"name": "email", "type": "String", "description": "Email used in attempt", "example": "user@example.com", "required": false}
  ],
  "code": {
    "python": "import requests\n\nSERVERNOTIFY_URL = \"https://omcard.net/v1/events\"\nSERVERNOTIFY_KEY = \"YOUR_APP_KEY\"\n\ndef track_login_failed(user_id, ip, reason=\"wrong_password\", email=None):\n    try:\n        requests.post(SERVERNOTIFY_URL, headers={\n            \"Authorization\": f\"Bearer {SERVERNOTIFY_KEY}\",\n            \"Content-Type\": \"application/json\"\n        }, json={\n            \"source\": \"auth-service\",\n            \"event\": \"login_failed\",\n            \"severity\": \"warning\",\n            \"meta\": {\"user_id\": user_id, \"ip\": ip, \"reason\": reason, \"email\": email}\n        }, timeout=5)\n    except Exception:\n        pass  # Never break your app because of monitoring"
  },
  "suggestions": ["login_success", "password_reset", "account_locked"]
}
```

Show a **loading spinner** while waiting for the AI response.

When completed, collapse to: "Event: login_failed — Failed login attempt"

---

#### Step 3: Review Generated Event

After the AI responds, display a **review card** showing:

- **Event name** (bold, monospace): `login_failed`
- **Display name**: Login Failed
- **Category badge**: Authentication
- **Severity badge**: warning (yellow)
- **Description**: Failed login attempt with incorrect password

**Parameters table:**
| Name | Type | Description | Example | Required |
|------|------|-------------|---------|----------|
| user_id | String | User identifier | usr_123 | Yes |
| ip | String | Client IP address | 192.168.1.1 | Yes |
| reason | String | Failure reason | wrong_password | Yes |
| email | String | Email used | user@example.com | No |

**Suggested related events** (from `suggestions` array):
Show as clickable chips. When clicked, auto-fill Step 2 with that event name and re-generate. (e.g. clicking "login_success" puts "user logged in successfully" in the description and triggers a new generate call)

A "Regenerate" button in case the user wants to modify the description and try again.

When completed (user clicks "Looks good" or "Next"), collapse to: "Event: login_failed (4 parameters)"

---

#### Step 4: Select Your Server & App Key

- Dropdown to select a server (from `GET /v1/servers`)
- Show existing app keys for that server: `GET /v1/servers/{server_id}/app-keys`
- If no keys exist, show "Create App Key" button
  - `POST /v1/servers/{server_id}/app-keys` body: `{"name": "my-key"}`
  - Show the `raw_key` ONCE with a copy button and warning: "Save this key — you won't see it again"
- User selects an existing key or creates a new one

**App Key list response:**
```json
[
  {
    "id": "uuid",
    "server_id": "uuid",
    "name": "auth-service-key",
    "prefix": "app_key_hQr...",
    "is_active": true,
    "created_at": "2026-01-01T00:00:00Z",
    "revoked_at": null
  }
]
```

**App Key create response:**
```json
{
  "ok": true,
  "id": "uuid",
  "name": "auth-service-key",
  "raw_key": "app_key_hQrTVbROtRvq3F8Y5hPrg_0j12okc0dNww8q3SL0rtc",
  "prefix": "app_key_hQr..."
}
```

When completed, collapse to: "Server: My VPS — Key: app_key_hQr..."

---

#### Step 5: Your Code — Ready to Copy

Show the final generated code block from the AI response's `code` field, but with `YOUR_APP_KEY` replaced with the actual app key the user selected/created in Step 4.

Display in a **code block with syntax highlighting** and a prominent **"Copy" button**.

Below the code, show:
- File name suggestion (e.g. "Save as `servernotify.py`")
- Usage example: "Then call `track_login_failed(user_id='123', ip='1.2.3.4')` wherever you handle failed logins"

If the user also wants to track the suggested events, show a **"Generate More Events"** button that scrolls back to Step 2 to add another event. Each generated event's code gets appended to the final code block so the user gets a single file with all their tracking functions.

---

#### Multiple Events Flow

The wizard supports generating multiple events into one file:
1. User completes Steps 1-3 for the first event
2. Clicks "Add Another Event" → Step 2 reappears (framework stays the same)
3. Generates a second event
4. Step 5 shows combined code with ALL tracking functions in one file
5. The combined file has: shared config (URL, key, headers) at the top, then one function per event

---

### Tab 3: Alert Rules

Manage event-based alert rules. A rule triggers an alert when an event occurs more than N times within a time window.

#### Rules List

Table with columns: Name, Event, Source, Severity Filter, Threshold, Window, Enabled, Actions (delete)

**API:** `GET /v1/event-alert-rules`

**Response:**
```json
[
  {
    "id": "uuid",
    "server_id": null,
    "name": "Too many login failures",
    "event": "login_failed",
    "source": null,
    "severity_filter": null,
    "threshold": 10,
    "window_seconds": 300,
    "is_enabled": true,
    "created_at": "2026-01-01T00:00:00Z"
  }
]
```

#### Create Rule Dialog

Form fields:
- **Name** (text input, required)
- **Event** (text input — user types the event name, e.g. "login_failed")
- **Server** (optional dropdown from `GET /v1/servers`, null = all servers)
- **Source** (optional text input)
- **Severity filter** (optional dropdown: info, warning, error)
- **Threshold** (number input, min 1, max 10000, default 10)
- **Window** (dropdown: 1 min = 60, 5 min = 300, 15 min = 900, 1 hour = 3600, 24 hours = 86400)

**API:** `POST /v1/event-alert-rules`
```json
{
  "name": "Too many login failures",
  "event": "login_failed",
  "server_id": null,
  "source": null,
  "severity_filter": null,
  "threshold": 10,
  "window_seconds": 300
}
```

#### Delete Rule

Confirmation dialog → `DELETE /v1/event-alert-rules/{rule_id}`

**Response:** `{"ok": true, "id": "uuid"}`

---

## Design

- **Dark mode** default (zinc/slate background, white text)
- **shadcn/ui** components: Tabs, Table, Badge, Button, Dialog, Sheet, Select, Input, Textarea, Popover, Card
- **Monospace font** for code snippets and JSON meta viewer
- **Severity badge colors:** info = blue/slate, warning = amber/yellow, error = red
- **Wizard step indicators:** numbered circles with connecting vertical line, green fill + checkmark when completed, blue fill when active, gray when pending
- **Framework cards:** 6 cards in a 3x2 grid with subtle language icons
- **AI loading state:** Skeleton shimmer + "Generating your event..." text while waiting for LLM response
- **Syntax highlighting** in generated code (use `prism-react-renderer` or highlight.js)
- **Toast notifications** (sonner) for: copied to clipboard, rule created, rule deleted, key created, key revoked, errors
- **Empty states**: "No events yet" with illustration, "No rules configured" with CTA
- **Loading states**: Skeleton loaders for tables and cards
- **Overall feel**: Like a Stripe/Vercel onboarding wizard — clean, modern, conversational

---

## Technical Stack

- **Next.js 14** App Router
- **TypeScript** strict
- **Tailwind CSS** + **shadcn/ui**
- **@supabase/ssr** for auth
- **sonner** for toasts
- **date-fns** for timestamps
- **prism-react-renderer** for code syntax highlighting
