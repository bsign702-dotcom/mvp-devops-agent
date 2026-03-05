# Bolt Prompt: App Events Feature

Copy everything below this line into Bolt:

---

Add a new feature called "App Events" to the existing dashboard. This feature lets users track custom application events (login_failed, payment_error, etc.) sent from their backends. Match the existing app design system exactly (same sidebar style, same table components, same colors, same modal patterns, same filter bar style).

## Sidebar

Add a new sidebar item called "App Events" with a Zap icon (or Activity icon from lucide-react). Place it after "Alerts" in the sidebar navigation. It should route to `/app-events`.

## API Endpoints (already built - just consume them)

Base URL comes from environment variable `VITE_API_URL`. All dashboard endpoints require `Authorization: Bearer <supabase_token>` header. Use the existing API client / auth context already in the app.

### App Events

```
GET /v1/app-events?server_id=<uuid>&source=<str>&event=<str>&severity=<str>&q=<str>&since=<iso>&until=<iso>&limit=100&offset=0

Response:
{
  "items": [
    {
      "id": 1,
      "server_id": "uuid",
      "source": "auth-service",
      "event": "login_failed",
      "severity": "warning",    // "info" | "warning" | "error"
      "meta": { "user_id": "123", "ip": "1.2.3.4", "reason": "wrong_password" },
      "ip": "203.0.113.5",
      "created_at": "2026-03-05T14:22:00Z"
    }
  ],
  "total": 542
}
```

### App Keys (per server)

```
POST /v1/servers/{server_id}/app-keys
Body: { "name": "auth-service-key" }
Response: { "id": "uuid", "server_id": "uuid", "name": "auth-service-key", "raw_key": "app_key_...", "created_at": "..." }

GET /v1/servers/{server_id}/app-keys
Response: [{ "id": "uuid", "server_id": "uuid", "name": "...", "created_at": "...", "revoked_at": null }]

DELETE /v1/app-keys/{key_id}
Response: { "ok": true, "id": "uuid", "revoked_at": "..." }
```

### Event Alert Rules

```
POST /v1/event-alert-rules
Body: { "server_id": "uuid|null", "name": "Too many login failures", "event": "login_failed", "source": null, "severity_filter": null, "threshold": 10, "window_seconds": 300 }
Response: { "id": "uuid", "server_id": null, "name": "...", "event": "...", "source": null, "severity_filter": null, "threshold": 10, "window_seconds": 300, "is_enabled": true, "created_at": "..." }

GET /v1/event-alert-rules
Response: [{ ... same shape as above }]

DELETE /v1/event-alert-rules/{rule_id}
Response: { "ok": true, "id": "uuid" }
```

### Servers list (already exists)

```
GET /v1/servers
Response: [{ "server_id": "uuid", "name": "prod-web-01", "status": "connected", "last_seen_at": "...", "created_at": "..." }]
```

---

## Page 1: App Events (`/app-events`)

This is the main page accessed from the sidebar.

### Filter Bar (top of page)
A horizontal filter bar with:
- **Server** dropdown (fetch from `GET /v1/servers`, show "All Servers" as default)
- **Source** text input with autocomplete/suggestions
- **Event** text input with autocomplete/suggestions
- **Severity** dropdown: All, Info, Warning, Error
- **Search** text input (searches event name, source, and meta JSON)
- **Time Range** selector: Last 1h, 6h, 24h, 7d, 30d, Custom range (date pickers)
- **Refresh** button

### Events Table
A data table showing events, sorted by most recent first. Columns:
| Time | Server | Source | Event | Severity | IP | Actions |
|------|--------|--------|-------|----------|-----|---------|

- **Time**: relative time (e.g., "2m ago") with full timestamp on hover tooltip
- **Server**: server name (fetched from servers list, cached)
- **Source**: text badge (muted color, e.g., gray pill)
- **Event**: text badge (e.g., `login_failed` in monospace)
- **Severity**: colored badge
  - `info` = blue/gray badge
  - `warning` = yellow/amber badge
  - `error` = red badge
- **IP**: the client IP that sent the event
- **Actions**: "View" button that opens detail modal

### Pagination
Show total count at top: "542 events". Pagination at bottom with page numbers. Default 100 per page.

### Event Detail Modal
When clicking "View" or clicking a table row, open a slide-over panel or modal showing:
- Event name (large)
- Severity badge
- Server name
- Source
- IP address
- Timestamp (full)
- **Meta JSON** displayed in a formatted, syntax-highlighted JSON viewer (use a `<pre>` block with proper formatting, or a JSON tree viewer component). This is the most important part - users need to read the meta easily.

### Empty State
If no events yet, show a friendly empty state with:
- Icon
- "No events yet"
- "Send your first event using the API. Check the Documentation page for code examples."
- Button: "View Documentation" (links to `/app-events/docs`)

---

## Page 2: App Events Documentation (`/app-events/docs`)

Accessible via a "Docs" tab/link at the top of the App Events page, or from the empty state.

### Content
A clean documentation page with copy-paste code examples for sending events. Include a tab selector for language:

**Tabs: curl | Node.js | Python | PHP**

#### curl
```bash
curl -X POST https://YOUR_API_URL/v1/events \
  -H "Authorization: Bearer YOUR_APP_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "source": "auth-service",
    "event": "login_failed",
    "severity": "warning",
    "meta": {
      "user_id": "123",
      "ip": "1.2.3.4",
      "reason": "wrong_password"
    }
  }'
```

#### Node.js
```javascript
const response = await fetch('https://YOUR_API_URL/v1/events', {
  method: 'POST',
  headers: {
    'Authorization': 'Bearer YOUR_APP_KEY',
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({
    source: 'auth-service',
    event: 'login_failed',
    severity: 'warning',
    meta: {
      user_id: '123',
      ip: '1.2.3.4',
      reason: 'wrong_password',
    },
  }),
});

const data = await response.json();
console.log(data); // { ok: true, event_id: 1 }
```

#### Python
```python
import requests

response = requests.post(
    "https://YOUR_API_URL/v1/events",
    headers={
        "Authorization": "Bearer YOUR_APP_KEY",
        "Content-Type": "application/json",
    },
    json={
        "source": "auth-service",
        "event": "login_failed",
        "severity": "warning",
        "meta": {
            "user_id": "123",
            "ip": "1.2.3.4",
            "reason": "wrong_password",
        },
    },
)

print(response.json())  # {"ok": True, "event_id": 1}
```

#### PHP
```php
$ch = curl_init('https://YOUR_API_URL/v1/events');
curl_setopt_array($ch, [
    CURLOPT_POST => true,
    CURLOPT_HTTPHEADER => [
        'Authorization: Bearer YOUR_APP_KEY',
        'Content-Type: application/json',
    ],
    CURLOPT_POSTFIELDS => json_encode([
        'source' => 'auth-service',
        'event' => 'login_failed',
        'severity' => 'warning',
        'meta' => [
            'user_id' => '123',
            'ip' => '1.2.3.4',
            'reason' => 'wrong_password',
        ],
    ]),
    CURLOPT_RETURNTRANSFER => true,
]);

$response = curl_exec($ch);
curl_close($ch);

echo $response; // {"ok":true,"event_id":1}
```

### Additional Docs Sections:
- **Severity Levels**: info (normal activity), warning (needs attention), error (action required)
- **Rate Limits**: Max 100 events per minute per app key
- **Meta Field**: Free-form JSON, max 16 KB. Use it for any context you want to attach to events.

Each code block should have a "Copy" button.

---

## Page 3: App Keys (inside Server Detail page)

Add a new tab or section called "App Integrations" inside the existing server detail page (`/servers/{server_id}`).

### App Keys Section
- Header: "App Keys" with a "Create Key" button on the right
- Table of existing keys:
  | Name | Created | Status | Actions |
  |------|---------|--------|---------|
  - **Status**: "Active" (green) or "Revoked" (red with revoked_at date)
  - **Actions**: "Revoke" button (with confirm dialog) for active keys

### Create Key Modal
When clicking "Create Key":
- Input: "Key Name" (e.g., "auth-service-key")
- Button: "Create"
- After creation, show a **one-time display** of the raw key:
  - Warning banner: "Copy this key now. You won't be able to see it again."
  - The key displayed in a monospace box with a "Copy to Clipboard" button
  - "Done" button to close

### Revoke Key Confirmation
- Destructive confirmation dialog: "Are you sure you want to revoke this key? Any services using this key will immediately lose access."
- "Cancel" and "Revoke Key" (red) buttons

---

## Page 4: Event Alert Rules (`/app-events/rules`)

Accessible via a "Alert Rules" tab at the top of the App Events page.

### Rules List
A card-based or table view of alert rules:
| Name | Event | Source | Severity | Threshold | Window | Status | Actions |
|------|-------|--------|----------|-----------|--------|--------|---------|

- **Threshold**: e.g., "10 events"
- **Window**: e.g., "5 minutes" (convert seconds to human readable)
- **Status**: "Enabled" green badge
- **Actions**: Delete button with confirmation

### Create Rule Button
Opens a form/modal:
- **Name**: text input (e.g., "Too many login failures")
- **Event**: text input (e.g., "login_failed") — required
- **Server**: dropdown, optional (null = all servers)
- **Source**: text input, optional (null = all sources)
- **Severity Filter**: dropdown optional (null = all severities)
- **Threshold**: number input, default 10
- **Window**: select or number input in minutes (convert to seconds for API). Options: 1m, 5m, 15m, 30m, 1h, custom
- Description text below form: "An alert will trigger when {threshold} or more '{event}' events occur within {window}."
- Create button

### Empty State
- "No alert rules configured"
- "Create rules to get notified when specific events exceed a threshold."
- "Create Rule" button

---

## Design Requirements

- Use the EXACT same design system as the rest of the app (colors, fonts, spacing, border-radius, shadows)
- Same sidebar active state styling
- Same table component with hover rows, same header style
- Same modal/dialog component
- Same button styles (primary, secondary, destructive)
- Same badge/pill components for status indicators
- Same filter bar pattern used elsewhere in the app
- Severity colors:
  - info: blue-ish or gray (matches existing "low" severity)
  - warning: amber/yellow (matches existing "medium" severity)
  - error: red (matches existing "high"/"critical" severity)
- Dark mode support if the app already has it
- Responsive: table should scroll horizontally on mobile
- Loading skeletons while data fetches
- Toast notifications for success/error actions (create key, revoke key, create rule, etc.)

## Navigation Structure

The App Events top area should have tabs or a secondary nav:
- **Events** (default, `/app-events`) — the main table
- **Alert Rules** (`/app-events/rules`) — manage threshold rules
- **Documentation** (`/app-events/docs`) — API examples

---

## Summary of Routes to Create

| Route | Page |
|-------|------|
| `/app-events` | Events list with filters + table |
| `/app-events/rules` | Event alert rules management |
| `/app-events/docs` | API documentation with code examples |
| `/servers/{id}` | Add "App Integrations" tab with app keys management |
