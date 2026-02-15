# ClawGuard Event Schema Reference

## Event Record (from `/api/events`)

Each event returned by the API contains these fields:

| Field | Type | Description |
|---|---|---|
| `id` | integer | Auto-increment row ID |
| `event_id` | string | Unique UUID for this event |
| `provider` | string | Email provider (e.g. `"generic"`, `"gmail"`) |
| `received_at` | string | ISO 8601 timestamp |
| `from_addr` | string | Sender email address |
| `subject_sanitized` | string | Sanitized subject line |
| `body_sanitized` | string | Sanitized body text (HTML stripped, secrets redacted) |
| `risk_flags` | string | JSON array of risk flag strings |
| `injection_detected` | integer | `1` if prompt injection was detected, `0` otherwise |
| `truncated` | integer | `1` if content was truncated, `0` otherwise |
| `risk_score` | integer | Composite risk score from 0 to 100 |
| `raw_payload_masked` | string or null | Masked version of raw payload (do not expose to user) |
| `sanitized_json` | string | Full `SanitizedEmailEvent` serialized as JSON |
| `created_at` | string | ISO 8601 timestamp when record was created |

## Stats Response (from `/api/stats`)

```json
{
  "total_processed": 42,
  "risky_count": 5,
  "injection_count": 2,
  "attachments_blocked": 3,
  "avg_risk_score": 12.5,
  "events_today": 8
}
```

## Timeline Response (from `/api/timeline?days=7`)

Returns an array of daily aggregates:

```json
[
  {
    "day": "2026-02-15",
    "total": 10,
    "injections": 1,
    "risky": 3
  }
]
```

## SanitizedEmailEvent (full JSON in `sanitized_json` field)

```json
{
  "event_id": "uuid-string",
  "provider": "generic",
  "received_at": "2026-02-15T10:00:00Z",
  "from_addr": "sender@example.com",
  "to_addrs": ["recipient@example.com"],
  "subject_sanitized": "Meeting tomorrow",
  "body_sanitized": "Hi, let's meet at 3pm.",
  "attachments_sanitized": [
    {
      "filename": "report.pdf",
      "content_type": "application/pdf",
      "size_bytes": 12345,
      "allowed": true,
      "extracted_text": null,
      "blocked_reason": null
    }
  ],
  "risk": {
    "flags": [],
    "injection_detected": false,
    "truncated": false,
    "risk_score": 0,
    "injection_patterns_found": []
  },
  "meta": {
    "original_sizes": {
      "subject": 18,
      "body": 25,
      "attachments_count": 1,
      "total_attachment_bytes": 12345
    },
    "sanitizer_version": "v1",
    "processing_time_ms": 2.5,
    "html_stripped": false,
    "unicode_cleaned": false,
    "secrets_redacted": 0
  }
}
```

## Risk Score Weights

| Flag | Weight |
|---|---|
| `injection_detected` | 40 |
| `script_detected` | 30 |
| `hidden_content` | 25 |
| `secret_detected` | 20 |
| `attachment_blocked` | 15 |
| `html_detected` | 10 |
| `unicode_suspicious` | 10 |
| `oversized` | 5 |

Additional injection patterns beyond the first add +10 each. Score is capped at 100.
