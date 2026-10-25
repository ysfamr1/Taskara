#!/usr/bin/env python3
"""
Tazkara — a free, single-file Discord ticket bot.

=============================================================================
 SECURITY WARNING
 ----------------
 A copy of this file that contains a REAL bot token must NEVER be committed to
 a public repository, pasted in chat, or shared with anyone. Anyone holding the
 token fully controls the bot. If it leaks: Developer Portal -> Bot -> Reset Token.
=============================================================================

Usage
-----
    python main.py --init-key            # create the archive encryption key (once)
    python main.py                       # run the bot
    python main.py --decrypt FILE OUT    # decrypt a local archive for recovery
    pytest main.py -q                    # run the built-in test-suite

Layout (single file, top to bottom)
-----------------------------------
 1. Settings & constants             7. Vault (encryption) + transcript builder
 2. Logging with secret redaction    8. Gateway protocol (abstract Discord I/O)
 3. Pure helpers & validation        9. Services (tickets, archive, automation,
 4. Schema + Database layer             retention, reconciliation, scheduler)
 5. State machine + permissions     10. Discord layer (gateway impl, views, /setup)
 6. Timer logic (pure)              11. Entry point          12. pytest tests

Services never talk to discord.py directly; they use the ``Gateway`` protocol,
which lets the test-suite inject failures without a real Discord connection.
"""
from __future__ import annotations

import argparse
import base64
import asyncio
import contextlib
import dataclasses
import hashlib
import html
import io
import json
import logging
import logging.handlers
import math
import os
import re
import sqlite3
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable, Iterable, Iterator, Optional, Protocol, Sequence, Union

import aiohttp
import discord
from discord import app_commands
from cryptography.fernet import Fernet, InvalidToken

# =============================================================================
# 1. SETTINGS & CONSTANTS
# =============================================================================

# Replace with your real token ONLY on your own machine. Never commit/share it.
BOT_TOKEN = "placeholder"

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "data.db"
ARCHIVE_DIR = BASE_DIR / "archives"
LOG_FILE = BASE_DIR / "tazkara.log"
#: Optional OS environment variable that overrides the key-file location.
#: (This is a normal OS variable, not a .env file.)
KEY_FILE_ENV = "TAZKARA_ARCHIVE_KEY_FILE"

#: Privileged intent; only needed for *instant* "owner left" detection.
#: The feature also works without it (periodic fetch_member check).
ENABLE_MEMBERS_INTENT = False
#: Sync slash commands on every start (set False after the first run if you like).
SYNC_COMMANDS_ON_START = True
#: Put a test server id here to sync commands instantly to that server only.
DEV_GUILD_ID: Optional[int] = None

LOCAL_RETENTION_DAYS = 30
EVENT_RETENTION_DAYS = 180
JOB_RETENTION_DAYS = 30

SCHEDULER_TICK_SECONDS = 5
SCHEDULER_BATCH = 10
SCHEDULER_CONCURRENCY = 3
JOB_TIMEOUT_SECONDS = 300
CREATION_RECONCILE_DELAY = 60
CREATION_GRACE_SECONDS = 120
OWNER_PRESENCE_INTERVAL = 600
RETENTION_SWEEP_INTERVAL = 6 * 3600
RETRY_BASE_SECONDS = 30
RETRY_MAX_SECONDS = 3600

MAX_ATTACHMENT_BYTES = 8 * 1024 * 1024
MAX_TOTAL_ATTACHMENT_BYTES = 20 * 1024 * 1024
UPLOAD_SAFETY_MARGIN = 256 * 1024
MAX_TRANSCRIPT_MESSAGES = 20_000
WIZARD_TIMEOUT = 900
EMBED_COLOR = 0x2B8A3E

#: Minimal bot permissions (no Administrator).
REQUIRED_CATEGORY_PERMS = (
    "view_channel", "send_messages", "embed_links", "attach_files",
    "read_message_history", "manage_channels", "manage_roles",
)
#: Fallback when Discord refuses new channels (long rate limit, category of 50 full, server of 500 full):
#: the ticket opens as a PRIVATE THREAD inside the panel channel (free for all servers). Staff join it
#: with a button posted in the log channel. Set to False to keep channels only.
THREAD_FALLBACK_ENABLED = True
THREAD_FALLBACK_PERMS = ("create_private_threads", "send_messages_in_threads", "manage_threads")
CATEGORY_CHANNEL_LIMIT = 50
REQUIRED_PANEL_CHANNEL_PERMS = ("view_channel", "send_messages", "embed_links", "read_message_history")
REQUIRED_LOG_CHANNEL_PERMS = ("view_channel", "send_messages", "embed_links", "attach_files", "read_message_history")


def default_key_path() -> Path:
    """Return the default key path — deliberately OUTSIDE the project/archive folders."""
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA") or (Path.home() / "AppData" / "Local"))
        return base / "Tazkara" / "keys" / "archive.key"
    return Path.home() / ".config" / "tazkara" / "archive.key"


def configured_key_path() -> Path:
    """Key path from the optional OS environment variable, else the default."""
    env = os.environ.get(KEY_FILE_ENV)
    return Path(env).expanduser().resolve() if env else default_key_path()


def bot_permissions_value() -> int:
    """Integer for the OAuth2 invite URL built from the minimal permission set."""
    perms = discord.Permissions.none()
    for name in (set(REQUIRED_CATEGORY_PERMS) | set(REQUIRED_LOG_CHANNEL_PERMS) | set(REQUIRED_PANEL_CHANNEL_PERMS)
                 | set(THREAD_FALLBACK_PERMS)):
        setattr(perms, name, True)
    return perms.value


# =============================================================================
# 2. LOGGING WITH SECRET REDACTION
# =============================================================================

_TOKEN_RE = re.compile(r"[A-Za-z\d_-]{23,28}\.[A-Za-z\d_-]{6,7}\.[A-Za-z\d_-]{27,}")


class RedactingFilter(logging.Filter):
    """Removes registered secrets and anything shaped like a Discord token."""

    def __init__(self) -> None:
        super().__init__()
        self._secrets: set[str] = set()

    def add_secret(self, secret: Optional[str]) -> None:
        if secret and len(secret) >= 8 and secret != "placeholder":
            self._secrets.add(secret)

    def redact(self, text: str) -> str:
        for secret in self._secrets:
            text = text.replace(secret, "[REDACTED]")
        return _TOKEN_RE.sub("[REDACTED_TOKEN]", text)

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except (TypeError, ValueError):
            message = str(record.msg)
        redacted = self.redact(message)
        if redacted != message:
            record.msg, record.args = redacted, None
        if record.exc_info:
            record.exc_text = self.redact(logging.Formatter().formatException(record.exc_info))
            record.exc_info = None
        return True


REDACTOR = RedactingFilter()
log = logging.getLogger("tazkara")


def setup_logging(level: int = logging.INFO, to_file: bool = True) -> None:
    """Configure structured key=value logging with redaction on every handler."""
    root = logging.getLogger()
    root.setLevel(level)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if to_file:
        handlers.append(logging.handlers.RotatingFileHandler(
            LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8"))
    for handler in handlers:
        handler.setFormatter(fmt)
        handler.addFilter(REDACTOR)
        root.addHandler(handler)
    logging.getLogger("discord.http").setLevel(logging.WARNING)
    logging.getLogger("discord.gateway").setLevel(logging.WARNING)


# =============================================================================
# 3. PURE HELPERS & VALIDATION
# =============================================================================

Clock = Callable[[], int]


def now_ts() -> int:
    return int(time.time())


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def clean_text(value: Optional[str], *, multiline: bool = False) -> str:
    """Strip control characters (keep newlines only when multiline)."""
    text = _CONTROL_CHARS.sub("", value or "")
    if not multiline:
        text = text.replace("\r", " ").replace("\n", " ")
    return text.strip()


TEMPLATE_PLACEHOLDERS = frozenset({"number", "user", "panel"})
_PLACEHOLDER_RE = re.compile(r"\{([^{}]*)\}")


def validate_name_template(template: str) -> Optional[str]:
    """Validate a channel-name template. Returns an error message or None.

    Only ``{number}``, ``{user}``, ``{panel}`` are allowed. ``str.format`` is never
    used with user data, so attribute-access tricks like ``{0.__class__}`` are rejected.
    """
    template = template.strip()
    if not 1 <= len(template) <= 60:
        return "قالب اسم القناة يجب أن يكون بين 1 و 60 حرفًا."
    names = _PLACEHOLDER_RE.findall(template)
    unknown = [n for n in names if n not in TEMPLATE_PLACEHOLDERS]
    if unknown:
        return "متغيرات غير مسموحة في القالب: " + ", ".join(sorted(set(unknown)))[:200]
    if "{" in _PLACEHOLDER_RE.sub("", template) or "}" in _PLACEHOLDER_RE.sub("", template):
        return "أقواس غير متوازنة في قالب اسم القناة."
    if "number" not in names:
        return "قالب اسم القناة يجب أن يحتوي {number}."
    return None


def slugify(value: str, max_len: int = 32) -> str:
    """Lower-case, keep unicode letters/digits/-/_ only, collapse dashes."""
    out = []
    for ch in value.lower():
        out.append(ch if (ch.isalnum() or ch in "-_") else "-")
    slug = re.sub(r"-{2,}", "-", "".join(out)).strip("-_")
    return slug[:max_len].strip("-_")


def render_channel_name(template: str, number: int, user_name: str, panel_name: str) -> str:
    """Render a validated template by plain replacement (never ``str.format``)."""
    rendered = (template.replace("{number}", f"{number:04d}")
                .replace("{user}", slugify(user_name) or "user")
                .replace("{panel}", slugify(panel_name) or "panel"))
    return slugify(rendered, 100) or f"ticket-{number:04d}"


def parse_int_field(raw: str, label: str, lo: int, hi: int, *, allow_zero: bool = False) -> tuple[Optional[int], Optional[str]]:
    """Parse a bounded integer from a modal text field."""
    raw = (raw or "").strip()
    if not re.fullmatch(r"\d{1,7}", raw):
        return None, f"{label}: أدخل رقمًا صحيحًا."
    value = int(raw)
    if allow_zero and value == 0:
        return 0, None
    if not lo <= value <= hi:
        extra = " (أو 0 للتعطيل)" if allow_zero else ""
        return None, f"{label}: يجب أن يكون بين {lo} و {hi}{extra}."
    return value, None


@dataclass
class PanelDraft:
    """In-memory wizard state. Persisted only after full validation."""
    guild_id: int
    panel_id: Optional[int] = None
    name: str = ""
    embed_title: str = ""
    embed_description: str = ""
    button_label: str = "فتح تيكت"
    channel_name_template: str = "ticket-{number}"
    admin_role_ids: list[int] = field(default_factory=list)
    staff_role_ids: list[int] = field(default_factory=list)
    category_id: Optional[int] = None
    panel_channel_id: Optional[int] = None
    log_channel_id: Optional[int] = None
    max_open_tickets: int = 25
    inactivity_enabled: bool = False
    inactivity_timeout_min: int = 1440
    inactivity_warning_min: int = 60
    sla_enabled: bool = False
    sla_first_response_min: int = 60
    escalation_role_id: Optional[int] = None
    escalation_after_min: int = 0
    close_on_owner_leave: bool = False


def validate_draft_text(d: PanelDraft) -> list[str]:
    """Validate the free-text part of a draft (wizard step 1)."""
    errors: list[str] = []
    if not 1 <= len(d.name) <= 50:
        errors.append("اسم البانل يجب أن يكون بين 1 و 50 حرفًا.")
    if not 1 <= len(d.embed_title) <= 256:
        errors.append("عنوان الـ Embed يجب أن يكون بين 1 و 256 حرفًا.")
    if not 1 <= len(d.embed_description) <= 2000:
        errors.append("وصف الـ Embed يجب أن يكون بين 1 و 2000 حرف.")
    if not 1 <= len(d.button_label) <= 80:
        errors.append("نص الزر يجب أن يكون بين 1 و 80 حرفًا.")
    template_error = validate_name_template(d.channel_name_template)
    if template_error:
        errors.append(template_error)
    return errors


def validate_draft_fields(d: PanelDraft) -> list[str]:
    """Validate every Discord-independent field of a draft."""
    errors = validate_draft_text(d)
    if not d.staff_role_ids:
        errors.append("اختر رول ستاف واحدة على الأقل.")
    if len(set(d.staff_role_ids) | set(d.admin_role_ids)) > 20:
        errors.append("الحد الأقصى 20 رولًا.")
    for label, value in (("الكاتيجوري", d.category_id), ("قناة النشر", d.panel_channel_id), ("قناة اللوج", d.log_channel_id)):
        if not value:
            errors.append(f"لم يتم اختيار {label}.")
    if not 1 <= d.max_open_tickets <= 50:  # a Discord category holds at most 50 channels
        errors.append("حد التيكتات المفتوحة يجب أن يكون بين 1 و 50 (حد Discord للكاتيجوري).")
    if d.inactivity_enabled:
        if not 10 <= d.inactivity_timeout_min <= 43200:
            errors.append("مهلة الخمول يجب أن تكون بين 10 و 43200 دقيقة.")
        if not 1 <= d.inactivity_warning_min < d.inactivity_timeout_min:
            errors.append("مدة التحذير يجب أن تكون أقل من مهلة الخمول.")
    if d.sla_enabled and not 5 <= d.sla_first_response_min <= 10080:
        errors.append("مهلة أول رد يجب أن تكون بين 5 و 10080 دقيقة.")
    if not 0 <= d.escalation_after_min <= 10080:
        errors.append("مهلة التصعيد يجب أن تكون بين 0 و 10080 دقيقة.")
    if d.escalation_role_id and not d.sla_enabled:
        errors.append("التصعيد يتطلب تفعيل SLA.")
    return errors


# =============================================================================
# 4. SCHEMA + DATABASE LAYER
# =============================================================================

SCHEMA_VERSION = 1

S_CREATING, S_OPEN, S_ON_HOLD, S_CLOSING, S_CLOSED, S_FAILED, S_LOST = (
    "CREATING", "OPEN", "ON_HOLD", "CLOSING", "CLOSED", "FAILED", "LOST")
ALL_STATES = (S_CREATING, S_OPEN, S_ON_HOLD, S_CLOSING, S_CLOSED, S_FAILED, S_LOST)
#: States covered by the one-active-ticket unique index.
ACTIVE_STATES = (S_CREATING, S_OPEN, S_ON_HOLD)
#: Allowed transitions — enforced in Python AND by a SQLite trigger.
TRANSITIONS: frozenset[tuple[str, str]] = frozenset({
    (S_CREATING, S_OPEN), (S_CREATING, S_FAILED), (S_CREATING, S_LOST),
    (S_OPEN, S_ON_HOLD), (S_ON_HOLD, S_OPEN),
    (S_OPEN, S_CLOSING), (S_ON_HOLD, S_CLOSING),
    (S_CLOSING, S_OPEN), (S_CLOSING, S_CLOSED),
    (S_OPEN, S_LOST), (S_ON_HOLD, S_LOST), (S_CLOSING, S_LOST),
})

STATE_LABELS = {
    S_CREATING: "⏳ قيد الإنشاء", S_OPEN: "🟢 مفتوح", S_ON_HOLD: "⏸️ معلّق (Hold)",
    S_CLOSING: "🟠 قيد الإغلاق والأرشفة", S_CLOSED: "🔒 مغلق", S_FAILED: "❌ فشل الإنشاء", S_LOST: "⚠️ القناة مفقودة",
}

_STATE_LIST_SQL = ",".join(f"'{s}'" for s in ALL_STATES)  # constants only, never user input
_ACTIVE_LIST_SQL = ",".join(f"'{s}'" for s in ACTIVE_STATES)

SCHEMA_SQL = f"""
CREATE TABLE IF NOT EXISTS schema_meta(
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- One row per guild; holds the per-guild ticket number counter.
CREATE TABLE IF NOT EXISTS guild_settings(
    guild_id            INTEGER PRIMARY KEY CHECK (guild_id > 0),
    next_ticket_number  INTEGER NOT NULL DEFAULT 1 CHECK (next_ticket_number >= 1),
    created_at          INTEGER NOT NULL,
    updated_at          INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS panels(
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    guild_id                INTEGER NOT NULL REFERENCES guild_settings(guild_id) ON DELETE RESTRICT,
    name                    TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 50),
    embed_title             TEXT NOT NULL CHECK (length(embed_title) BETWEEN 1 AND 256),
    embed_description       TEXT NOT NULL CHECK (length(embed_description) BETWEEN 1 AND 2000),
    button_label            TEXT NOT NULL CHECK (length(button_label) BETWEEN 1 AND 80),
    category_id             INTEGER NOT NULL CHECK (category_id > 0),
    panel_channel_id        INTEGER NOT NULL CHECK (panel_channel_id > 0),
    log_channel_id          INTEGER NOT NULL CHECK (log_channel_id > 0),
    panel_message_id        INTEGER,
    channel_name_template   TEXT NOT NULL CHECK (length(channel_name_template) BETWEEN 1 AND 60),
    max_open_tickets        INTEGER NOT NULL CHECK (max_open_tickets BETWEEN 1 AND 50),
    status                  TEXT NOT NULL DEFAULT 'ACTIVE'
                            CHECK (status IN ('ACTIVE','PAUSED','MISCONFIGURED','ARCHIVED','DELETED')),
    inactivity_enabled      INTEGER NOT NULL DEFAULT 0 CHECK (inactivity_enabled IN (0,1)),
    inactivity_timeout_min  INTEGER NOT NULL DEFAULT 1440 CHECK (inactivity_timeout_min BETWEEN 10 AND 43200),
    inactivity_warning_min  INTEGER NOT NULL DEFAULT 60 CHECK (inactivity_warning_min >= 1),
    sla_enabled             INTEGER NOT NULL DEFAULT 0 CHECK (sla_enabled IN (0,1)),
    sla_first_response_min  INTEGER NOT NULL DEFAULT 60 CHECK (sla_first_response_min BETWEEN 5 AND 10080),
    escalation_role_id      INTEGER,
    escalation_after_min    INTEGER NOT NULL DEFAULT 0 CHECK (escalation_after_min BETWEEN 0 AND 10080),
    close_on_owner_leave    INTEGER NOT NULL DEFAULT 0 CHECK (close_on_owner_leave IN (0,1)),
    created_by              INTEGER NOT NULL,
    created_at              INTEGER NOT NULL,
    updated_at              INTEGER NOT NULL,
    CHECK (inactivity_warning_min < inactivity_timeout_min)
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_panels_name ON panels(guild_id, name) WHERE status <> 'DELETED';

CREATE TABLE IF NOT EXISTS panel_roles(
    panel_id  INTEGER NOT NULL REFERENCES panels(id) ON DELETE CASCADE,
    role_id   INTEGER NOT NULL CHECK (role_id > 0),
    kind      TEXT NOT NULL CHECK (kind IN ('admin','staff')),
    PRIMARY KEY (panel_id, role_id, kind)
);

-- Allowed state transitions; read by the trigger below.
CREATE TABLE IF NOT EXISTS ticket_transitions(
    from_state TEXT NOT NULL,
    to_state   TEXT NOT NULL,
    PRIMARY KEY (from_state, to_state)
);

CREATE TABLE IF NOT EXISTS tickets(
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    guild_id              INTEGER NOT NULL REFERENCES guild_settings(guild_id) ON DELETE RESTRICT,
    panel_id              INTEGER NOT NULL REFERENCES panels(id) ON DELETE RESTRICT,
    number                INTEGER NOT NULL CHECK (number >= 1),
    owner_id              INTEGER NOT NULL CHECK (owner_id > 0),
    channel_id            INTEGER UNIQUE,
    control_message_id    INTEGER,
    state                 TEXT NOT NULL CHECK (state IN ({_STATE_LIST_SQL})),
    version               INTEGER NOT NULL DEFAULT 0,
    create_op_key         TEXT NOT NULL UNIQUE,
    creation_uncertain    INTEGER NOT NULL DEFAULT 0 CHECK (creation_uncertain IN (0,1)),
    claimed_by            INTEGER,
    claimed_at            INTEGER,
    created_at            INTEGER NOT NULL,
    opened_at             INTEGER,
    close_seq             INTEGER NOT NULL DEFAULT 0 CHECK (close_seq >= 0),
    closed_by             INTEGER,
    close_reason          TEXT CHECK (close_reason IS NULL OR length(close_reason) <= 200),
    close_requested_at    INTEGER,
    closed_at             INTEGER,
    first_response_at     INTEGER,
    inactivity_deadline   INTEGER,
    inactivity_remaining  INTEGER CHECK (inactivity_remaining IS NULL OR inactivity_remaining >= 0),
    inactivity_warned     INTEGER NOT NULL DEFAULT 0 CHECK (inactivity_warned IN (0,1)),
    sla_deadline          INTEGER,
    sla_remaining         INTEGER CHECK (sla_remaining IS NULL OR sla_remaining >= 0),
    sla_breached_at       INTEGER,
    escalation_deadline   INTEGER,
    escalation_remaining  INTEGER CHECK (escalation_remaining IS NULL OR escalation_remaining >= 0),
    escalated_at          INTEGER,
    hold_started_at       INTEGER,
    total_hold_seconds    INTEGER NOT NULL DEFAULT 0 CHECK (total_hold_seconds >= 0),
    channel_deleted       INTEGER NOT NULL DEFAULT 0 CHECK (channel_deleted IN (0,1)),
    updated_at            INTEGER NOT NULL,
    UNIQUE (guild_id, number),
    CHECK (state NOT IN ('OPEN','ON_HOLD','CLOSING','CLOSED') OR channel_id IS NOT NULL),
    CHECK (state <> 'ON_HOLD' OR hold_started_at IS NOT NULL)
);
-- THE duplicate guard: at most one active ticket per (guild, panel, owner).
CREATE UNIQUE INDEX IF NOT EXISTS ux_tickets_one_active
    ON tickets(guild_id, panel_id, owner_id) WHERE state IN ({_ACTIVE_LIST_SQL});
CREATE INDEX IF NOT EXISTS ix_tickets_state ON tickets(state);
CREATE INDEX IF NOT EXISTS ix_tickets_panel_state ON tickets(panel_id, state);

CREATE TRIGGER IF NOT EXISTS trg_tickets_initial_state BEFORE INSERT ON tickets
WHEN NEW.state <> 'CREATING'
BEGIN SELECT RAISE(ABORT, 'tazkara:invalid_initial_state'); END;

CREATE TRIGGER IF NOT EXISTS trg_tickets_transition BEFORE UPDATE OF state ON tickets
WHEN OLD.state <> NEW.state AND NOT EXISTS (
    SELECT 1 FROM ticket_transitions WHERE from_state = OLD.state AND to_state = NEW.state)
BEGIN SELECT RAISE(ABORT, 'tazkara:invalid_transition'); END;

CREATE TRIGGER IF NOT EXISTS trg_tickets_limit_insert BEFORE INSERT ON tickets
WHEN (SELECT COUNT(*) FROM tickets WHERE panel_id = NEW.panel_id AND state IN ({_ACTIVE_LIST_SQL}))
     >= (SELECT max_open_tickets FROM panels WHERE id = NEW.panel_id)
BEGIN SELECT RAISE(ABORT, 'tazkara:panel_limit'); END;

CREATE TRIGGER IF NOT EXISTS trg_tickets_limit_reopen BEFORE UPDATE OF state ON tickets
WHEN OLD.state = 'CLOSING' AND NEW.state = 'OPEN'
     AND (SELECT COUNT(*) FROM tickets WHERE panel_id = NEW.panel_id AND state IN ({_ACTIVE_LIST_SQL}))
         >= (SELECT max_open_tickets FROM panels WHERE id = NEW.panel_id)
BEGIN SELECT RAISE(ABORT, 'tazkara:panel_limit'); END;

-- Audit trail. Never contains message content.
CREATE TABLE IF NOT EXISTS ticket_events(
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    guild_id    INTEGER NOT NULL,
    ticket_id   INTEGER REFERENCES tickets(id) ON DELETE CASCADE,
    panel_id    INTEGER REFERENCES panels(id) ON DELETE CASCADE,
    actor_id    INTEGER NOT NULL DEFAULT 0,
    event_type  TEXT NOT NULL CHECK (length(event_type) BETWEEN 1 AND 64),
    from_state  TEXT,
    to_state    TEXT,
    details     TEXT NOT NULL DEFAULT '{{}}' CHECK (json_valid(details)),
    created_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_events_ticket ON ticket_events(ticket_id);
CREATE INDEX IF NOT EXISTS ix_events_created ON ticket_events(created_at);

CREATE TABLE IF NOT EXISTS archives(
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id            INTEGER NOT NULL REFERENCES tickets(id) ON DELETE RESTRICT,
    close_seq            INTEGER NOT NULL,
    attempt              INTEGER NOT NULL CHECK (attempt >= 1),
    status               TEXT NOT NULL DEFAULT 'BUILDING'
                         CHECK (status IN ('BUILDING','PENDING_COPIES','BLOCKED','COMPLETE','SUPERSEDED')),
    transcript_sha256    TEXT CHECK (transcript_sha256 IS NULL OR length(transcript_sha256) = 64),
    transcript_size      INTEGER,
    message_count        INTEGER,
    last_message_id      INTEGER,
    transcript_complete  INTEGER NOT NULL DEFAULT 0 CHECK (transcript_complete IN (0,1)),
    incomplete_reason    TEXT,
    omissions_ack_by     INTEGER,
    log_status           TEXT NOT NULL DEFAULT 'PENDING' CHECK (log_status IN ('PENDING','SENDING','VERIFIED','FAILED')),
    log_channel_id       INTEGER,
    log_message_id       INTEGER,
    log_attempts         INTEGER NOT NULL DEFAULT 0,
    log_error            TEXT,
    log_verified_at      INTEGER,
    local_status         TEXT NOT NULL DEFAULT 'PENDING'
                         CHECK (local_status IN ('PENDING','VERIFIED','FAILED','EXPIRED','RETENTION_HOLD')),
    local_path           TEXT,
    local_cipher_sha256  TEXT CHECK (local_cipher_sha256 IS NULL OR length(local_cipher_sha256) = 64),
    local_attempts       INTEGER NOT NULL DEFAULT 0,
    local_error          TEXT,
    local_verified_at    INTEGER,
    expires_at           INTEGER,
    local_deleted_at     INTEGER,
    created_at           INTEGER NOT NULL,
    completed_at         INTEGER,
    UNIQUE (ticket_id, close_seq, attempt),
    CHECK (status <> 'COMPLETE' OR (log_status = 'VERIFIED' AND local_status IN ('VERIFIED','EXPIRED','RETENTION_HOLD')
                                    AND transcript_complete = 1 AND transcript_sha256 IS NOT NULL))
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_archives_live ON archives(ticket_id)
    WHERE status IN ('BUILDING','PENDING_COPIES','BLOCKED');

CREATE TABLE IF NOT EXISTS scheduled_jobs(
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    kind          TEXT NOT NULL CHECK (kind IN ('archive','delete_channel','dm_owner','inactivity','sla',
                                               'escalation','reconcile_ticket','owner_presence','retention_sweep')),
    dedupe_key    TEXT NOT NULL UNIQUE,
    guild_id      INTEGER,
    ticket_id     INTEGER REFERENCES tickets(id) ON DELETE CASCADE,
    run_at        INTEGER NOT NULL,
    status        TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING','RUNNING','DONE','FAILED','CANCELLED')),
    lease_token   TEXT,
    attempts      INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    max_attempts  INTEGER NOT NULL DEFAULT 10 CHECK (max_attempts >= 1),
    payload       TEXT NOT NULL DEFAULT '{{}}' CHECK (json_valid(payload)),
    last_error    TEXT,
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_jobs_due ON scheduled_jobs(status, run_at);

-- Outbox-style record of external (Discord) side effects to reduce duplicates.
CREATE TABLE IF NOT EXISTS external_ops(
    op_key       TEXT PRIMARY KEY,
    kind         TEXT NOT NULL,
    ticket_id    INTEGER REFERENCES tickets(id) ON DELETE CASCADE,
    status       TEXT NOT NULL CHECK (status IN ('STARTED','SUCCEEDED','FAILED','UNCERTAIN')),
    external_id  INTEGER,
    attempts     INTEGER NOT NULL DEFAULT 0,
    last_error   TEXT,
    created_at   INTEGER NOT NULL,
    updated_at   INTEGER NOT NULL
);
"""


class DuplicateActiveTicket(Exception):
    """The owner already has an active ticket in this panel (unique index hit)."""


class PanelLimitReached(Exception):
    """The panel's max_open_tickets limit was hit (trigger)."""


class InvalidTransition(Exception):
    """A state transition not present in TRANSITIONS was attempted."""


class _Rollback(Exception):
    """Internal: abort the current transaction without it being an error."""


def _from_row(cls: type, row: Optional[sqlite3.Row]) -> Any:
    if row is None:
        return None
    names = {f.name for f in dataclasses.fields(cls)}
    return cls(**{k: row[k] for k in row.keys() if k in names})


@dataclass
class Panel:
    id: int
    guild_id: int
    name: str
    embed_title: str
    embed_description: str
    button_label: str
    category_id: int
    panel_channel_id: int
    log_channel_id: int
    panel_message_id: Optional[int]
    channel_name_template: str
    max_open_tickets: int
    status: str
    inactivity_enabled: int
    inactivity_timeout_min: int
    inactivity_warning_min: int
    sla_enabled: int
    sla_first_response_min: int
    escalation_role_id: Optional[int]
    escalation_after_min: int
    close_on_owner_leave: int
    created_by: int
    created_at: int
    updated_at: int


@dataclass(frozen=True)
class PanelRoles:
    admin: frozenset[int]
    staff: frozenset[int]

    @property
    def all(self) -> frozenset[int]:
        return self.admin | self.staff


@dataclass
class Ticket:
    id: int
    guild_id: int
    panel_id: int
    number: int
    owner_id: int
    channel_id: Optional[int]
    control_message_id: Optional[int]
    state: str
    version: int
    create_op_key: str
    creation_uncertain: int
    claimed_by: Optional[int]
    claimed_at: Optional[int]
    created_at: int
    opened_at: Optional[int]
    close_seq: int
    closed_by: Optional[int]
    close_reason: Optional[str]
    close_requested_at: Optional[int]
    closed_at: Optional[int]
    first_response_at: Optional[int]
    inactivity_deadline: Optional[int]
    inactivity_remaining: Optional[int]
    inactivity_warned: int
    sla_deadline: Optional[int]
    sla_remaining: Optional[int]
    sla_breached_at: Optional[int]
    escalation_deadline: Optional[int]
    escalation_remaining: Optional[int]
    escalated_at: Optional[int]
    hold_started_at: Optional[int]
    total_hold_seconds: int
    channel_deleted: int
    updated_at: int


@dataclass
class Archive:
    id: int
    ticket_id: int
    close_seq: int
    attempt: int
    status: str
    transcript_sha256: Optional[str]
    transcript_size: Optional[int]
    message_count: Optional[int]
    last_message_id: Optional[int]
    transcript_complete: int
    incomplete_reason: Optional[str]
    omissions_ack_by: Optional[int]
    log_status: str
    log_channel_id: Optional[int]
    log_message_id: Optional[int]
    log_attempts: int
    log_error: Optional[str]
    log_verified_at: Optional[int]
    local_status: str
    local_path: Optional[str]
    local_cipher_sha256: Optional[str]
    local_attempts: int
    local_error: Optional[str]
    local_verified_at: Optional[int]
    expires_at: Optional[int]
    local_deleted_at: Optional[int]
    created_at: int
    completed_at: Optional[int]


@dataclass
class Job:
    id: int
    kind: str
    dedupe_key: str
    guild_id: Optional[int]
    ticket_id: Optional[int]
    run_at: int
    status: str
    lease_token: Optional[str]
    attempts: int
    max_attempts: int
    payload: str
    last_error: Optional[str]


TICKET_UPDATABLE = frozenset(f.name for f in dataclasses.fields(Ticket)) - {"id", "guild_id", "panel_id", "number",
                                                                          "owner_id", "create_op_key", "created_at",
                                                                          "state", "version", "updated_at"}
ARCHIVE_UPDATABLE = frozenset(f.name for f in dataclasses.fields(Archive)) - {"id", "ticket_id", "close_seq", "attempt",
                                                                            "created_at"}
LIVE_ARCHIVE_STATUSES = ("BUILDING", "PENDING_COPIES", "BLOCKED")


def _check_columns(columns: Iterable[str], allowed: frozenset[str]) -> None:
    """Column names are SQL identifiers: they must come from a fixed whitelist, never from users."""
    bad = [c for c in columns if c not in allowed]
    if bad:
        raise ValueError(f"disallowed column(s): {bad}")


class Database:
    """All SQLite access. Knows nothing about discord.py.

    A single connection is used from the asyncio thread; no ``await`` ever occurs
    inside a transaction, so transactions never interleave. Cross-process safety
    still comes from SQLite itself (BEGIN IMMEDIATE, unique indexes, triggers).
    """

    def __init__(self, path: str | Path, clock: Clock = now_ts) -> None:
        self.path = str(path)
        self.clock = clock
        self.conn = sqlite3.connect(self.path, isolation_level=None, timeout=5.0)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA busy_timeout = 5000")
        if self.path != ":memory:":
            self.conn.execute("PRAGMA journal_mode = WAL")
        self.conn.execute("PRAGMA synchronous = FULL")
        self._migrate()

    # ---------------------------------------------------------------- basics
    def close(self) -> None:
        with contextlib.suppress(sqlite3.Error):
            if self.path != ":memory:":
                self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        self.conn.close()

    @contextlib.contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        """``BEGIN IMMEDIATE`` transaction: takes the write lock up front."""
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            yield self.conn
        except BaseException:
            if self.conn.in_transaction:
                self.conn.execute("ROLLBACK")
            raise
        else:
            self.conn.execute("COMMIT")

    def _migrate(self) -> None:
        self.conn.executescript(SCHEMA_SQL)
        with self.tx() as c:
            c.executemany("INSERT OR IGNORE INTO ticket_transitions(from_state, to_state) VALUES(?, ?)",
                          sorted(TRANSITIONS))
            c.execute("INSERT OR IGNORE INTO schema_meta(key, value) VALUES('schema_version', ?)", (str(SCHEMA_VERSION),))
        fk = self.conn.execute("PRAGMA foreign_keys").fetchone()[0]
        if fk != 1:
            raise RuntimeError("SQLite foreign keys could not be enabled")

    def integrity_ok(self) -> bool:
        return self.conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"

    def _ensure_guild(self, c: sqlite3.Connection, guild_id: int) -> None:
        now = self.clock()
        c.execute("INSERT OR IGNORE INTO guild_settings(guild_id, created_at, updated_at) VALUES(?, ?, ?)",
                  (guild_id, now, now))

    def add_event(self, guild_id: int, event_type: str, *, ticket_id: Optional[int] = None,
                  panel_id: Optional[int] = None, actor_id: int = 0, from_state: Optional[str] = None,
                  to_state: Optional[str] = None, details: Optional[dict[str, Any]] = None,
                  conn: Optional[sqlite3.Connection] = None) -> None:
        """Append an audit event (metadata only — never message content)."""
        c = conn or self.conn
        c.execute("INSERT INTO ticket_events(guild_id, ticket_id, panel_id, actor_id, event_type, from_state, "
                  "to_state, details, created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                  (guild_id, ticket_id, panel_id, actor_id, event_type[:64], from_state, to_state,
                   json.dumps(details or {}, ensure_ascii=False), self.clock()))

    # ---------------------------------------------------------------- panels
    def save_panel(self, draft: PanelDraft, actor_id: int) -> int:
        """Insert or update a panel and its roles atomically. Returns the panel id."""
        now = self.clock()
        values = (draft.name, draft.embed_title, draft.embed_description, draft.button_label, draft.category_id,
                  draft.panel_channel_id, draft.log_channel_id, draft.channel_name_template, draft.max_open_tickets,
                  int(draft.inactivity_enabled), draft.inactivity_timeout_min, draft.inactivity_warning_min,
                  int(draft.sla_enabled), draft.sla_first_response_min, draft.escalation_role_id,
                  draft.escalation_after_min, int(draft.close_on_owner_leave))
        with self.tx() as c:
            self._ensure_guild(c, draft.guild_id)
            if draft.panel_id is None:
                cur = c.execute(
                    "INSERT INTO panels(name, embed_title, embed_description, button_label, category_id, "
                    "panel_channel_id, log_channel_id, channel_name_template, max_open_tickets, inactivity_enabled, "
                    "inactivity_timeout_min, inactivity_warning_min, sla_enabled, sla_first_response_min, "
                    "escalation_role_id, escalation_after_min, close_on_owner_leave, guild_id, status, created_by, "
                    "created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'ACTIVE',?,?,?)",
                    values + (draft.guild_id, actor_id, now, now))
                panel_id = int(cur.lastrowid)
                event = "panel_created"
            else:
                cur = c.execute(
                    "UPDATE panels SET name=?, embed_title=?, embed_description=?, button_label=?, category_id=?, "
                    "panel_channel_id=?, log_channel_id=?, channel_name_template=?, max_open_tickets=?, "
                    "inactivity_enabled=?, inactivity_timeout_min=?, inactivity_warning_min=?, sla_enabled=?, "
                    "sla_first_response_min=?, escalation_role_id=?, escalation_after_min=?, close_on_owner_leave=?, "
                    "status=CASE WHEN status='MISCONFIGURED' THEN 'ACTIVE' ELSE status END, updated_at=? "
                    "WHERE id=? AND guild_id=? AND status IN ('ACTIVE','PAUSED','MISCONFIGURED')",
                    values + (now, draft.panel_id, draft.guild_id))
                if cur.rowcount != 1:
                    raise ValueError("panel not found or not editable")
                panel_id = draft.panel_id
                c.execute("DELETE FROM panel_roles WHERE panel_id=?", (panel_id,))
                event = "panel_updated"
            c.executemany("INSERT OR IGNORE INTO panel_roles(panel_id, role_id, kind) VALUES(?,?,?)",
                          [(panel_id, r, "admin") for r in draft.admin_role_ids]
                          + [(panel_id, r, "staff") for r in draft.staff_role_ids])
            self.add_event(draft.guild_id, event, panel_id=panel_id, actor_id=actor_id, conn=c)
        return panel_id

    def get_panel(self, panel_id: int) -> Optional[Panel]:
        return _from_row(Panel, self.conn.execute("SELECT * FROM panels WHERE id=?", (panel_id,)).fetchone())

    def list_panels(self, guild_id: Optional[int] = None, statuses: Sequence[str] = ("ACTIVE", "PAUSED", "MISCONFIGURED")) -> list[Panel]:
        marks = ",".join("?" * len(statuses))
        if guild_id is None:
            rows = self.conn.execute(f"SELECT * FROM panels WHERE status IN ({marks}) ORDER BY id", tuple(statuses))
        else:
            rows = self.conn.execute(f"SELECT * FROM panels WHERE guild_id=? AND status IN ({marks}) ORDER BY id",
                                     (guild_id, *statuses))
        return [_from_row(Panel, r) for r in rows.fetchall()]

    def panel_roles(self, panel_id: int) -> PanelRoles:
        rows = self.conn.execute("SELECT role_id, kind FROM panel_roles WHERE panel_id=?", (panel_id,)).fetchall()
        return PanelRoles(admin=frozenset(r["role_id"] for r in rows if r["kind"] == "admin"),
                          staff=frozenset(r["role_id"] for r in rows if r["kind"] == "staff"))

    def draft_from_panel(self, panel: Panel) -> PanelDraft:
        roles = self.panel_roles(panel.id)
        return PanelDraft(
            guild_id=panel.guild_id, panel_id=panel.id, name=panel.name, embed_title=panel.embed_title,
            embed_description=panel.embed_description, button_label=panel.button_label,
            channel_name_template=panel.channel_name_template, admin_role_ids=sorted(roles.admin),
            staff_role_ids=sorted(roles.staff), category_id=panel.category_id, panel_channel_id=panel.panel_channel_id,
            log_channel_id=panel.log_channel_id, max_open_tickets=panel.max_open_tickets,
            inactivity_enabled=bool(panel.inactivity_enabled), inactivity_timeout_min=panel.inactivity_timeout_min,
            inactivity_warning_min=panel.inactivity_warning_min, sla_enabled=bool(panel.sla_enabled),
            sla_first_response_min=panel.sla_first_response_min, escalation_role_id=panel.escalation_role_id,
            escalation_after_min=panel.escalation_after_min, close_on_owner_leave=bool(panel.close_on_owner_leave))

    def set_panel_status(self, panel_id: int, status: str, *, expected: Optional[Sequence[str]] = None,
                         actor_id: int = 0, reason: str = "") -> bool:
        with self.tx() as c:
            row = c.execute("SELECT guild_id, status FROM panels WHERE id=?", (panel_id,)).fetchone()
            if row is None or (expected is not None and row["status"] not in expected):
                return False
            c.execute("UPDATE panels SET status=?, updated_at=? WHERE id=?", (status, self.clock(), panel_id))
            self.add_event(row["guild_id"], "panel_status", panel_id=panel_id, actor_id=actor_id,
                           from_state=row["status"], to_state=status, details={"reason": reason[:200]}, conn=c)
        return True

    def set_panel_message(self, panel_id: int, message_id: Optional[int]) -> None:
        with self.tx() as c:
            c.execute("UPDATE panels SET panel_message_id=?, updated_at=? WHERE id=?", (message_id, self.clock(), panel_id))

    def count_panel_tickets(self, panel_id: int, states: Sequence[str]) -> int:
        marks = ",".join("?" * len(states))
        return int(self.conn.execute(f"SELECT COUNT(*) FROM tickets WHERE panel_id=? AND state IN ({marks})",
                                     (panel_id, *states)).fetchone()[0])

    def retire_panel(self, panel_id: int, *, delete: bool, actor_id: int) -> Optional[str]:
        """Archive or delete a panel, refusing while active/closing tickets exist.

        Returns ``None`` on success or an error code. Deletion is a hard delete if the
        panel never had tickets; otherwise it is a soft delete (history is preserved).
        """
        with self.tx() as c:
            panel = c.execute("SELECT guild_id, status FROM panels WHERE id=?", (panel_id,)).fetchone()
            if panel is None or panel["status"] == "DELETED":
                return "not_found"
            busy = c.execute("SELECT COUNT(*) FROM tickets WHERE panel_id=? AND state IN ('CREATING','OPEN','ON_HOLD','CLOSING')",
                             (panel_id,)).fetchone()[0]
            if busy:
                return "has_active_tickets"
            if not delete:
                c.execute("UPDATE panels SET status='ARCHIVED', updated_at=? WHERE id=?", (self.clock(), panel_id))
                self.add_event(panel["guild_id"], "panel_archived", panel_id=panel_id, actor_id=actor_id, conn=c)
                return None
            total = c.execute("SELECT COUNT(*) FROM tickets WHERE panel_id=?", (panel_id,)).fetchone()[0]
            if total == 0:
                c.execute("DELETE FROM ticket_events WHERE panel_id=?", (panel_id,))
                c.execute("DELETE FROM panels WHERE id=?", (panel_id,))
                self.add_event(panel["guild_id"], "panel_deleted", actor_id=actor_id, details={"panel_id": panel_id}, conn=c)
            else:
                c.execute("UPDATE panels SET status='DELETED', panel_message_id=NULL, embed_description='(deleted)', "
                          "updated_at=? WHERE id=?", (self.clock(), panel_id))
                self.add_event(panel["guild_id"], "panel_soft_deleted", panel_id=panel_id, actor_id=actor_id, conn=c)
        return None

    def panels_using_channel(self, channel_id: int) -> list[Panel]:
        rows = self.conn.execute(
            "SELECT * FROM panels WHERE status IN ('ACTIVE','PAUSED','MISCONFIGURED') AND "
            "(category_id=? OR log_channel_id=? OR panel_channel_id=?)", (channel_id, channel_id, channel_id)).fetchall()
        return [_from_row(Panel, r) for r in rows]

    def panel_by_message(self, message_id: int) -> Optional[Panel]:
        return _from_row(Panel, self.conn.execute("SELECT * FROM panels WHERE panel_message_id=?", (message_id,)).fetchone())

    # --------------------------------------------------------------- tickets
    def create_ticket(self, guild_id: int, panel_id: int, owner_id: int) -> Ticket:
        """Allocate a ticket number and insert a CREATING row (before any Discord call)."""
        now = self.clock()
        try:
            with self.tx() as c:
                self._ensure_guild(c, guild_id)
                number = c.execute("SELECT next_ticket_number FROM guild_settings WHERE guild_id=?",
                                   (guild_id,)).fetchone()[0]
                c.execute("UPDATE guild_settings SET next_ticket_number=next_ticket_number+1, updated_at=? WHERE guild_id=?",
                          (now, guild_id))
                cur = c.execute(
                    "INSERT INTO tickets(guild_id, panel_id, number, owner_id, state, create_op_key, created_at, updated_at) "
                    "VALUES(?,?,?,?,'CREATING',?,?,?)", (guild_id, panel_id, number, owner_id, uuid.uuid4().hex, now, now))
                ticket_id = int(cur.lastrowid)
                self.add_event(guild_id, "ticket_creating", ticket_id=ticket_id, panel_id=panel_id, actor_id=owner_id,
                               to_state=S_CREATING, conn=c)
        except sqlite3.IntegrityError as exc:
            text = str(exc)
            if "ux_tickets_one_active" in text or "tickets.guild_id, tickets.panel_id, tickets.owner_id" in text:
                raise DuplicateActiveTicket() from exc
            if "tazkara:panel_limit" in text:
                raise PanelLimitReached() from exc
            raise
        return self.get_ticket(ticket_id)

    def get_ticket(self, ticket_id: int) -> Optional[Ticket]:
        return _from_row(Ticket, self.conn.execute("SELECT * FROM tickets WHERE id=?", (ticket_id,)).fetchone())

    def get_ticket_by_channel(self, channel_id: int) -> Optional[Ticket]:
        return _from_row(Ticket, self.conn.execute("SELECT * FROM tickets WHERE channel_id=?", (channel_id,)).fetchone())

    def get_active_ticket(self, guild_id: int, panel_id: int, owner_id: int) -> Optional[Ticket]:
        return _from_row(Ticket, self.conn.execute(
            f"SELECT * FROM tickets WHERE guild_id=? AND panel_id=? AND owner_id=? AND state IN ({_ACTIVE_LIST_SQL})",
            (guild_id, panel_id, owner_id)).fetchone())

    def tickets_in_states(self, states: Sequence[str], *, guild_id: Optional[int] = None) -> list[Ticket]:
        marks = ",".join("?" * len(states))
        sql = f"SELECT * FROM tickets WHERE state IN ({marks})"
        params: tuple[Any, ...] = tuple(states)
        if guild_id is not None:
            sql += " AND guild_id=?"
            params += (guild_id,)
        return [_from_row(Ticket, r) for r in self.conn.execute(sql + " ORDER BY id", params).fetchall()]

    def tickets_for_owner(self, guild_id: int, owner_id: int, states: Sequence[str]) -> list[Ticket]:
        marks = ",".join("?" * len(states))
        rows = self.conn.execute(f"SELECT * FROM tickets WHERE guild_id=? AND owner_id=? AND state IN ({marks})",
                                 (guild_id, owner_id, *states)).fetchall()
        return [_from_row(Ticket, r) for r in rows]

    def _transition_in(self, c: sqlite3.Connection, ticket_id: int, from_states: Sequence[str], to_state: str,
                       updates: dict[str, Any], expected: dict[str, Any]) -> Optional[sqlite3.Row]:
        _check_columns(updates, TICKET_UPDATABLE)
        _check_columns(expected, TICKET_UPDATABLE | {"version"})
        for s in from_states:
            if (s, to_state) not in TRANSITIONS:
                raise InvalidTransition(f"{s}->{to_state}")
        row = c.execute("SELECT * FROM tickets WHERE id=?", (ticket_id,)).fetchone()
        if row is None or row["state"] not in from_states:
            return None
        for col, val in expected.items():
            if row[col] != val:
                return None
        sets = ", ".join(f"{col}=?" for col in updates)
        sql = f"UPDATE tickets SET state=?, version=version+1, updated_at=?{', ' + sets if sets else ''} WHERE id=? AND state=? AND version=?"
        cur = c.execute(sql, (to_state, self.clock(), *updates.values(), ticket_id, row["state"], row["version"]))
        return row if cur.rowcount == 1 else None

    def transition(self, ticket_id: int, from_states: Sequence[str], to_state: str, *, actor_id: int = 0,
                   event: str = "state_change", updates: Optional[dict[str, Any]] = None,
                   expected: Optional[dict[str, Any]] = None, details: Optional[dict[str, Any]] = None) -> Optional[Ticket]:
        """Atomically move a ticket to ``to_state`` if it is currently in ``from_states``.

        ``expected`` adds optimistic checks on other columns. Returns the updated
        ticket, or ``None`` if the precondition no longer holds (lost race / stale).
        """
        with self.tx() as c:
            before = self._transition_in(c, ticket_id, from_states, to_state, updates or {}, expected or {})
            if before is None:
                return None
            self.add_event(before["guild_id"], event, ticket_id=ticket_id, panel_id=before["panel_id"],
                           actor_id=actor_id, from_state=before["state"], to_state=to_state, details=details, conn=c)
        return self.get_ticket(ticket_id)

    def update_ticket_if(self, ticket_id: int, states: Sequence[str], updates: dict[str, Any], *,
                         expected: Optional[dict[str, Any]] = None, event: Optional[str] = None,
                         actor_id: int = 0, details: Optional[dict[str, Any]] = None) -> Optional[Ticket]:
        """Conditionally update non-state columns (state must be one of ``states``)."""
        _check_columns(updates, TICKET_UPDATABLE)
        expected = expected or {}
        _check_columns(expected, TICKET_UPDATABLE | {"version"})
        with self.tx() as c:
            row = c.execute("SELECT * FROM tickets WHERE id=?", (ticket_id,)).fetchone()
            if row is None or row["state"] not in states:
                return None
            if any(row[k] != v for k, v in expected.items()):
                return None
            if updates:
                sets = ", ".join(f"{col}=?" for col in updates)
                cur = c.execute(f"UPDATE tickets SET {sets}, version=version+1, updated_at=? WHERE id=? AND version=?",
                                (*updates.values(), self.clock(), ticket_id, row["version"]))
                if cur.rowcount != 1:
                    return None
            if event:
                self.add_event(row["guild_id"], event, ticket_id=ticket_id, panel_id=row["panel_id"],
                               actor_id=actor_id, details=details, conn=c)
        return self.get_ticket(ticket_id)

    # -------------------------------------------------------------- archives
    def get_archive(self, archive_id: int) -> Optional[Archive]:
        return _from_row(Archive, self.conn.execute("SELECT * FROM archives WHERE id=?", (archive_id,)).fetchone())

    def get_live_archive(self, ticket_id: int) -> Optional[Archive]:
        return _from_row(Archive, self.conn.execute(
            "SELECT * FROM archives WHERE ticket_id=? AND status IN ('BUILDING','PENDING_COPIES','BLOCKED')",
            (ticket_id,)).fetchone())

    def archives_for_ticket(self, ticket_id: int) -> list[Archive]:
        return [_from_row(Archive, r) for r in
                self.conn.execute("SELECT * FROM archives WHERE ticket_id=? ORDER BY id", (ticket_id,)).fetchall()]

    def create_archive(self, ticket_id: int, close_seq: int) -> Archive:
        with self.tx() as c:
            attempt = c.execute("SELECT COALESCE(MAX(attempt), 0) + 1 FROM archives WHERE ticket_id=? AND close_seq=?",
                                (ticket_id, close_seq)).fetchone()[0]
            cur = c.execute("INSERT INTO archives(ticket_id, close_seq, attempt, created_at) VALUES(?,?,?,?)",
                            (ticket_id, close_seq, attempt, self.clock()))
            archive_id = int(cur.lastrowid)
        return self.get_archive(archive_id)

    def update_archive(self, archive_id: int, *, only_if_status: Optional[Sequence[str]] = None, **fields: Any) -> bool:
        _check_columns(fields, ARCHIVE_UPDATABLE)
        sets = ", ".join(f"{k}=?" for k in fields)
        sql = f"UPDATE archives SET {sets} WHERE id=?"
        params: tuple[Any, ...] = (*fields.values(), archive_id)
        if only_if_status:
            sql += f" AND status IN ({','.join('?' * len(only_if_status))})"
            params += tuple(only_if_status)
        with self.tx() as c:
            return c.execute(sql, params).rowcount == 1

    def supersede_live_archives(self, ticket_id: int, conn: Optional[sqlite3.Connection] = None) -> int:
        c = conn or self.conn
        return c.execute("UPDATE archives SET status='SUPERSEDED' WHERE ticket_id=? AND status IN "
                         "('BUILDING','PENDING_COPIES','BLOCKED')", (ticket_id,)).rowcount

    def complete_archive_and_close(self, ticket_id: int, archive_id: int) -> bool:
        """Single transaction: archive -> COMPLETE and ticket CLOSING -> CLOSED.

        Both copies must be VERIFIED and the transcript complete, otherwise nothing
        changes. This is the ONLY code path that can lead to channel deletion.
        """
        now = self.clock()
        try:
            with self.tx() as c:
                cur = c.execute("UPDATE archives SET status='COMPLETE', completed_at=? WHERE id=? AND ticket_id=? "
                                "AND status='PENDING_COPIES' AND log_status='VERIFIED' AND local_status='VERIFIED' "
                                "AND transcript_complete=1", (now, archive_id, ticket_id))
                if cur.rowcount != 1:
                    raise _Rollback()
                before = self._transition_in(c, ticket_id, (S_CLOSING,), S_CLOSED, {"closed_at": now}, {})
                if before is None:
                    raise _Rollback()
                self.add_event(before["guild_id"], "ticket_closed", ticket_id=ticket_id, panel_id=before["panel_id"],
                               from_state=S_CLOSING, to_state=S_CLOSED, details={"archive_id": archive_id}, conn=c)
        except _Rollback:
            return False
        return True

    def archives_for_retention(self, now: int) -> list[Archive]:
        rows = self.conn.execute(
            "SELECT * FROM archives WHERE (local_status='VERIFIED' AND expires_at IS NOT NULL AND expires_at<=?) "
            "OR local_status='RETENTION_HOLD' ORDER BY id", (now,)).fetchall()
        return [_from_row(Archive, r) for r in rows]

    # ------------------------------------------------------------------ jobs
    def schedule_job(self, kind: str, dedupe_key: str, run_at: int, *, guild_id: Optional[int] = None,
                     ticket_id: Optional[int] = None, payload: Optional[dict[str, Any]] = None,
                     max_attempts: int = 10, keep_existing: bool = False) -> None:
        """Upsert a job by ``dedupe_key``. ``keep_existing`` leaves a PENDING/RUNNING job untouched."""
        now = self.clock()
        condition = " WHERE scheduled_jobs.status NOT IN ('PENDING','RUNNING')" if keep_existing else ""
        with self.tx() as c:
            c.execute(
                "INSERT INTO scheduled_jobs(kind, dedupe_key, guild_id, ticket_id, run_at, max_attempts, payload, "
                "created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(dedupe_key) DO UPDATE SET "
                "run_at=excluded.run_at, status='PENDING', lease_token=NULL, attempts=0, "
                "max_attempts=excluded.max_attempts, payload=excluded.payload, last_error=NULL, "
                "updated_at=excluded.updated_at" + condition,
                (kind, dedupe_key, guild_id, ticket_id, run_at, max_attempts, json.dumps(payload or {}), now, now))

    def cancel_job(self, dedupe_key: str) -> None:
        with self.tx() as c:
            c.execute("UPDATE scheduled_jobs SET status='CANCELLED', lease_token=NULL, updated_at=? "
                      "WHERE dedupe_key=? AND status IN ('PENDING','RUNNING')", (self.clock(), dedupe_key))

    def get_job(self, dedupe_key: str) -> Optional[Job]:
        return _from_row(Job, self.conn.execute("SELECT * FROM scheduled_jobs WHERE dedupe_key=?", (dedupe_key,)).fetchone())

    def claim_due_jobs(self, now: int, limit: int) -> list[Job]:
        """Lease due PENDING jobs (status -> RUNNING with a fresh lease token)."""
        claimed: list[Job] = []
        with self.tx() as c:
            rows = c.execute("SELECT id FROM scheduled_jobs WHERE status='PENDING' AND run_at<=? ORDER BY run_at, id LIMIT ?",
                             (now, limit)).fetchall()
            for row in rows:
                token = uuid.uuid4().hex
                c.execute("UPDATE scheduled_jobs SET status='RUNNING', lease_token=?, attempts=attempts+1, updated_at=? "
                          "WHERE id=? AND status='PENDING'", (token, now, row["id"]))
        for row in rows:
            job = _from_row(Job, self.conn.execute("SELECT * FROM scheduled_jobs WHERE id=?", (row["id"],)).fetchone())
            if job and job.status == "RUNNING":
                claimed.append(job)
        return claimed

    def finish_job(self, job: Job, status: str, *, run_at: Optional[int] = None, error: Optional[str] = None,
                   reset_attempts: bool = False) -> bool:
        """Finish a leased job. No-op if the job was re-scheduled/cancelled meanwhile (lease mismatch)."""
        new_status = "PENDING" if status in ("retry", "reschedule") else status
        with self.tx() as c:
            cur = c.execute(
                "UPDATE scheduled_jobs SET status=?, run_at=COALESCE(?, run_at), last_error=?, lease_token=NULL, "
                "attempts=CASE WHEN ? THEN 0 ELSE attempts END, updated_at=? WHERE id=? AND status='RUNNING' AND lease_token=?",
                (new_status, run_at, (error or None) and error[:500], 1 if reset_attempts else 0, self.clock(),
                 job.id, job.lease_token))
            return cur.rowcount == 1

    def reset_running_jobs(self) -> int:
        """After a crash/restart, RUNNING jobs are made PENDING again (handlers are idempotent)."""
        with self.tx() as c:
            return c.execute("UPDATE scheduled_jobs SET status='PENDING', lease_token=NULL, updated_at=? "
                             "WHERE status='RUNNING'", (self.clock(),)).rowcount

    def pending_jobs(self, ticket_id: Optional[int] = None) -> list[Job]:
        sql, params = "SELECT * FROM scheduled_jobs WHERE status IN ('PENDING','RUNNING')", ()
        if ticket_id is not None:
            sql, params = sql + " AND ticket_id=?", (ticket_id,)
        return [_from_row(Job, r) for r in self.conn.execute(sql + " ORDER BY run_at", params).fetchall()]

    # ----------------------------------------------------------- outbox ops
    def op_get(self, op_key: str) -> Optional[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM external_ops WHERE op_key=?", (op_key,)).fetchone()

    def op_set(self, op_key: str, kind: str, status: str, *, ticket_id: Optional[int] = None,
               external_id: Optional[int] = None, error: Optional[str] = None) -> None:
        now = self.clock()
        with self.tx() as c:
            c.execute(
                "INSERT INTO external_ops(op_key, kind, ticket_id, status, external_id, attempts, last_error, created_at, "
                "updated_at) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(op_key) DO UPDATE SET status=excluded.status, "
                "external_id=COALESCE(excluded.external_id, external_ops.external_id), "
                "attempts=external_ops.attempts + CASE WHEN excluded.status='STARTED' THEN 1 ELSE 0 END, "
                "last_error=excluded.last_error, updated_at=excluded.updated_at",
                (op_key, kind, ticket_id, status, external_id, 1 if status == "STARTED" else 0,
                 (error or None) and error[:300], now, now))

    # ------------------------------------------------------- stats & purge
    def stats(self, guild_id: int, now: Optional[int] = None) -> dict[str, Any]:
        now = now or self.clock()
        by_state = {r[0]: r[1] for r in self.conn.execute(
            "SELECT state, COUNT(*) FROM tickets WHERE guild_id=? GROUP BY state", (guild_id,)).fetchall()}
        week = self.conn.execute("SELECT COUNT(*) FROM tickets WHERE guild_id=? AND created_at>=?",
                                 (guild_id, now - 7 * 86400)).fetchone()[0]
        avg_first = self.conn.execute("SELECT AVG(first_response_at - opened_at) FROM tickets WHERE guild_id=? AND "
                                      "first_response_at IS NOT NULL AND opened_at IS NOT NULL", (guild_id,)).fetchone()[0]
        pending = self.conn.execute("SELECT COUNT(*) FROM archives a JOIN tickets t ON t.id=a.ticket_id WHERE t.guild_id=? "
                                    "AND a.status IN ('BUILDING','PENDING_COPIES','BLOCKED')", (guild_id,)).fetchone()[0]
        holds = self.conn.execute("SELECT COUNT(*) FROM archives a JOIN tickets t ON t.id=a.ticket_id WHERE t.guild_id=? "
                                  "AND a.local_status='RETENTION_HOLD'", (guild_id,)).fetchone()[0]
        breaches = self.conn.execute("SELECT COUNT(*) FROM tickets WHERE guild_id=? AND sla_breached_at IS NOT NULL",
                                     (guild_id,)).fetchone()[0]
        return {"by_state": by_state, "last_7_days": week, "avg_first_response_s": avg_first,
                "archives_pending": pending, "retention_holds": holds, "sla_breaches": breaches}

    def purge_old(self, now: int) -> dict[str, int]:
        """Apply DB retention: events 180d, finished jobs/ops 30d."""
        with self.tx() as c:
            ev = c.execute("DELETE FROM ticket_events WHERE created_at < ?", (now - EVENT_RETENTION_DAYS * 86400,)).rowcount
            jobs = c.execute("DELETE FROM scheduled_jobs WHERE status IN ('DONE','CANCELLED','FAILED') AND updated_at < ?",
                             (now - JOB_RETENTION_DAYS * 86400,)).rowcount
            ops = c.execute("DELETE FROM external_ops WHERE status IN ('SUCCEEDED','FAILED','UNCERTAIN') AND updated_at < ?",
                            (now - JOB_RETENTION_DAYS * 86400,)).rowcount
        return {"events": ev, "jobs": jobs, "ops": ops}


# =============================================================================
# 5. STATE MACHINE + PERMISSION POLICY (pure)
# =============================================================================

A_CLAIM, A_HOLD, A_CLOSE, A_REOPEN, A_ACK = "claim", "hold", "close", "reopen", "ack_omissions"


@dataclass(frozen=True)
class Actor:
    """Who is acting. Built from the *live* interaction data on every click."""
    user_id: int
    role_ids: frozenset[int]
    is_manager: bool  # Manage Server / Administrator, as reported by Discord for this interaction
    is_system: bool = False


SYSTEM_ACTOR = Actor(user_id=0, role_ids=frozenset(), is_manager=True, is_system=True)


def is_staff(actor: Actor, roles: PanelRoles) -> bool:
    return actor.is_manager or bool(actor.role_ids & roles.all)


def is_panel_admin(actor: Actor, roles: PanelRoles) -> bool:
    return actor.is_manager or bool(actor.role_ids & roles.admin)


def is_allowed(action: str, actor: Actor, ticket: Ticket, roles: PanelRoles) -> bool:
    """Central permission policy (see DESIGN.md §5)."""
    if actor.is_system:
        return True
    if action == A_CLOSE:
        return actor.user_id == ticket.owner_id or is_staff(actor, roles)
    if action == A_CLAIM:
        return is_staff(actor, roles) and actor.user_id != ticket.owner_id
    if action in (A_HOLD, A_REOPEN):
        return is_staff(actor, roles)
    if action == A_ACK:
        return is_panel_admin(actor, roles)
    return False


def can_transition(from_state: str, to_state: str) -> bool:
    return (from_state, to_state) in TRANSITIONS


# =============================================================================
# 6. TIMER LOGIC (pure; hold time never counts toward deadlines)
# =============================================================================
# Definitions:
#  * Customer inactivity: the timer is ARMED when a staff member writes (the ball
#    is in the customer's court) and DISARMED when the owner writes. If it expires,
#    a warning is sent; if the owner is still silent after the warning period, the
#    ticket is auto-closed. A warning is always delivered before an auto-close.
#  * SLA: deadline = open time + first-response minutes. The first message from a
#    staff member stops it. On breach staff roles are alerted; optional escalation
#    role is alerted after "escalation minutes".
#  * Hold: every running deadline is converted into "remaining seconds" and
#    restored on resume, so hold duration is never counted.

TIMER_NAMES = ("inactivity", "sla", "escalation")


def timers_on_open(panel: Panel, now: int) -> dict[str, Any]:
    return {"sla_deadline": now + panel.sla_first_response_min * 60} if panel.sla_enabled else {}


def timers_pause(ticket: Ticket, now: int) -> dict[str, Any]:
    updates: dict[str, Any] = {"hold_started_at": now}
    for name in TIMER_NAMES:
        deadline = getattr(ticket, f"{name}_deadline")
        if deadline is not None:
            updates[f"{name}_remaining"] = max(0, deadline - now)
            updates[f"{name}_deadline"] = None
    return updates


def timers_resume(ticket: Ticket, now: int) -> dict[str, Any]:
    updates: dict[str, Any] = {"hold_started_at": None}
    for name in TIMER_NAMES:
        remaining = getattr(ticket, f"{name}_remaining")
        if remaining is not None:
            updates[f"{name}_deadline"] = now + remaining
            updates[f"{name}_remaining"] = None
    held = max(0, now - (ticket.hold_started_at or now))
    updates["total_hold_seconds"] = ticket.total_hold_seconds + held
    return updates


def timers_on_staff_message(ticket: Ticket, panel: Panel, now: int) -> dict[str, Any]:
    updates: dict[str, Any] = {}
    if ticket.first_response_at is None:
        updates.update(first_response_at=now, sla_deadline=None, sla_remaining=None,
                       escalation_deadline=None, escalation_remaining=None)
    if panel.inactivity_enabled:
        timeout = panel.inactivity_timeout_min * 60
        if ticket.state == S_ON_HOLD:
            updates.update(inactivity_remaining=timeout, inactivity_deadline=None)
        else:
            updates.update(inactivity_deadline=now + timeout, inactivity_remaining=None)
        updates["inactivity_warned"] = 0
    return updates


def timers_on_owner_message(ticket: Ticket) -> dict[str, Any]:
    if ticket.inactivity_deadline is None and ticket.inactivity_remaining is None and not ticket.inactivity_warned:
        return {}
    return {"inactivity_deadline": None, "inactivity_remaining": None, "inactivity_warned": 0}


def timers_cleared() -> dict[str, Any]:
    cleared: dict[str, Any] = {"inactivity_warned": 0}
    for name in TIMER_NAMES:
        cleared[f"{name}_deadline"] = None
        cleared[f"{name}_remaining"] = None
    return cleared


# =============================================================================
# 7. VAULT (ENCRYPTION) + TRANSCRIPT BUILDER
# =============================================================================

class VaultError(Exception):
    """Encryption, decryption or integrity verification failed."""


class ArchiveVault:
    """Fernet (AES-128-CBC + HMAC-SHA256) authenticated encryption for local archives."""

    def __init__(self, key: bytes) -> None:
        try:
            self._fernet = Fernet(key)
        except (ValueError, TypeError) as exc:
            raise VaultError("invalid key format") from exc

    @classmethod
    def load(cls, key_path: Path, archive_dir: Path) -> "ArchiveVault":
        """Load the key, refusing a key stored inside the archive directory."""
        key_path = key_path.resolve()
        archive_dir = archive_dir.resolve()
        if key_path == archive_dir or archive_dir in key_path.parents:
            raise VaultError("the key file must not be stored inside the archive directory")
        if not key_path.is_file():
            raise VaultError(f"key file not found: {key_path} (run: python main.py --init-key)")
        key = key_path.read_bytes().strip()
        REDACTOR.add_secret(key.decode("ascii", errors="ignore"))
        return cls(key)

    def encrypt(self, data: bytes) -> bytes:
        return self._fernet.encrypt(data)

    def decrypt(self, token: bytes) -> bytes:
        try:
            return self._fernet.decrypt(token)
        except InvalidToken as exc:
            raise VaultError("decryption/authentication failed") from exc

    def write_verified(self, path: Path, plaintext: bytes, expected_sha256: str) -> str:
        """Encrypt -> temp file -> fsync -> atomic replace -> read back -> decrypt -> compare.

        Returns the SHA-256 of the ciphertext file. Raises VaultError/OSError; on a
        verification failure the bad file is removed so it is never mistaken as valid.
        """
        if sha256_hex(plaintext) != expected_sha256:
            raise VaultError("plaintext does not match expected hash")
        path.parent.mkdir(parents=True, exist_ok=True)
        token = self.encrypt(plaintext)
        tmp = path.with_name(path.name + ".tmp")
        with open(tmp, "wb") as handle:
            handle.write(token)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        stored = path.read_bytes()
        try:
            ok = sha256_hex(self.decrypt(stored)) == expected_sha256
        except VaultError:
            ok = False
        if not ok:
            path.unlink(missing_ok=True)
            raise VaultError("integrity verification failed after write")
        return sha256_hex(stored)

    def read_verified(self, path: Path, expected_sha256: str, expected_cipher_sha256: Optional[str] = None) -> bytes:
        stored = path.read_bytes()
        if expected_cipher_sha256 and sha256_hex(stored) != expected_cipher_sha256:
            raise VaultError("ciphertext hash mismatch")
        plaintext = self.decrypt(stored)
        if sha256_hex(plaintext) != expected_sha256:
            raise VaultError("plaintext hash mismatch")
        return plaintext


def init_key_file(path: Path) -> Path:
    """Create a new random Fernet key file (refuses to overwrite)."""
    path = path.resolve()
    if path.exists():
        raise FileExistsError(f"key already exists: {path} (refusing to overwrite — old archives need it)")
    if ARCHIVE_DIR.resolve() in path.parents:
        raise VaultError("the key file must not be stored inside the archive directory")
    path.parent.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        os.chmod(path.parent, 0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(Fernet.generate_key())
    return path


@dataclass
class TranscriptAttachment:
    filename: str
    size: int
    data: Optional[bytes] = None
    omitted_reason: Optional[str] = None


@dataclass
class TranscriptMessage:
    id: int
    author_id: int
    author_name: str
    is_bot: bool
    created_at: int
    content: str
    embeds: list[tuple[str, str]] = field(default_factory=list)
    attachments: list[TranscriptAttachment] = field(default_factory=list)
    edited: bool = False


@dataclass
class TranscriptMeta:
    guild_name: str
    guild_id: int
    channel_name: str
    ticket_id: int
    ticket_number: int
    panel_name: str
    owner_id: int
    owner_name: str
    created_at: int
    closed_by: Optional[int]
    close_reason: Optional[str]
    generated_at: int
    omissions_acknowledged: bool = False


_TRANSCRIPT_CSP = ("default-src 'none'; img-src data:; style-src 'unsafe-inline'; base-uri 'none'; "
                   "form-action 'none'; frame-ancestors 'none'")
_TRANSCRIPT_CSS = (
    "body{font-family:Segoe UI,Tahoma,Arial,sans-serif;background:#1e1f22;color:#dbdee1;margin:0;padding:16px}"
    "header{background:#2b2d31;border-radius:8px;padding:12px 16px;margin-bottom:16px}"
    "header table td{padding:2px 10px 2px 0;vertical-align:top}.msg{padding:8px 12px;border-bottom:1px solid #2b2d31}"
    ".msg.bot{background:#232428}.meta{font-size:13px;color:#949ba4}.author{color:#f2f3f5;font-weight:600}"
    ".content{white-space:normal;word-wrap:break-word;margin-top:4px}.embed{border-inline-start:4px solid #5865f2;"
    "background:#2b2d31;padding:6px 10px;margin-top:6px;border-radius:4px}.att{margin-top:6px}"
    ".omitted{color:#f0b232}img{max-width:480px;max-height:480px;display:block;border-radius:4px}"
    "figure{margin:6px 0}figcaption{font-size:12px;color:#949ba4}footer{margin-top:16px;font-size:12px;color:#949ba4}"
    "a{color:#00a8fc}")


def _esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _esc_multiline(value: str) -> str:
    return _esc(value).replace("\r\n", "\n").replace("\n", "<br>")


def _fmt_ts(ts: Optional[int]) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(ts)) if ts else "-"


def _fmt_size(size: int) -> str:
    return f"{size / 1024:.1f} KB" if size < 1024 * 1024 else f"{size / 1024 / 1024:.2f} MB"


def sniff_image_mime(data: bytes) -> Optional[str]:
    """Detect raster images by magic bytes (SVG is deliberately NOT treated as an image)."""
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return "image/gif"
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    return None


def safe_filename(name: str) -> str:
    cleaned = re.sub(r"[^\w.\- ]", "_", name, flags=re.UNICODE).strip(" .")
    return (cleaned or "file")[:100]


def build_transcript_html(meta: TranscriptMeta, messages: Sequence[TranscriptMessage]) -> bytes:
    """Build a self-contained, script-free HTML transcript.

    * Every untrusted string is HTML-escaped (quote=True).
    * A strict CSP forbids scripts and any network fetch; images are data: URIs.
    * URLs in messages are rendered as plain text, never as live links.
    """
    title = f"Ticket #{meta.ticket_number} — {meta.guild_name}"
    out: list[str] = [
        '<!DOCTYPE html><html lang="ar" dir="auto"><head><meta charset="utf-8">',
        f'<meta http-equiv="Content-Security-Policy" content="{_TRANSCRIPT_CSP}">',
        '<meta name="referrer" content="no-referrer"><meta name="robots" content="noindex">',
        f"<title>{_esc(title)}</title><style>{_TRANSCRIPT_CSS}</style></head><body>",
        "<header><h2>Tazkara Transcript</h2><table>",
    ]
    rows = [
        ("Server", f"{meta.guild_name} ({meta.guild_id})"), ("Channel", meta.channel_name),
        ("Ticket", f"#{meta.ticket_number} (id {meta.ticket_id})"), ("Panel", meta.panel_name),
        ("Owner", f"{meta.owner_name} ({meta.owner_id})"), ("Created", _fmt_ts(meta.created_at)),
        ("Closed by", str(meta.closed_by) if meta.closed_by else "system"),
        ("Close reason", meta.close_reason or "-"), ("Generated", _fmt_ts(meta.generated_at)),
        ("Messages", str(len(messages))),
    ]
    out.extend(f"<tr><td><b>{_esc(k)}</b></td><td>{_esc(v)}</td></tr>" for k, v in rows)
    out.append("</table>")
    if meta.omissions_acknowledged:
        out.append('<p class="omitted">⚠ Some attachments could not be stored; an administrator explicitly '
                   'acknowledged this before archiving.</p>')
    out.append("</header><main>")
    for msg in messages:
        css = "msg bot" if msg.is_bot else "msg"
        edited = ' <span class="ts">(edited)</span>' if msg.edited else ""
        out.append(f'<div class="{css}" id="m{int(msg.id)}"><div class="meta"><span class="author">{_esc(msg.author_name)}'
                   f'</span> <span>({int(msg.author_id)})</span> · <span>{_fmt_ts(msg.created_at)}</span>{edited}</div>')
        if msg.content:
            out.append(f'<div class="content">{_esc_multiline(msg.content)}</div>')
        for embed_title, embed_desc in msg.embeds:
            out.append(f'<div class="embed"><b>{_esc(embed_title)}</b><div>{_esc_multiline(embed_desc)}</div></div>')
        for att in msg.attachments:
            out.append(_render_attachment(att))
        out.append("</div>")
    out.append(f"</main><footer>Generated by Tazkara · {len(messages)} messages · times in UTC</footer></body></html>")
    return "".join(out).encode("utf-8")


def _render_attachment(att: TranscriptAttachment) -> str:
    label = f"{_esc(att.filename)} ({_fmt_size(att.size)})"
    if att.data is None:
        return f'<div class="att omitted">📎 {label} — not stored: {_esc(att.omitted_reason or "unknown")}</div>'
    b64 = base64.b64encode(att.data).decode("ascii")
    mime = sniff_image_mime(att.data)
    if mime:
        return (f'<figure class="att"><img alt="{_esc(att.filename)}" src="data:{mime};base64,{b64}">'
                f"<figcaption>{label}</figcaption></figure>")
    return (f'<div class="att">📎 <a download="{_esc(safe_filename(att.filename))}" '
            f'href="data:application/octet-stream;base64,{b64}">{label}</a> · sha256 {sha256_hex(att.data)[:16]}</div>')


# =============================================================================
# 8. GATEWAY PROTOCOL (abstract Discord I/O)
# =============================================================================

class GatewayError(Exception):
    """Normalised Discord failure. ``kind`` drives retry/compensation decisions."""
    NOT_FOUND = "not_found"
    FORBIDDEN = "forbidden"
    TRANSIENT = "transient"   # safe to retry (rate limit, temporary)
    UNCERTAIN = "uncertain"   # request may or may not have been applied (5xx/timeout)
    INVALID = "invalid"       # 4xx — will not succeed on retry

    def __init__(self, kind: str, detail: str = "", retry_after: Optional[float] = None) -> None:
        super().__init__(f"{kind}:{detail}"[:300])
        self.kind = kind
        self.detail = detail[:200]
        self.retry_after = retry_after  # seconds Discord asked us to wait (rate limits only)

    @property
    def retryable(self) -> bool:
        return self.kind in (self.TRANSIENT, self.UNCERTAIN)


@dataclass
class TranscriptCollection:
    messages: list[TranscriptMessage]
    last_message_id: Optional[int]
    guild_name: str
    channel_name: str
    owner_name: str
    fatal_reason: Optional[str] = None  # cannot be acknowledged (e.g. missing MESSAGE_CONTENT)
    omissions: list[str] = field(default_factory=list)  # attachments not stored (admin may acknowledge)


class Gateway(Protocol):
    """Every external Discord side-effect the services need."""

    async def create_ticket_channel(self, panel: Panel, roles: PanelRoles, ticket: Ticket, owner_name: str) -> int: ...
    async def create_ticket_thread(self, panel: Panel, ticket: Ticket, owner_name: str) -> int: ...
    async def add_ticket_member(self, channel_id: int, user_id: int) -> bool: ...
    async def find_ticket_channel(self, guild_id: int, ticket_id: int) -> Optional[int]: ...
    async def list_marked_channels(self, guild_id: int) -> list[tuple[int, int]]: ...
    async def channel_exists(self, channel_id: int) -> bool: ...
    async def delete_channel(self, channel_id: int, reason: str) -> None: ...
    async def send_control_message(self, ticket: Ticket, panel: Panel) -> int: ...
    async def update_control_message(self, ticket: Ticket, panel: Panel) -> None: ...
    async def set_channel_locked(self, ticket: Ticket, roles: PanelRoles, locked: bool) -> None: ...
    async def post_notice(self, channel_id: int, text: str, *, mention_role_ids: Sequence[int] = (),
                          mention_user_ids: Sequence[int] = (), ack_archive_id: Optional[int] = None,
                          join_ticket_id: Optional[int] = None) -> None: ...
    async def collect_transcript(self, ticket: Ticket, panel: Panel, attachment_budget: int) -> TranscriptCollection: ...
    async def human_messages_after(self, channel_id: int, message_id: int) -> bool: ...
    async def upload_limit(self, guild_id: int) -> int: ...
    async def upload_log_copy(self, log_channel_id: int, filename: str, data: bytes, summary: dict[str, Any],
                              marker: str) -> int: ...
    async def find_log_copy(self, log_channel_id: int, marker: str) -> Optional[int]: ...
    async def download_log_copy(self, log_channel_id: int, message_id: int) -> Optional[bytes]: ...
    async def send_dm(self, user_id: int, text: str) -> None: ...
    async def member_present(self, guild_id: int, user_id: int) -> bool: ...
    async def check_panel_resources(self, panel: Panel) -> list[str]: ...


# =============================================================================
# 9. SERVICES (business logic; Discord only through Gateway)
# =============================================================================

MSG: dict[str, str] = {
    "panel_unavailable": "هذه البانل غير متاحة.",
    "stale_panel": "رسالة البانل هذه قديمة. استخدم أحدث رسالة بانل في السيرفر.",
    "panel_paused": "هذه البانل متوقفة مؤقتًا. حاول لاحقًا.",
    "panel_misconfigured": "إعدادات هذه البانل تحتاج مراجعة من الإدارة. حاول لاحقًا.",
    "duplicate": "لديك تيكت مفتوح بالفعل في هذه البانل: {where}",
    "panel_limit": "تم الوصول إلى الحد الأقصى للتيكتات المفتوحة في هذه البانل. حاول لاحقًا.",
    "db_error": "حدث خطأ داخلي أثناء حفظ البيانات. حاول بعد قليل.",
    "create_rate_limited": ("⏳ Discord أوقف مؤقتًا إنشاء قنوات جديدة في هذا السيرفر (حد من Discord نفسه، وليس خطأ في "
                            "إعداداتك). حاول مرة أخرى <t:{until}:R>."),
    "created_thread": ("✅ تم إنشاء تيكتك: <#{channel}>\n(فُتح كـ Thread خاص لأن Discord يقيّد إنشاء القنوات حاليًا، "
                       "ولا يراه إلا أنت والإدارة.)"),
    "category_full": "الكاتيجوري ممتلئة (حد Discord هو 50 قناة). أبلغ الإدارة.",
    "thread_join_notice": ("🧵 تيكت جديد #{number:04d} من <@{owner}> فُتح كـ **Thread خاص**: <#{channel}>\n"
                           "اضغط الزر للانضمام (للستاف فقط)."),
    "thread_fallback_admin": ("⚠️ **تنبيه للإدارة:** Discord يرفض إنشاء قنوات جديدة ({reason}). التيكتات الجديدة تُفتح الآن "
                              "كـ **Threads خاصة** داخل قناة البانل، ويصلكم هنا زر انضمام لكل تيكت."),
    "thread_fallback_unavailable": ("⛔ **تنبيه للإدارة:** تعذّر فتح التيكت كـ Thread خاص بدلًا من القناة ({detail}). "
                                    "امنح البوت في قناة البانل: Create Private Threads و Send Messages in Threads "
                                    "و Manage Threads."),
    "joined": "✅ تمت إضافتك إلى التيكت: <#{channel}>",
    "join_not_needed": "التيكت قناة عادية وأنت ترى القنوات بالفعل: <#{channel}>",
    "join_failed": "تعذّرت إضافتك الآن ({kind}). حاول مرة أخرى بعد قليل.",
    "create_rate_limited_admin": ("⏳ **تنبيه للإدارة:** Discord رفض إنشاء قنوات تيكت جديدة في هذا السيرفر حتى <t:{until}:F> "
                                  "(<t:{until}:R>). السبب حد معدّل من Discord على إنشاء القنوات، وليس صلاحيات البوت. "
                                  "التيكتات الحالية تعمل طبيعيًا. البوت لن يحاول الإنشاء قبل هذا الوقت."),
    "channel_failed_temporary": "تعذّر إنشاء قناة التيكت بسبب ضغط مؤقت على Discord. حاول مرة أخرى بعد دقيقة.",
    "channel_failed": "تعذّر إنشاء قناة التيكت (صلاحيات أو إعدادات ناقصة). تم تسجيل المشكلة للإدارة.",
    "uncertain": ("تعذّر التأكد من إنشاء التيكت بسبب مشكلة مؤقتة في Discord. سيتم التحقق تلقائيًا خلال دقائق؛ "
                  "لا داعي للضغط مجددًا."),
    "created": "✅ تم إنشاء تيكتك: <#{channel}>",
    "stale": "هذا الزر قديم أو لا يخص هذه القناة.",
    "not_found": "التيكت غير موجود.",
    "forbidden": "⛔ ليست لديك صلاحية لهذا الإجراء.",
    "bad_state": "لا يمكن تنفيذ هذا الإجراء والتيكت في حالة: {state}",
    "already_claimed": "هذا التيكت مستلم بالفعل بواسطة <@{user}>.",
    "claimed": "🙋 استلم <@{user}> هذا التيكت.",
    "held": "⏸️ تم تعليق التيكت (Hold) بواسطة <@{user}>. عدادات الأتمتة متوقفة.",
    "resumed": "▶️ تم استئناف التيكت بواسطة <@{user}>. استؤنفت العدادات من حيث توقفت.",
    "closing": "🔒 تم طلب الإغلاق ({who}). جارٍ إنشاء الأرشيف — لن تُحذف القناة قبل التحقق من النسختين.",
    "close_ok": "تم بدء إغلاق التيكت وأرشفته.",
    "reopened": "🔓 أُعيد فتح التيكت بواسطة <@{user}>.",
    "reopen_conflict": "لا يمكن إعادة الفتح: صاحب التيكت لديه تيكت نشط آخر في هذه البانل.",
    "race": "تغيّرت حالة التيكت أثناء المعالجة. أعد المحاولة.",
    "ok": "تم.",
    "inactivity_warning": ("⏰ <@{user}> لم يصلنا ردك. سيُغلق التيكت تلقائيًا <t:{deadline}:R> إن لم ترد. "
                           "أرسل أي رسالة لإبقائه مفتوحًا."),
    "sla_breach": "🚨 تجاوز التيكت مهلة أول رد للستاف ({minutes} دقيقة). يرجى الرد.",
    "escalation": "📣 تصعيد: التيكت #{number} بلا رد من الستاف منذ فتحه.",
    "archive_failed_notice": ("⚠️ تعذّر إكمال الأرشفة بعد (اللوج: {log}، المحلي: {local}). القناة محفوظة وستُعاد "
                              "المحاولة تلقائيًا."),
    "archive_blocked_notice": ("⚠️ الأرشيف ناقص: {reason}. لن تُحذف القناة. يمكن لأدمن البانل الإقرار "
                               "والمتابعة بالضغط على الزر أدناه (سيُذكر النقص داخل الـ Transcript)."),
    "ack_ok": "تم تسجيل الإقرار. ستُستأنف الأرشفة الآن.",
    "dm_summary": ("📪 تم إغلاق تيكتك رقم #{number} ({panel}).\nالحالة: مغلق\nوقت الإغلاق: <t:{closed_at}:F>\n"
                   "(هذه رسالة ملخص فقط؛ لا تحتوي على نص المحادثة.)"),
    "lost": "⚠️ قناة التيكت #{number} حُذفت يدويًا؛ تم وضع التيكت في حالة LOST.",
    "panel_problem": "⚠️ البانل \"{name}\" أصبحت بحاجة لمراجعة: {problems}",
}


@dataclass
class OpResult:
    ok: bool
    code: str
    message: str
    ticket: Optional[Ticket] = None


def _fail(code: str, **fmt: Any) -> OpResult:
    return OpResult(False, code, MSG[code].format(**fmt) if fmt else MSG[code])


@dataclass
class JobOutcome:
    status: str  # "done" | "retry" | "reschedule" | "failed"
    run_at: Optional[int] = None
    error: Optional[str] = None


JOB_DONE = JobOutcome("done")


def backoff_delay(attempts: int) -> int:
    return int(min(RETRY_MAX_SECONDS, RETRY_BASE_SECONDS * (2 ** max(0, attempts - 1))))


async def best_effort(coro: Awaitable[Any], what: str) -> bool:
    """Await a non-critical Discord call; log failures instead of propagating."""
    try:
        await coro
        return True
    except GatewayError as exc:
        log.warning("best_effort.failed what=%s kind=%s detail=%s", what, exc.kind, exc.detail)
        return False


TIMER_JOB_KINDS = ("inactivity", "sla", "escalation")


class TicketService:
    """Ticket lifecycle: open, claim, hold, close, reopen, activity, loss."""

    def __init__(self, db: Database, gateway: Gateway, clock: Clock = now_ts) -> None:
        self.db, self.gw, self.clock = db, gateway, clock
        self._open_locks: dict[tuple[int, int, int], asyncio.Lock] = {}
        # guild_id -> unix time until which Discord refuses channel creation (long rate limit).
        # While blocked we do not call the API at all (no hammering, no wasted ticket numbers).
        self._create_blocked_until: dict[int, int] = {}
        self._fallback_warned: set[int] = set()  # panel ids already warned about missing thread permissions

    def creation_blocked_until(self, guild_id: int) -> Optional[int]:
        until = self._create_blocked_until.get(guild_id)
        if until is None:
            return None
        if until <= self.clock():
            del self._create_blocked_until[guild_id]
            return None
        return until

    # ----------------------------------------------------------- helpers
    def _lock_for(self, key: tuple[int, int, int]) -> asyncio.Lock:
        if len(self._open_locks) > 10_000:
            for k in [k for k, v in self._open_locks.items() if not v.locked()]:
                self._open_locks.pop(k, None)
        return self._open_locks.setdefault(key, asyncio.Lock())

    def _load(self, ticket_id: int, guild_id: int, channel_id: Optional[int]) -> tuple[Ticket, Panel, PanelRoles] | OpResult:
        """Re-validate ticket identity against the interaction (never trust custom_id alone)."""
        ticket = self.db.get_ticket(ticket_id)
        if ticket is None:
            return _fail("not_found")
        if ticket.guild_id != guild_id or (channel_id is not None and ticket.channel_id != channel_id):
            return _fail("stale")
        panel = self.db.get_panel(ticket.panel_id)
        if panel is None:
            return _fail("not_found")
        return ticket, panel, self.db.panel_roles(panel.id)

    async def refresh_control(self, ticket_id: int) -> None:
        ticket = self.db.get_ticket(ticket_id)
        if ticket and ticket.control_message_id and ticket.state in (S_OPEN, S_ON_HOLD, S_CLOSING):
            panel = self.db.get_panel(ticket.panel_id)
            if panel:
                await best_effort(self.gw.update_control_message(ticket, panel), "update_control")

    def sync_jobs(self, ticket_id: int) -> None:
        """Make scheduled timer jobs match the ticket's persisted deadlines."""
        ticket = self.db.get_ticket(ticket_id)
        if ticket is None:
            return
        panel = self.db.get_panel(ticket.panel_id)
        if ticket.state != S_OPEN or panel is None:
            for kind in TIMER_JOB_KINDS:
                self.db.cancel_job(f"{kind}:{ticket.id}")
            if ticket.state != S_ON_HOLD:
                self.db.cancel_job(f"owner_presence:{ticket.id}")
            return
        common = {"guild_id": ticket.guild_id, "ticket_id": ticket.id}
        if panel.inactivity_enabled and ticket.inactivity_deadline is not None:
            run_at = ticket.inactivity_deadline if ticket.inactivity_warned else \
                ticket.inactivity_deadline - panel.inactivity_warning_min * 60
            self.db.schedule_job("inactivity", f"inactivity:{ticket.id}", run_at, **common)
        else:
            self.db.cancel_job(f"inactivity:{ticket.id}")
        for kind in ("sla", "escalation"):
            deadline = getattr(ticket, f"{kind}_deadline")
            if deadline is not None:
                self.db.schedule_job(kind, f"{kind}:{ticket.id}", deadline, **common)
            else:
                self.db.cancel_job(f"{kind}:{ticket.id}")
        if panel.close_on_owner_leave:
            self.db.schedule_job("owner_presence", f"owner_presence:{ticket.id}",
                                 self.clock() + OWNER_PRESENCE_INTERVAL, keep_existing=True, **common)
        else:
            self.db.cancel_job(f"owner_presence:{ticket.id}")

    def _safe_sync(self, ticket_id: int) -> None:
        try:
            self.sync_jobs(ticket_id)
        except sqlite3.Error:
            log.exception("jobs.sync_failed ticket=%s", ticket_id)

    # -------------------------------------------------------------- open
    async def open_ticket(self, guild_id: int, panel_id: int, owner_id: int, owner_name: str,
                          panel_message_id: Optional[int] = None) -> OpResult:
        """Open a ticket safely (DB row first, then channel, then OPEN)."""
        panel = self.db.get_panel(panel_id)
        if panel is None or panel.guild_id != guild_id or panel.status in ("ARCHIVED", "DELETED"):
            return _fail("panel_unavailable")
        if panel_message_id is not None and panel.panel_message_id != panel_message_id:
            return _fail("stale_panel")
        if panel.status == "PAUSED":
            return _fail("panel_paused")
        if panel.status == "MISCONFIGURED":
            return _fail("panel_misconfigured")
        blocked_until = self.creation_blocked_until(guild_id)
        if blocked_until is not None and not THREAD_FALLBACK_ENABLED:
            existing = self.db.get_active_ticket(guild_id, panel_id, owner_id)
            if existing:
                return self._duplicate(existing)
            return _fail("create_rate_limited", until=blocked_until)
        async with self._lock_for((guild_id, panel_id, owner_id)):
            existing = self.db.get_active_ticket(guild_id, panel_id, owner_id)
            if existing:
                return self._duplicate(existing)
            try:
                ticket = self.db.create_ticket(guild_id, panel_id, owner_id)
            except DuplicateActiveTicket:
                return self._duplicate(self.db.get_active_ticket(guild_id, panel_id, owner_id))
            except PanelLimitReached:
                return _fail("panel_limit")
            except sqlite3.Error:
                log.exception("ticket.create_record_failed guild=%s panel=%s", guild_id, panel_id)
                return _fail("db_error")
            roles = self.db.panel_roles(panel_id)
            channel_id: Optional[int] = None
            channel_exc: Optional[GatewayError] = None
            if blocked_until is None:  # while blocked, do not even ask Discord for a channel
                try:
                    channel_id = await self.gw.create_ticket_channel(panel, roles, ticket, owner_name)
                except GatewayError as exc:
                    reason = self._fallback_reason(exc)
                    if reason is None:
                        return await self._creation_failed(ticket, panel, exc)
                    channel_exc = exc
                    if reason == "rate_limited":
                        blocked_until = await self._record_channel_block(ticket, panel, exc)
                    else:
                        await self._warn_fallback_once(panel, reason)
            via_thread = channel_id is None
            if via_thread:
                try:
                    channel_id = await self.gw.create_ticket_thread(panel, ticket, owner_name)
                except GatewayError as texc:
                    return await self._thread_fallback_failed(ticket, panel, texc, blocked_until, channel_exc)
            now = self.clock()
            try:
                opened = self.db.transition(
                    ticket.id, (S_CREATING,), S_OPEN, actor_id=owner_id, event="ticket_opened",
                    updates={"channel_id": channel_id, "opened_at": now, "creation_uncertain": 0,
                             **timers_on_open(panel, now)},
                    details={"container": "thread" if via_thread else "channel"})
            except sqlite3.Error:
                log.exception("ticket.open_commit_failed ticket=%s", ticket.id)
                await self._compensate(ticket, channel_id)
                return _fail("db_error")
            if opened is None:
                current = self.db.get_ticket(ticket.id)
                if not (current and current.state == S_OPEN and current.channel_id == channel_id):
                    await self._compensate(ticket, channel_id)
                    return _fail("race")
                opened = current
            await self._after_open(opened, panel)
            if via_thread:
                await best_effort(self.gw.post_notice(
                    panel.log_channel_id,
                    MSG["thread_join_notice"].format(number=opened.number, owner=opened.owner_id, channel=channel_id),
                    mention_role_ids=sorted(roles.staff), join_ticket_id=opened.id), "thread_join_notice")
                return OpResult(True, "created_thread", MSG["created_thread"].format(channel=channel_id), opened)
            return OpResult(True, "created", MSG["created"].format(channel=channel_id), opened)

    # ------------------------------------------------------ thread fallback
    @staticmethod
    def _fallback_reason(exc: GatewayError) -> Optional[str]:
        """Which channel-creation failures switch this ticket to a private thread."""
        if not THREAD_FALLBACK_ENABLED:
            return None
        if exc.kind == GatewayError.TRANSIENT and exc.retry_after and exc.retry_after > 60:
            return "rate_limited"
        if exc.detail in ("category_full", "guild_channel_limit"):
            return exc.detail
        return None

    async def _record_channel_block(self, ticket: Ticket, panel: Panel, exc: GatewayError) -> int:
        """Remember a long channel-creation rate limit for the guild and tell admins once."""
        now = self.clock()
        until = now + int(math.ceil(exc.retry_after or 0))
        first = self.creation_blocked_until(ticket.guild_id) is None
        self._create_blocked_until[ticket.guild_id] = until
        log.warning("ticket.channel_create_rate_limited guild=%s ticket=%s until=%s (%.0fs)",
                    ticket.guild_id, ticket.id, until, exc.retry_after or 0)
        if first:
            text = MSG["create_rate_limited_admin"].format(until=until)
            if THREAD_FALLBACK_ENABLED:
                text += "\n" + MSG["thread_fallback_admin"].format(reason="حد معدّل مؤقت")
            await best_effort(self.gw.post_notice(panel.log_channel_id, text), "rate_limit_notice")
        return until

    async def _warn_fallback_once(self, panel: Panel, reason: str) -> None:
        key = -panel.id  # negative keys: "fallback active" notices; positive: "fallback unavailable"
        if key in self._fallback_warned:
            return
        self._fallback_warned.add(key)
        label = "الكاتيجوري ممتلئة (50 قناة)" if reason == "category_full" else "السيرفر وصل لحد 500 قناة"
        await best_effort(self.gw.post_notice(panel.log_channel_id, MSG["thread_fallback_admin"].format(reason=label)),
                          "fallback_notice")

    async def _thread_fallback_failed(self, ticket: Ticket, panel: Panel, texc: GatewayError,
                                      blocked_until: Optional[int], channel_exc: Optional[GatewayError]) -> OpResult:
        """The private-thread fallback failed too. Never marks the panel MISCONFIGURED for this."""
        if texc.kind == GatewayError.UNCERTAIN:
            return await self._creation_failed(ticket, panel, texc)  # reconciliation adopts it if it exists
        try:
            self.db.transition(ticket.id, (S_CREATING,), S_FAILED, event="creation_failed",
                               details={"kind": texc.kind, "detail": texc.detail, "container": "thread"})
        except sqlite3.Error:
            log.exception("ticket.creation_failure_record_failed ticket=%s", ticket.id)
        log.warning("ticket.thread_fallback_failed ticket=%s kind=%s detail=%s", ticket.id, texc.kind, texc.detail)
        if texc.kind in (GatewayError.FORBIDDEN, GatewayError.NOT_FOUND, GatewayError.INVALID) \
                and panel.id not in self._fallback_warned:
            self._fallback_warned.add(panel.id)
            await best_effort(self.gw.post_notice(panel.log_channel_id, MSG["thread_fallback_unavailable"].format(
                detail=texc.detail or texc.kind)), "fallback_unavailable_notice")
        if blocked_until is not None:
            return _fail("create_rate_limited", until=blocked_until)
        if channel_exc is not None and channel_exc.detail in ("category_full", "guild_channel_limit"):
            return _fail("category_full")
        return _fail("channel_failed_temporary" if texc.kind == GatewayError.TRANSIENT else "channel_failed")

    async def join_ticket(self, ticket_id: int, actor: Actor, guild_id: int) -> OpResult:
        """Staff joins a private-thread ticket (button in the log channel). Re-validated server-side."""
        ctx = self._load(ticket_id, guild_id, None)
        if isinstance(ctx, OpResult):
            return ctx
        ticket, _panel, roles = ctx
        if not is_staff(actor, roles):
            return _fail("forbidden")
        if ticket.state not in (S_OPEN, S_ON_HOLD, S_CLOSING) or not ticket.channel_id:
            return _fail("bad_state", state=STATE_LABELS.get(ticket.state, ticket.state))
        try:
            added = await self.gw.add_ticket_member(ticket.channel_id, actor.user_id)
        except GatewayError as exc:
            log.warning("ticket.join_failed ticket=%s kind=%s", ticket.id, exc.kind)
            return _fail("join_failed", kind=exc.kind)
        if added is False:
            return OpResult(True, "join_not_needed", MSG["join_not_needed"].format(channel=ticket.channel_id), ticket)
        with contextlib.suppress(sqlite3.Error):
            self.db.add_event(ticket.guild_id, "staff_joined", ticket_id=ticket.id, actor_id=actor.user_id)
        return OpResult(True, "joined", MSG["joined"].format(channel=ticket.channel_id), ticket)

    def _duplicate(self, existing: Optional[Ticket]) -> OpResult:
        if existing and existing.channel_id:
            where = f"<#{existing.channel_id}>"
        else:
            where = "(قيد الإنشاء — انتظر قليلًا)"
        return OpResult(False, "duplicate", MSG["duplicate"].format(where=where), existing)

    async def _creation_failed(self, ticket: Ticket, panel: Panel, exc: GatewayError) -> OpResult:
        now = self.clock()
        try:
            if exc.kind == GatewayError.UNCERTAIN:
                self.db.update_ticket_if(ticket.id, (S_CREATING,), {"creation_uncertain": 1},
                                         event="creation_uncertain", details={"detail": exc.detail})
                self.db.schedule_job("reconcile_ticket", f"reconcile:{ticket.id}", now + CREATION_RECONCILE_DELAY,
                                     guild_id=ticket.guild_id, ticket_id=ticket.id)
                return _fail("uncertain")
            self.db.transition(ticket.id, (S_CREATING,), S_FAILED, event="creation_failed",
                               details={"kind": exc.kind, "detail": exc.detail})
            if exc.kind == GatewayError.TRANSIENT and exc.retry_after and exc.retry_after > 60:
                until = await self._record_channel_block(ticket, panel, exc)
                return _fail("create_rate_limited", until=until)
            if exc.kind in (GatewayError.NOT_FOUND, GatewayError.FORBIDDEN):
                if self.db.set_panel_status(panel.id, "MISCONFIGURED", expected=("ACTIVE",), reason=exc.detail):
                    await best_effort(self.gw.post_notice(panel.log_channel_id, MSG["panel_problem"].format(
                        name=panel.name, problems=exc.detail or exc.kind)), "panel_problem_notice")
        except sqlite3.Error:
            log.exception("ticket.creation_failure_record_failed ticket=%s", ticket.id)
        log.warning("ticket.channel_create_failed ticket=%s kind=%s detail=%s", ticket.id, exc.kind, exc.detail)
        if exc.kind == GatewayError.TRANSIENT:
            return _fail("channel_failed_temporary")
        return _fail("channel_failed")

    async def _compensate(self, ticket: Ticket, channel_id: int) -> None:
        """Undo a created channel when the DB could not record it (avoid orphans)."""
        try:
            await self.gw.delete_channel(channel_id, f"Tazkara: compensating failed ticket {ticket.id}")
        except GatewayError as exc:
            log.error("ticket.compensation_failed ticket=%s channel=%s kind=%s — reconciliation will adopt it",
                      ticket.id, channel_id, exc.kind)
            return
        try:
            self.db.transition(ticket.id, (S_CREATING,), S_FAILED, event="creation_compensated")
        except sqlite3.Error:
            log.exception("ticket.mark_failed_failed ticket=%s (reconciliation will resolve)", ticket.id)

    async def _after_open(self, ticket: Ticket, panel: Panel) -> None:
        try:
            message_id = await self.gw.send_control_message(ticket, panel)
            self.db.update_ticket_if(ticket.id, (S_OPEN, S_ON_HOLD), {"control_message_id": message_id})
        except GatewayError as exc:
            log.warning("ticket.control_message_failed ticket=%s kind=%s", ticket.id, exc.kind)
            with contextlib.suppress(sqlite3.Error):
                self.db.schedule_job("reconcile_ticket", f"reconcile:{ticket.id}", self.clock() + CREATION_RECONCILE_DELAY,
                                     guild_id=ticket.guild_id, ticket_id=ticket.id)
        except sqlite3.Error:
            log.exception("ticket.control_message_record_failed ticket=%s", ticket.id)
        self._safe_sync(ticket.id)

    # ------------------------------------------------------- staff actions
    async def claim(self, ticket_id: int, actor: Actor, guild_id: int, channel_id: Optional[int]) -> OpResult:
        ctx = self._load(ticket_id, guild_id, channel_id)
        if isinstance(ctx, OpResult):
            return ctx
        ticket, _panel, roles = ctx
        if not is_allowed(A_CLAIM, actor, ticket, roles):
            return _fail("forbidden")
        if ticket.state not in (S_OPEN, S_ON_HOLD):
            return _fail("bad_state", state=STATE_LABELS[ticket.state])
        if ticket.claimed_by:
            return _fail("already_claimed", user=ticket.claimed_by)
        updated = self.db.update_ticket_if(ticket.id, (S_OPEN, S_ON_HOLD),
                                           {"claimed_by": actor.user_id, "claimed_at": self.clock()},
                                           expected={"claimed_by": None}, event="ticket_claimed", actor_id=actor.user_id)
        if updated is None:
            current = self.db.get_ticket(ticket.id)
            if current and current.claimed_by:
                return _fail("already_claimed", user=current.claimed_by)
            return _fail("race")
        await self.refresh_control(ticket.id)
        await best_effort(self.gw.post_notice(ticket.channel_id, MSG["claimed"].format(user=actor.user_id)), "claim_notice")
        return OpResult(True, "claimed", MSG["claimed"].format(user=actor.user_id), updated)

    async def toggle_hold(self, ticket_id: int, actor: Actor, guild_id: int, channel_id: Optional[int]) -> OpResult:
        ctx = self._load(ticket_id, guild_id, channel_id)
        if isinstance(ctx, OpResult):
            return ctx
        ticket, _panel, roles = ctx
        if not is_allowed(A_HOLD, actor, ticket, roles):
            return _fail("forbidden")
        now = self.clock()
        if ticket.state == S_OPEN:
            updated = self.db.transition(ticket.id, (S_OPEN,), S_ON_HOLD, actor_id=actor.user_id, event="ticket_hold",
                                         updates=timers_pause(ticket, now), expected={"version": ticket.version})
            key = "held"
        elif ticket.state == S_ON_HOLD:
            updated = self.db.transition(ticket.id, (S_ON_HOLD,), S_OPEN, actor_id=actor.user_id, event="ticket_resumed",
                                         updates=timers_resume(ticket, now), expected={"version": ticket.version})
            key = "resumed"
        else:
            return _fail("bad_state", state=STATE_LABELS[ticket.state])
        if updated is None:
            return _fail("race")
        self._safe_sync(ticket.id)
        await self.refresh_control(ticket.id)
        text = MSG[key].format(user=actor.user_id)
        await best_effort(self.gw.post_notice(ticket.channel_id, text), "hold_notice")
        return OpResult(True, key, text, updated)

    def check_close(self, ticket_id: int, actor: Actor, guild_id: int, channel_id: Optional[int]) -> OpResult:
        """Pre-check used before showing the confirmation dialog (re-checked on confirm)."""
        ctx = self._load(ticket_id, guild_id, channel_id)
        if isinstance(ctx, OpResult):
            return ctx
        ticket, _panel, roles = ctx
        if not is_allowed(A_CLOSE, actor, ticket, roles):
            return _fail("forbidden")
        if ticket.state not in (S_OPEN, S_ON_HOLD):
            return _fail("bad_state", state=STATE_LABELS[ticket.state])
        return OpResult(True, "ok", MSG["ok"], ticket)

    async def request_close(self, ticket_id: int, actor: Actor, guild_id: int, channel_id: Optional[int], reason: str,
                            *, from_states: Sequence[str] = (S_OPEN, S_ON_HOLD),
                            expected: Optional[dict[str, Any]] = None) -> OpResult:
        """OPEN/ON_HOLD -> CLOSING and enqueue the archive job. The channel is NOT deleted here."""
        ctx = self._load(ticket_id, guild_id, channel_id)
        if isinstance(ctx, OpResult):
            return ctx
        ticket, _panel, roles = ctx
        if not is_allowed(A_CLOSE, actor, ticket, roles):
            return _fail("forbidden")
        if ticket.state not in from_states:
            return _fail("bad_state", state=STATE_LABELS[ticket.state])
        now = self.clock()
        held = (now - ticket.hold_started_at) if (ticket.state == S_ON_HOLD and ticket.hold_started_at) else 0
        updates = {"close_seq": ticket.close_seq + 1, "closed_by": actor.user_id or None,
                   "close_reason": clean_text(reason)[:200] or None, "close_requested_at": now,
                   "hold_started_at": None, "total_hold_seconds": ticket.total_hold_seconds + max(0, held),
                   **timers_cleared()}
        updated = self.db.transition(ticket.id, tuple(from_states), S_CLOSING, actor_id=actor.user_id,
                                     event="ticket_closing", updates=updates,
                                     expected={"version": ticket.version, **(expected or {})},
                                     details={"reason": updates["close_reason"]})
        if updated is None:
            return _fail("race")
        self._safe_sync(ticket.id)
        self.db.schedule_job("archive", f"archive:{ticket.id}", now, guild_id=ticket.guild_id, ticket_id=ticket.id,
                             max_attempts=1_000_000)
        await self.refresh_control(ticket.id)
        who = "النظام" if actor.is_system else f"<@{actor.user_id}>"
        await best_effort(self.gw.post_notice(ticket.channel_id, MSG["closing"].format(who=who)), "closing_notice")
        return OpResult(True, "closing", MSG["close_ok"], updated)

    async def reopen(self, ticket_id: int, actor: Actor, guild_id: int, channel_id: Optional[int]) -> OpResult:
        """CLOSING -> OPEN (staff only), superseding any in-progress archive."""
        ctx = self._load(ticket_id, guild_id, channel_id)
        if isinstance(ctx, OpResult):
            return ctx
        ticket, _panel, roles = ctx
        if not is_allowed(A_REOPEN, actor, ticket, roles):
            return _fail("forbidden")
        if ticket.state != S_CLOSING:
            return _fail("bad_state", state=STATE_LABELS[ticket.state])
        updates = {"closed_by": None, "close_reason": None, "close_requested_at": None, **timers_cleared()}
        try:
            with self.db.tx() as c:
                before = self.db._transition_in(c, ticket.id, (S_CLOSING,), S_OPEN, updates, {"version": ticket.version})
                if before is None:
                    raise _Rollback()
                self.db.supersede_live_archives(ticket.id, conn=c)
                self.db.add_event(ticket.guild_id, "ticket_reopened", ticket_id=ticket.id, panel_id=ticket.panel_id,
                                  actor_id=actor.user_id, from_state=S_CLOSING, to_state=S_OPEN, conn=c)
        except _Rollback:
            return _fail("race")
        except sqlite3.IntegrityError as exc:
            if "tazkara:panel_limit" in str(exc):
                return _fail("panel_limit")
            return _fail("reopen_conflict")
        self.db.cancel_job(f"archive:{ticket.id}")
        await best_effort(self.gw.set_channel_locked(ticket, roles, False), "unlock_channel")
        self._safe_sync(ticket.id)
        await self.refresh_control(ticket.id)
        text = MSG["reopened"].format(user=actor.user_id)
        await best_effort(self.gw.post_notice(ticket.channel_id, text), "reopen_notice")
        return OpResult(True, "reopened", text, self.db.get_ticket(ticket.id))

    # ---------------------------------------------------- activity & loss
    def record_activity(self, channel_id: int, author_id: int, role_ids: Iterable[int], is_manager: bool) -> None:
        """Apply the activity definition (owner vs staff message) to the timers."""
        for _ in range(2):  # one retry on optimistic-lock conflict
            ticket = self.db.get_ticket_by_channel(channel_id)
            if ticket is None or ticket.state not in (S_OPEN, S_ON_HOLD):
                return
            panel = self.db.get_panel(ticket.panel_id)
            if panel is None:
                return
            actor = Actor(author_id, frozenset(role_ids), is_manager)
            if author_id == ticket.owner_id:
                updates = timers_on_owner_message(ticket)
            elif is_staff(actor, self.db.panel_roles(panel.id)):
                updates = timers_on_staff_message(ticket, panel, self.clock())
            else:
                return
            if not updates:
                return
            if self.db.update_ticket_if(ticket.id, (ticket.state,), updates, expected={"version": ticket.version}):
                self._safe_sync(ticket.id)
                return

    def mark_lost(self, ticket: Ticket, reason: str) -> Optional[Ticket]:
        """Ticket channel vanished: move to LOST, keep any partial archive (never delete it)."""
        try:
            with self.db.tx() as c:
                before = self.db._transition_in(c, ticket.id, (S_CREATING, S_OPEN, S_ON_HOLD, S_CLOSING), S_LOST,
                                                {"channel_deleted": 1, **timers_cleared()}, {})
                if before is None:
                    raise _Rollback()
                self.db.supersede_live_archives(ticket.id, conn=c)
                self.db.add_event(ticket.guild_id, "ticket_lost", ticket_id=ticket.id, panel_id=ticket.panel_id,
                                  from_state=before["state"], to_state=S_LOST, details={"reason": reason}, conn=c)
        except _Rollback:
            return None
        for job in self.db.pending_jobs(ticket.id):
            self.db.cancel_job(job.dedupe_key)
        log.warning("ticket.lost ticket=%s reason=%s", ticket.id, reason)
        return self.db.get_ticket(ticket.id)

    async def handle_channel_deleted(self, channel_id: int) -> None:
        ticket = self.db.get_ticket_by_channel(channel_id)
        if ticket is None:
            return
        if ticket.state == S_CLOSED:
            self.db.update_ticket_if(ticket.id, (S_CLOSED,), {"channel_deleted": 1})
            self.db.cancel_job(f"delete_channel:{ticket.id}")
            return
        if ticket.state in (S_CREATING, S_OPEN, S_ON_HOLD, S_CLOSING) and self.mark_lost(ticket, "channel_deleted_manually"):
            panel = self.db.get_panel(ticket.panel_id)
            if panel:
                await best_effort(self.gw.post_notice(panel.log_channel_id, MSG["lost"].format(number=ticket.number)),
                                  "lost_notice")


class AutomationService:
    """Scheduled handlers for inactivity, SLA, escalation and owner-left."""

    def __init__(self, db: Database, gateway: Gateway, tickets: TicketService, clock: Clock = now_ts) -> None:
        self.db, self.gw, self.tickets, self.clock = db, gateway, tickets, clock

    def _ctx(self, job: Job) -> Optional[tuple[Ticket, Panel]]:
        ticket = self.db.get_ticket(job.ticket_id) if job.ticket_id else None
        if ticket is None or ticket.state != S_OPEN:
            return None  # ON_HOLD/closed: nothing to do (resume re-schedules)
        panel = self.db.get_panel(ticket.panel_id)
        return (ticket, panel) if panel else None

    async def handle_inactivity(self, job: Job) -> JobOutcome:
        ctx = self._ctx(job)
        if ctx is None:
            return JOB_DONE
        ticket, panel = ctx
        if not panel.inactivity_enabled or ticket.inactivity_deadline is None:
            return JOB_DONE
        now, deadline = self.clock(), ticket.inactivity_deadline
        warning = panel.inactivity_warning_min * 60
        if not ticket.inactivity_warned:
            if now < deadline - warning:
                return JobOutcome("reschedule", deadline - warning)
            new_deadline = max(deadline, now + warning)  # a warning always precedes the close
            updated = self.db.update_ticket_if(ticket.id, (S_OPEN,), {"inactivity_warned": 1, "inactivity_deadline": new_deadline},
                                               expected={"inactivity_deadline": deadline, "inactivity_warned": 0},
                                               event="inactivity_warning")
            if updated is None:
                return JOB_DONE  # activity happened meanwhile; sync_jobs re-scheduled
            await best_effort(self.gw.post_notice(ticket.channel_id, MSG["inactivity_warning"].format(
                user=ticket.owner_id, deadline=new_deadline), mention_user_ids=[ticket.owner_id]), "inactivity_warning")
            return JobOutcome("reschedule", new_deadline)
        if now < deadline:
            return JobOutcome("reschedule", deadline)
        await self.tickets.request_close(ticket.id, SYSTEM_ACTOR, ticket.guild_id, None, "auto: customer inactivity",
                                         from_states=(S_OPEN,), expected={"inactivity_deadline": deadline})
        return JOB_DONE

    async def handle_sla(self, job: Job) -> JobOutcome:
        ctx = self._ctx(job)
        if ctx is None:
            return JOB_DONE
        ticket, panel = ctx
        if not panel.sla_enabled or ticket.first_response_at or ticket.sla_deadline is None or ticket.sla_breached_at:
            return JOB_DONE
        now = self.clock()
        if now < ticket.sla_deadline:
            return JobOutcome("reschedule", ticket.sla_deadline)
        escalate_now = bool(panel.escalation_role_id) and panel.escalation_after_min == 0
        updates: dict[str, Any] = {"sla_breached_at": now, "sla_deadline": None}
        if panel.escalation_role_id and panel.escalation_after_min > 0:
            updates["escalation_deadline"] = now + panel.escalation_after_min * 60
        if escalate_now:
            updates["escalated_at"] = now
        updated = self.db.update_ticket_if(ticket.id, (S_OPEN,), updates,
                                           expected={"sla_deadline": ticket.sla_deadline, "first_response_at": None},
                                           event="sla_breached")
        if updated is None:
            return JOB_DONE
        roles = self.db.panel_roles(panel.id)
        text = MSG["sla_breach"].format(minutes=panel.sla_first_response_min)
        await best_effort(self.gw.post_notice(ticket.channel_id, text, mention_role_ids=sorted(roles.staff)), "sla_notice")
        await best_effort(self.gw.post_notice(panel.log_channel_id, f"{text} (#{ticket.number}, <#{ticket.channel_id}>)"),
                          "sla_log_notice")
        if escalate_now:
            await self._escalate(ticket, panel)
        self.tickets._safe_sync(ticket.id)
        return JOB_DONE

    async def handle_escalation(self, job: Job) -> JobOutcome:
        ctx = self._ctx(job)
        if ctx is None:
            return JOB_DONE
        ticket, panel = ctx
        if not panel.escalation_role_id or ticket.first_response_at or ticket.escalated_at or ticket.escalation_deadline is None:
            return JOB_DONE
        if self.clock() < ticket.escalation_deadline:
            return JobOutcome("reschedule", ticket.escalation_deadline)
        updated = self.db.update_ticket_if(ticket.id, (S_OPEN,), {"escalated_at": self.clock(), "escalation_deadline": None},
                                           expected={"escalation_deadline": ticket.escalation_deadline, "escalated_at": None},
                                           event="sla_escalated")
        if updated:
            await self._escalate(ticket, panel)
        return JOB_DONE

    async def _escalate(self, ticket: Ticket, panel: Panel) -> None:
        await best_effort(self.gw.post_notice(ticket.channel_id, MSG["escalation"].format(number=ticket.number),
                                              mention_role_ids=[panel.escalation_role_id]), "escalation_notice")

    async def handle_owner_presence(self, job: Job) -> JobOutcome:
        ticket = self.db.get_ticket(job.ticket_id) if job.ticket_id else None
        if ticket is None or ticket.state not in (S_OPEN, S_ON_HOLD):
            return JOB_DONE
        panel = self.db.get_panel(ticket.panel_id)
        if panel is None or not panel.close_on_owner_leave:
            return JOB_DONE
        if ticket.state == S_ON_HOLD:  # Hold suspends automation, including owner-left closing
            return JobOutcome("reschedule", self.clock() + OWNER_PRESENCE_INTERVAL)
        try:
            present = await self.gw.member_present(ticket.guild_id, ticket.owner_id)
        except GatewayError as exc:
            return JobOutcome("retry", self.clock() + backoff_delay(job.attempts), f"{exc.kind}")
        if present:
            return JobOutcome("reschedule", self.clock() + OWNER_PRESENCE_INTERVAL)
        await self.owner_left(ticket.guild_id, ticket.owner_id)
        return JOB_DONE

    async def owner_left(self, guild_id: int, user_id: int) -> None:
        """Close the owner's OPEN tickets in panels that enabled close-on-leave."""
        for ticket in self.db.tickets_for_owner(guild_id, user_id, (S_OPEN,)):
            panel = self.db.get_panel(ticket.panel_id)
            if panel and panel.close_on_owner_leave:
                await self.tickets.request_close(ticket.id, SYSTEM_ACTOR, guild_id, None, "auto: owner left the server",
                                                 from_states=(S_OPEN,))


class ArchiveService:
    """Dual-archive protocol (DESIGN.md §4). Never deletes a channel itself."""

    def __init__(self, db: Database, gateway: Gateway, vault: ArchiveVault, archive_dir: Path,
                 tickets: TicketService, clock: Clock = now_ts) -> None:
        self.db, self.gw, self.vault, self.archive_dir, self.tickets, self.clock = (
            db, gateway, vault, archive_dir, tickets, clock)

    def _retry(self, job: Job, error: str) -> JobOutcome:
        return JobOutcome("retry", self.clock() + backoff_delay(job.attempts), error)

    async def run(self, job: Job) -> JobOutcome:
        """One resumable archive pass for a CLOSING ticket."""
        ticket = self.db.get_ticket(job.ticket_id) if job.ticket_id else None
        if ticket is None or ticket.state != S_CLOSING:
            return JOB_DONE
        panel = self.db.get_panel(ticket.panel_id)
        roles = self.db.panel_roles(ticket.panel_id)
        try:
            exists = await self.gw.channel_exists(ticket.channel_id)
        except GatewayError as exc:
            return self._retry(job, f"channel_check:{exc.kind}")
        if not exists:
            if self.tickets.mark_lost(ticket, "channel_missing_during_archive"):
                await best_effort(self.gw.post_notice(panel.log_channel_id, MSG["lost"].format(number=ticket.number)),
                                  "lost_notice")
            return JOB_DONE
        await best_effort(self.gw.set_channel_locked(ticket, roles, True), "lock_channel")

        archive = self.db.get_live_archive(ticket.id) or self.db.create_archive(ticket.id, ticket.close_seq)
        if archive.status == "BLOCKED" and not archive.omissions_ack_by:
            return JOB_DONE  # waiting for an explicit admin acknowledgement

        html_bytes: Optional[bytes] = None
        had_verified = "VERIFIED" in (archive.log_status, archive.local_status)
        if archive.transcript_sha256 and archive.transcript_complete and (had_verified or archive.log_status == "SENDING"):
            try:
                html_bytes = await self._recover(archive)
            except GatewayError as exc:
                return self._retry(job, f"recover:{exc.kind}")
            if html_bytes is None and had_verified:
                self.db.update_archive(archive.id, status="SUPERSEDED")
                self.db.add_event(ticket.guild_id, "archive_recovery_failed", ticket_id=ticket.id,
                                  details={"archive_id": archive.id})
                archive = self.db.create_archive(ticket.id, ticket.close_seq)
            else:
                archive = self.db.get_archive(archive.id)
        if html_bytes is None:
            built = await self._build(ticket, panel, archive, job)
            if isinstance(built, JobOutcome):
                return built
            html_bytes = built
            archive = self.db.get_archive(archive.id)

        log_ok = archive.log_status == "VERIFIED" or await self._ensure_log_copy(ticket, panel, archive, html_bytes)
        local_ok = archive.local_status == "VERIFIED" or self._ensure_local_copy(ticket, archive, html_bytes)
        archive = self.db.get_archive(archive.id)
        if archive is None or archive.status != "PENDING_COPIES":
            return JOB_DONE  # superseded meanwhile (e.g. reopened)
        if not (log_ok and local_ok):
            await self._notify_once(f"archive:{archive.id}:fail_notice", [ticket.channel_id, panel.log_channel_id],
                                    MSG["archive_failed_notice"].format(log=archive.log_status, local=archive.local_status))
            return self._retry(job, f"copies log={archive.log_status} local={archive.local_status}")
        try:
            newer = await self.gw.human_messages_after(ticket.channel_id, archive.last_message_id or 0)
        except GatewayError as exc:
            return self._retry(job, f"newer_check:{exc.kind}")
        if newer:
            self.db.update_archive(archive.id, only_if_status=("PENDING_COPIES",), status="SUPERSEDED")
            self.db.add_event(ticket.guild_id, "archive_superseded_new_messages", ticket_id=ticket.id,
                              details={"archive_id": archive.id})
            return JobOutcome("reschedule", self.clock())
        if not self.db.complete_archive_and_close(ticket.id, archive.id):
            return JOB_DONE
        now = self.clock()
        self.db.schedule_job("delete_channel", f"delete_channel:{ticket.id}", now, guild_id=ticket.guild_id,
                             ticket_id=ticket.id, max_attempts=1_000_000)
        self.db.schedule_job("dm_owner", f"dm_owner:{ticket.id}:{ticket.close_seq}", now, guild_id=ticket.guild_id,
                             ticket_id=ticket.id, max_attempts=3)
        log.info("archive.complete ticket=%s archive=%s sha=%s", ticket.id, archive.id, archive.transcript_sha256[:16])
        return JOB_DONE

    async def _recover(self, archive: Archive) -> Optional[bytes]:
        """Re-obtain the exact transcript bytes from an existing copy (hash-verified)."""
        sha = archive.transcript_sha256 or ""
        if archive.local_status == "VERIFIED" and archive.local_path:
            try:
                return self.vault.read_verified(self.archive_dir / archive.local_path, sha, archive.local_cipher_sha256)
            except (OSError, VaultError) as exc:
                log.error("archive.local_recover_failed archive=%s err=%s", archive.id, type(exc).__name__)
                self.db.update_archive(archive.id, local_status="FAILED", local_error=f"recover:{type(exc).__name__}")
        if archive.log_status in ("VERIFIED", "SENDING") and archive.log_channel_id:
            message_id = archive.log_message_id
            if archive.log_status == "SENDING":
                message_id = await self.gw.find_log_copy(archive.log_channel_id, self._marker(archive))
            if message_id:
                data = await self.gw.download_log_copy(archive.log_channel_id, message_id)
                if data is not None and sha256_hex(data) == sha:
                    if archive.log_status == "SENDING":
                        self.db.update_archive(archive.id, log_status="VERIFIED", log_message_id=message_id,
                                               log_verified_at=self.clock(), log_error=None)
                    return data
            self.db.update_archive(archive.id, log_status="FAILED", log_error="recover:missing_or_mismatch")
        return None

    @staticmethod
    def _marker(archive: Archive) -> str:
        return f"tazkara-archive:{archive.id}:{(archive.transcript_sha256 or '')[:16]}"

    async def _build(self, ticket: Ticket, panel: Panel, archive: Archive, job: Job) -> bytes | JobOutcome:
        try:
            limit = await self.gw.upload_limit(ticket.guild_id)
        except GatewayError as exc:
            return self._retry(job, f"upload_limit:{exc.kind}")
        max_html = limit - UPLOAD_SAFETY_MARGIN
        acknowledged = bool(archive.omissions_ack_by)
        if acknowledged and archive.incomplete_reason == "transcript_too_large":
            budget = 0
        else:
            budget = min(MAX_TOTAL_ATTACHMENT_BYTES, int(max(0, max_html - 512 * 1024) / 1.37))
        try:
            coll = await self.gw.collect_transcript(ticket, panel, budget)
        except GatewayError as exc:
            return self._retry(job, f"collect:{exc.kind}")
        if coll.fatal_reason:
            self.db.update_archive(archive.id, incomplete_reason=coll.fatal_reason[:200])
            await self._notify_once(f"archive:{archive.id}:fatal", [ticket.channel_id, panel.log_channel_id],
                                    MSG["archive_failed_notice"].format(log=coll.fatal_reason, local="-"))
            return self._retry(job, f"incomplete:{coll.fatal_reason}")
        meta = TranscriptMeta(
            guild_name=coll.guild_name, guild_id=ticket.guild_id, channel_name=coll.channel_name, ticket_id=ticket.id,
            ticket_number=ticket.number, panel_name=panel.name, owner_id=ticket.owner_id, owner_name=coll.owner_name,
            created_at=ticket.created_at, closed_by=ticket.closed_by, close_reason=ticket.close_reason,
            generated_at=self.clock(), omissions_acknowledged=acknowledged and bool(coll.omissions))
        html_bytes = build_transcript_html(meta, coll.messages)
        if coll.omissions and not acknowledged:
            return await self._block(ticket, panel, archive, "attachments not stored: " + ", ".join(coll.omissions))
        if len(html_bytes) > max_html:
            if not acknowledged:
                return await self._block(ticket, panel, archive, "transcript_too_large")
            return self._retry(job, "transcript_too_large_even_without_attachments")
        sha = sha256_hex(html_bytes)
        self.db.update_archive(archive.id, only_if_status=LIVE_ARCHIVE_STATUSES, status="PENDING_COPIES",
                               transcript_sha256=sha, transcript_size=len(html_bytes),
                               message_count=len(coll.messages), last_message_id=coll.last_message_id,
                               transcript_complete=1, log_status="PENDING", local_status="PENDING")
        return html_bytes

    async def _block(self, ticket: Ticket, panel: Panel, archive: Archive, reason: str) -> JobOutcome:
        reason = reason[:200]
        self.db.update_archive(archive.id, only_if_status=LIVE_ARCHIVE_STATUSES, status="BLOCKED",
                               incomplete_reason=reason, transcript_complete=0)
        self.db.add_event(ticket.guild_id, "archive_blocked", ticket_id=ticket.id, details={"reason": reason})
        text = MSG["archive_blocked_notice"].format(reason=reason)
        await self._notify_once(f"archive:{archive.id}:blocked", [ticket.channel_id], text, ack_archive_id=archive.id)
        await self._notify_once(f"archive:{archive.id}:blocked_log", [panel.log_channel_id],
                                f"{text} (#{ticket.number}, <#{ticket.channel_id}>)")
        return JOB_DONE

    async def _ensure_log_copy(self, ticket: Ticket, panel: Panel, archive: Archive, html_bytes: bytes) -> bool:
        sha = archive.transcript_sha256 or ""
        marker = self._marker(archive)
        channel_id = panel.log_channel_id
        message_id: Optional[int] = None
        uploaded = False
        try:
            if archive.log_status == "SENDING" and archive.log_channel_id:
                message_id = await self.gw.find_log_copy(archive.log_channel_id, marker)
                if message_id:
                    channel_id = archive.log_channel_id
            if message_id is None:
                self.db.update_archive(archive.id, log_status="SENDING", log_channel_id=channel_id,
                                       log_attempts=archive.log_attempts + 1, log_error=None)
                summary = {"ticket_number": ticket.number, "ticket_id": ticket.id, "owner_id": ticket.owner_id,
                           "closed_by": ticket.closed_by, "reason": ticket.close_reason,
                           "messages": archive.message_count, "sha256": sha, "panel": panel.name}
                message_id = await self.gw.upload_log_copy(channel_id, f"ticket-{ticket.number:04d}-{sha[:8]}.html",
                                                           html_bytes, summary, marker)
                uploaded = True
                self.db.update_archive(archive.id, log_message_id=message_id)
            data = await self.gw.download_log_copy(channel_id, message_id)
        except GatewayError as exc:
            status = "SENDING" if (exc.kind == GatewayError.UNCERTAIN or uploaded) else "FAILED"
            self.db.update_archive(archive.id, log_status=status, log_error=f"{exc.kind}:{exc.detail}"[:200])
            if exc.kind in (GatewayError.NOT_FOUND, GatewayError.FORBIDDEN) and not uploaded:
                self.db.set_panel_status(panel.id, "MISCONFIGURED", expected=("ACTIVE", "PAUSED"),
                                         reason=f"log channel: {exc.kind}")
            log.warning("archive.log_copy_failed archive=%s kind=%s", archive.id, exc.kind)
            return False
        if data is None or sha256_hex(data) != sha:
            self.db.update_archive(archive.id, log_status="FAILED", log_error="verification_failed")
            log.warning("archive.log_copy_verify_failed archive=%s", archive.id)
            return False
        self.db.update_archive(archive.id, log_status="VERIFIED", log_channel_id=channel_id, log_message_id=message_id,
                               log_verified_at=self.clock(), log_error=None)
        return True

    def _ensure_local_copy(self, ticket: Ticket, archive: Archive, html_bytes: bytes) -> bool:
        sha = archive.transcript_sha256 or ""
        rel = Path(f"g{ticket.guild_id}") / f"ticket{ticket.id}_a{archive.id}_{sha[:12]}.html.enc"
        try:
            cipher_sha = self.vault.write_verified(self.archive_dir / rel, html_bytes, sha)
        except (OSError, VaultError) as exc:
            self.db.update_archive(archive.id, local_status="FAILED", local_attempts=archive.local_attempts + 1,
                                   local_error=f"{type(exc).__name__}: {exc}"[:200])
            log.error("archive.local_copy_failed archive=%s err=%s", archive.id, type(exc).__name__)
            return False
        now = self.clock()
        self.db.update_archive(archive.id, local_status="VERIFIED", local_path=rel.as_posix(),
                               local_cipher_sha256=cipher_sha, local_verified_at=now,
                               expires_at=now + LOCAL_RETENTION_DAYS * 86400,
                               local_attempts=archive.local_attempts + 1, local_error=None)
        return True

    async def _notify_once(self, op_key: str, channel_ids: Sequence[int], text: str,
                           ack_archive_id: Optional[int] = None) -> None:
        if self.db.op_get(op_key):
            return
        sent = False
        for index, channel_id in enumerate(channel_ids):
            sent |= await best_effort(self.gw.post_notice(
                channel_id, text, ack_archive_id=ack_archive_id if index == 0 else None), "archive_notice")
        if sent:
            self.db.op_set(op_key, "notice", "SUCCEEDED")

    async def acknowledge_omissions(self, archive_id: int, actor: Actor, guild_id: int,
                                    channel_id: Optional[int]) -> OpResult:
        """Admin explicitly accepts missing attachments for one archive attempt."""
        archive = self.db.get_archive(archive_id)
        if archive is None:
            return _fail("not_found")
        ctx = self.tickets._load(archive.ticket_id, guild_id, channel_id)
        if isinstance(ctx, OpResult):
            return ctx
        ticket, _panel, roles = ctx
        if not is_allowed(A_ACK, actor, ticket, roles):
            return _fail("forbidden")
        if ticket.state != S_CLOSING or archive.status != "BLOCKED":
            return _fail("stale")
        if not self.db.update_archive(archive.id, only_if_status=("BLOCKED",), omissions_ack_by=actor.user_id,
                                      status="BUILDING"):
            return _fail("race")
        self.db.add_event(ticket.guild_id, "archive_omissions_acknowledged", ticket_id=ticket.id, actor_id=actor.user_id,
                          details={"archive_id": archive.id, "reason": archive.incomplete_reason})
        self.db.schedule_job("archive", f"archive:{ticket.id}", self.clock(), guild_id=ticket.guild_id,
                             ticket_id=ticket.id, max_attempts=1_000_000)
        return OpResult(True, "ack", MSG["ack_ok"], ticket)


class PostCloseService:
    """Channel deletion (only for CLOSED tickets) and the privacy-safe DM summary."""

    def __init__(self, db: Database, gateway: Gateway, clock: Clock = now_ts) -> None:
        self.db, self.gw, self.clock = db, gateway, clock

    async def delete_channel(self, job: Job) -> JobOutcome:
        ticket = self.db.get_ticket(job.ticket_id) if job.ticket_id else None
        if ticket is None or ticket.state != S_CLOSED or ticket.channel_deleted:
            return JOB_DONE
        if not any(a.status == "COMPLETE" for a in self.db.archives_for_ticket(ticket.id)):
            log.error("delete.refused_no_complete_archive ticket=%s", ticket.id)  # defence in depth
            return JOB_DONE
        try:
            await self.gw.delete_channel(ticket.channel_id, f"Tazkara: ticket #{ticket.number} archived")
        except GatewayError as exc:
            if exc.kind != GatewayError.NOT_FOUND:
                return JobOutcome("retry", self.clock() + backoff_delay(job.attempts), exc.kind)
        self.db.update_ticket_if(ticket.id, (S_CLOSED,), {"channel_deleted": 1}, event="channel_deleted")
        return JOB_DONE

    async def dm_owner(self, job: Job) -> JobOutcome:
        """At-most-once DM: an uncertain send is never repeated."""
        ticket = self.db.get_ticket(job.ticket_id) if job.ticket_id else None
        if ticket is None or ticket.state != S_CLOSED:
            return JOB_DONE
        op_key = f"dm:{ticket.id}:{ticket.close_seq}"
        op = self.db.op_get(op_key)
        if op is not None and op["status"] in ("SUCCEEDED", "STARTED", "UNCERTAIN"):
            return JOB_DONE
        panel = self.db.get_panel(ticket.panel_id)
        self.db.op_set(op_key, "dm", "STARTED", ticket_id=ticket.id)
        text = MSG["dm_summary"].format(number=ticket.number, panel=panel.name if panel else "-",
                                        closed_at=ticket.closed_at or self.clock())
        try:
            await self.gw.send_dm(ticket.owner_id, text)
        except GatewayError as exc:
            if exc.kind == GatewayError.UNCERTAIN:
                self.db.op_set(op_key, "dm", "UNCERTAIN", ticket_id=ticket.id, error=exc.kind)
                return JOB_DONE
            self.db.op_set(op_key, "dm", "FAILED", ticket_id=ticket.id, error=exc.kind)
            self.db.add_event(ticket.guild_id, "dm_failed", ticket_id=ticket.id, details={"kind": exc.kind})
            if exc.kind == GatewayError.TRANSIENT:
                return JobOutcome("retry", self.clock() + backoff_delay(job.attempts), exc.kind)
            return JOB_DONE
        self.db.op_set(op_key, "dm", "SUCCEEDED", ticket_id=ticket.id)
        return JOB_DONE


class RetentionService:
    """30-day local retention that never deletes the only valid copy."""

    def __init__(self, db: Database, gateway: Gateway, archive_dir: Path, clock: Clock = now_ts) -> None:
        self.db, self.gw, self.archive_dir, self.clock = db, gateway, archive_dir, clock

    async def _log_copy_valid(self, archive: Archive) -> bool:
        if archive.log_status != "VERIFIED" or not archive.log_channel_id or not archive.log_message_id:
            return False
        data = await self.gw.download_log_copy(archive.log_channel_id, archive.log_message_id)
        return data is not None and sha256_hex(data) == archive.transcript_sha256

    async def _decide(self, archive: Archive) -> str:
        if archive.status == "COMPLETE":
            return "delete" if await self._log_copy_valid(archive) else "hold"
        if archive.status == "SUPERSEDED":
            for other in self.db.archives_for_ticket(archive.ticket_id):
                if other.id != archive.id and other.status == "COMPLETE" and await self._log_copy_valid(other):
                    return "delete"
            ticket = self.db.get_ticket(archive.ticket_id)
            if ticket and ticket.state in (S_OPEN, S_ON_HOLD, S_CLOSING) and ticket.channel_id \
                    and await self.gw.channel_exists(ticket.channel_id):
                return "delete"  # the live channel still holds the full source
            return "hold"
        return "skip"  # live archive: the channel is still the source of truth

    async def sweep(self, job: Optional[Job] = None) -> JobOutcome:
        now = self.clock()
        for archive in self.db.archives_for_retention(now):
            try:
                decision = await self._decide(archive)
            except GatewayError as exc:
                log.warning("retention.check_deferred archive=%s kind=%s", archive.id, exc.kind)
                continue
            if decision == "delete":
                self._delete_local(archive, now)
            elif decision == "hold" and archive.local_status != "RETENTION_HOLD":
                self.db.update_archive(archive.id, local_status="RETENTION_HOLD",
                                       local_error="other copy unavailable; local copy kept")
                ticket = self.db.get_ticket(archive.ticket_id)
                if ticket:
                    self.db.add_event(ticket.guild_id, "retention_hold", ticket_id=ticket.id,
                                      details={"archive_id": archive.id})
                log.warning("retention.hold archive=%s (only remaining valid copy)", archive.id)
        purged = self.db.purge_old(now)
        log.info("retention.sweep_done purged=%s", purged)
        return JobOutcome("reschedule", now + RETENTION_SWEEP_INTERVAL)

    def _delete_local(self, archive: Archive, now: int) -> None:
        if archive.local_path:
            try:
                (self.archive_dir / archive.local_path).unlink(missing_ok=True)
            except OSError as exc:
                log.error("retention.delete_failed archive=%s err=%s", archive.id, type(exc).__name__)
                return
        self.db.update_archive(archive.id, local_status="EXPIRED", local_deleted_at=now)
        log.info("retention.deleted archive=%s", archive.id)


class Reconciler:
    """Startup/periodic reconciliation between SQLite and real Discord state."""

    def __init__(self, db: Database, gateway: Gateway, tickets: TicketService, clock: Clock = now_ts) -> None:
        self.db, self.gw, self.tickets, self.clock = db, gateway, tickets, clock

    async def reconcile_all(self) -> dict[str, int]:
        summary = {"jobs_reset": self.db.reset_running_jobs(), "creating": 0, "lost": 0, "control_resent": 0}
        panels = self.db.list_panels()
        for panel in panels:
            await self.check_panel(panel)
        for ticket in self.db.tickets_in_states((S_CREATING,)):
            summary["creating"] += 1
            outcome = await self.reconcile_creating(ticket)
            if outcome.status in ("reschedule", "retry"):
                self.db.schedule_job("reconcile_ticket", f"reconcile:{ticket.id}", outcome.run_at or self.clock() + 60,
                                     guild_id=ticket.guild_id, ticket_id=ticket.id)
        for ticket in self.db.tickets_in_states((S_OPEN, S_ON_HOLD)):
            result = await self._reconcile_live(ticket)
            summary[result] = summary.get(result, 0) + 1
        for ticket in self.db.tickets_in_states((S_CLOSING,)):
            self.db.schedule_job("archive", f"archive:{ticket.id}", self.clock(), guild_id=ticket.guild_id,
                                 ticket_id=ticket.id, max_attempts=1_000_000, keep_existing=True)
        for ticket in self.db.tickets_in_states((S_CLOSED,)):
            if not ticket.channel_deleted:
                self.db.schedule_job("delete_channel", f"delete_channel:{ticket.id}", self.clock(),
                                     guild_id=ticket.guild_id, ticket_id=ticket.id, max_attempts=1_000_000,
                                     keep_existing=True)
        for guild_id in sorted({p.guild_id for p in panels}):
            await self.cleanup_orphans(guild_id)
        self.db.schedule_job("retention_sweep", "retention_sweep", self.clock() + 60, keep_existing=True,
                             max_attempts=1_000_000)
        log.info("reconcile.done summary=%s", summary)
        return summary

    async def check_panel(self, panel: Panel) -> list[str]:
        try:
            problems = await self.gw.check_panel_resources(panel)
        except GatewayError as exc:
            log.warning("reconcile.panel_check_deferred panel=%s kind=%s", panel.id, exc.kind)
            return []
        if problems and panel.status in ("ACTIVE", "PAUSED"):
            self.db.set_panel_status(panel.id, "MISCONFIGURED", expected=("ACTIVE", "PAUSED"), reason="; ".join(problems))
            if not any(p.startswith("log_channel") for p in problems):
                await best_effort(self.gw.post_notice(panel.log_channel_id, MSG["panel_problem"].format(
                    name=panel.name, problems=", ".join(problems))), "panel_problem_notice")
            log.warning("reconcile.panel_misconfigured panel=%s problems=%s", panel.id, problems)
        return problems

    async def reconcile_creating(self, ticket: Ticket) -> JobOutcome:
        """Resolve a CREATING ticket: adopt the marked channel, or fail after the grace period."""
        try:
            channel_id = await self.gw.find_ticket_channel(ticket.guild_id, ticket.id)
        except GatewayError as exc:
            return JobOutcome("retry", self.clock() + 60, exc.kind)
        now = self.clock()
        if channel_id:
            panel = self.db.get_panel(ticket.panel_id)
            opened = self.db.transition(ticket.id, (S_CREATING,), S_OPEN, event="ticket_adopted",
                                        updates={"channel_id": channel_id, "opened_at": now, "creation_uncertain": 0,
                                                 **(timers_on_open(panel, now) if panel else {})})
            if opened and panel:
                await self.tickets._after_open(opened, panel)
            return JOB_DONE
        if now - ticket.created_at >= CREATION_GRACE_SECONDS:
            self.db.transition(ticket.id, (S_CREATING,), S_FAILED, event="creation_unresolved")
            return JOB_DONE
        return JobOutcome("reschedule", ticket.created_at + CREATION_GRACE_SECONDS)

    async def _reconcile_live(self, ticket: Ticket) -> str:
        try:
            exists = await self.gw.channel_exists(ticket.channel_id)
        except GatewayError:
            return "deferred"
        if not exists:
            await self.tickets.handle_channel_deleted(ticket.channel_id)
            return "lost"
        if ticket.control_message_id is None:
            panel = self.db.get_panel(ticket.panel_id)
            if panel:
                await self.tickets._after_open(ticket, panel)
            return "control_resent"
        self.tickets._safe_sync(ticket.id)
        return "ok"

    async def handle_job(self, job: Job) -> JobOutcome:
        ticket = self.db.get_ticket(job.ticket_id) if job.ticket_id else None
        if ticket is None:
            return JOB_DONE
        if ticket.state == S_CREATING:
            return await self.reconcile_creating(ticket)
        if ticket.state in (S_OPEN, S_ON_HOLD) and ticket.control_message_id is None:
            panel = self.db.get_panel(ticket.panel_id)
            if panel:
                await self.tickets._after_open(ticket, panel)
        return JOB_DONE

    async def cleanup_orphans(self, guild_id: int) -> int:
        """Delete bot-marked channels with no matching ticket — only if no human ever wrote in them."""
        try:
            marked = await self.gw.list_marked_channels(guild_id)
        except GatewayError:
            return 0
        removed = 0
        for channel_id, ticket_id in marked:
            ticket = self.db.get_ticket(ticket_id)
            if ticket and (ticket.channel_id == channel_id or ticket.state == S_CREATING):
                continue
            try:
                has_humans = await self.gw.human_messages_after(channel_id, 0)
            except GatewayError:
                continue
            if has_humans:
                log.warning("reconcile.orphan_kept channel=%s ticket=%s (contains human messages)", channel_id, ticket_id)
                continue
            if await best_effort(self.gw.delete_channel(channel_id, "Tazkara: orphan ticket channel"), "orphan_delete"):
                removed += 1
        return removed


JobHandler = Callable[[Job], Awaitable[JobOutcome]]


class Scheduler:
    """Persistent scheduler: jobs live in SQLite; memory only drives the polling loop."""

    def __init__(self, db: Database, handlers: dict[str, JobHandler], clock: Clock = now_ts) -> None:
        self.db, self.handlers, self.clock = db, handlers, clock
        self._stop = asyncio.Event()
        self._task: Optional[asyncio.Task[None]] = None

    async def run_once(self) -> int:
        jobs = self.db.claim_due_jobs(self.clock(), SCHEDULER_BATCH)
        if not jobs:
            return 0
        groups: dict[str, list[Job]] = {}
        for job in jobs:  # jobs of the same ticket run sequentially
            groups.setdefault(f"t{job.ticket_id}" if job.ticket_id else f"j{job.id}", []).append(job)
        semaphore = asyncio.Semaphore(SCHEDULER_CONCURRENCY)

        async def run_group(group: list[Job]) -> None:
            async with semaphore:
                for item in group:
                    await self._execute(item)

        await asyncio.gather(*(run_group(g) for g in groups.values()))
        return len(jobs)

    async def _execute(self, job: Job) -> None:
        handler = self.handlers.get(job.kind)
        if handler is None:
            self.db.finish_job(job, "FAILED", error="no handler")
            return
        try:
            outcome = await asyncio.wait_for(handler(job), JOB_TIMEOUT_SECONDS)
        except asyncio.TimeoutError:
            outcome = JobOutcome("retry", self.clock() + backoff_delay(job.attempts), "timeout")
        except sqlite3.Error as exc:
            log.exception("job.db_error id=%s kind=%s", job.id, job.kind)
            outcome = JobOutcome("retry", self.clock() + backoff_delay(job.attempts), f"db:{type(exc).__name__}")
        except Exception as exc:  # job boundary: logged with traceback and retried — never silently ignored
            log.exception("job.crashed id=%s kind=%s", job.id, job.kind)
            outcome = JobOutcome("retry", self.clock() + backoff_delay(job.attempts), type(exc).__name__)
        try:
            self._apply(job, outcome)
        except sqlite3.Error:
            log.exception("job.finish_failed id=%s (will be reset to PENDING on restart)", job.id)

    def _apply(self, job: Job, outcome: JobOutcome) -> None:
        if outcome.status == "done":
            self.db.finish_job(job, "DONE")
        elif outcome.status == "reschedule":
            self.db.finish_job(job, "reschedule", run_at=outcome.run_at or self.clock(), reset_attempts=True)
        elif outcome.status == "retry" and job.attempts < job.max_attempts:
            self.db.finish_job(job, "retry", run_at=outcome.run_at or self.clock() + backoff_delay(job.attempts),
                               error=outcome.error)
        else:
            log.error("job.failed_permanently id=%s kind=%s error=%s", job.id, job.kind, outcome.error)
            self.db.finish_job(job, "FAILED", error=outcome.error)

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._stop.clear()
            self._task = asyncio.create_task(self._loop(), name="tazkara-scheduler")

    async def _loop(self) -> None:
        log.info("scheduler.started")
        while not self._stop.is_set():
            try:
                await self.run_once()
            except sqlite3.Error:
                log.exception("scheduler.tick_failed")
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(self._stop.wait(), SCHEDULER_TICK_SECONDS)
        log.info("scheduler.stopped")

    async def stop(self, timeout: float = 30.0) -> None:
        """Graceful stop: let the current batch finish (bounded), then exit."""
        self._stop.set()
        if self._task and not self._task.done():
            try:
                await asyncio.wait_for(self._task, timeout)
            except asyncio.TimeoutError:
                log.warning("scheduler.stop_timeout — running jobs will be re-queued on next start")


class TazkaraCore:
    """Wires the services together. Used by the bot and by the tests."""

    def __init__(self, db: Database, gateway: Gateway, vault: ArchiveVault, archive_dir: Path,
                 clock: Clock = now_ts) -> None:
        self.db, self.gw, self.vault, self.archive_dir, self.clock = db, gateway, vault, archive_dir, clock
        self.tickets = TicketService(db, gateway, clock)
        self.automation = AutomationService(db, gateway, self.tickets, clock)
        self.archive = ArchiveService(db, gateway, vault, archive_dir, self.tickets, clock)
        self.post_close = PostCloseService(db, gateway, clock)
        self.retention = RetentionService(db, gateway, archive_dir, clock)
        self.reconciler = Reconciler(db, gateway, self.tickets, clock)
        self.scheduler = Scheduler(db, {
            "archive": self.archive.run,
            "delete_channel": self.post_close.delete_channel,
            "dm_owner": self.post_close.dm_owner,
            "inactivity": self.automation.handle_inactivity,
            "sla": self.automation.handle_sla,
            "escalation": self.automation.handle_escalation,
            "owner_presence": self.automation.handle_owner_presence,
            "reconcile_ticket": self.reconciler.handle_job,
            "retention_sweep": self.retention.sweep,
        }, clock)


# =============================================================================
# 10. DISCORD LAYER
# =============================================================================

DISCORD_ERRORS: tuple[type[BaseException], ...] = (
    discord.HTTPException, discord.RateLimited, aiohttp.ClientError, asyncio.TimeoutError)
_TOPIC_MARKER_RE = re.compile(r"tazkara-ticket-id:(\d{1,19})\b")
_THREAD_MARKER_RE = re.compile(r"·t(\d{1,19})$")  # private-thread tickets carry the id at the end of the name
TicketContainer = Union[discord.TextChannel, discord.Thread]


def map_discord_error(exc: BaseException) -> GatewayError:
    """Translate discord.py/aiohttp errors into retry-relevant categories."""
    if isinstance(exc, discord.NotFound):
        return GatewayError(GatewayError.NOT_FOUND, f"code={exc.code}")
    if isinstance(exc, discord.Forbidden):
        return GatewayError(GatewayError.FORBIDDEN, f"code={exc.code}")
    if isinstance(exc, discord.DiscordServerError):
        return GatewayError(GatewayError.UNCERTAIN, f"http={exc.status}")
    if isinstance(exc, discord.RateLimited):
        return GatewayError(GatewayError.TRANSIENT, f"rate_limited retry_after={exc.retry_after:.0f}s",
                            retry_after=float(exc.retry_after))
    if isinstance(exc, discord.HTTPException):
        if exc.status == 429:
            retry_after: Optional[float] = None
            headers = getattr(exc.response, "headers", None)
            try:
                retry_after = float(headers.get("Retry-After")) if headers and headers.get("Retry-After") else None
            except (TypeError, ValueError):
                retry_after = None
            return GatewayError(GatewayError.TRANSIENT, "http=429", retry_after=retry_after)
        if exc.code == 30013:  # Maximum number of guild channels reached (500)
            return GatewayError(GatewayError.INVALID, "guild_channel_limit")
        if 400 <= exc.status < 500:
            return GatewayError(GatewayError.INVALID, f"http={exc.status} code={exc.code}")
        return GatewayError(GatewayError.UNCERTAIN, f"http={exc.status}")
    return GatewayError(GatewayError.UNCERTAIN, type(exc).__name__)


def _missing_perms(perms: discord.Permissions, required: Sequence[str]) -> list[str]:
    return [name for name in required if not getattr(perms, name)]


class DiscordGateway:
    """Real implementation of ``Gateway`` on top of discord.py."""

    def __init__(self, bot: "TazkaraBot") -> None:
        self.bot = bot

    def _guild(self, guild_id: int) -> discord.Guild:
        guild = self.bot.get_guild(guild_id)
        if guild is None or guild.unavailable:
            raise GatewayError(GatewayError.TRANSIENT, "guild_unavailable")
        return guild

    async def _text_channel(self, channel_id: Optional[int]) -> TicketContainer:
        if not channel_id:
            raise GatewayError(GatewayError.NOT_FOUND, "no_channel_id")
        channel = self.bot.get_channel(channel_id)
        if channel is None:
            try:
                channel = await self.bot.fetch_channel(channel_id)
            except DISCORD_ERRORS as exc:
                raise map_discord_error(exc) from exc
        if not isinstance(channel, (discord.TextChannel, discord.Thread)):
            raise GatewayError(GatewayError.NOT_FOUND, "not_a_text_channel")
        return channel

    async def create_ticket_channel(self, panel: Panel, roles: PanelRoles, ticket: Ticket, owner_name: str) -> int:
        guild = self._guild(panel.guild_id)
        category = guild.get_channel(panel.category_id)
        if not isinstance(category, discord.CategoryChannel):
            raise GatewayError(GatewayError.NOT_FOUND, "category_missing")
        missing = _missing_perms(category.permissions_for(guild.me), REQUIRED_CATEGORY_PERMS)
        if missing:
            raise GatewayError(GatewayError.FORBIDDEN, "missing_permissions:" + ",".join(missing))
        if len(category.channels) >= CATEGORY_CHANNEL_LIMIT:
            raise GatewayError(GatewayError.INVALID, "category_full")
        member_allow = discord.PermissionOverwrite(view_channel=True, send_messages=True, read_message_history=True,
                                                   attach_files=True, embed_links=True)
        overwrites: dict[Any, discord.PermissionOverwrite] = {
            guild.default_role: discord.PermissionOverwrite(view_channel=False),
            guild.me: discord.PermissionOverwrite(view_channel=True, send_messages=True, read_message_history=True,
                                                  embed_links=True, attach_files=True, manage_channels=True),
            discord.Object(id=ticket.owner_id, type=discord.Member): member_allow,
        }
        for role_id in roles.all:
            role = guild.get_role(role_id)
            if role is not None and not role.is_default():
                overwrites[role] = member_allow
        name = render_channel_name(panel.channel_name_template, ticket.number, owner_name, panel.name)
        try:
            channel = await guild.create_text_channel(
                name, category=category, overwrites=overwrites,
                topic=f"Tazkara ticket #{ticket.number} | tazkara-ticket-id:{ticket.id}",
                reason=f"Tazkara ticket {ticket.id}")
        except DISCORD_ERRORS as exc:
            raise map_discord_error(exc) from exc
        return channel.id

    async def create_ticket_thread(self, panel: Panel, ticket: Ticket, owner_name: str) -> int:
        """Private, non-invitable thread in the panel channel; only the owner is added (staff join by button)."""
        guild = self._guild(panel.guild_id)
        parent = guild.get_channel(panel.panel_channel_id)
        if not isinstance(parent, discord.TextChannel):
            raise GatewayError(GatewayError.NOT_FOUND, "thread_parent_missing")
        if parent.is_news():
            raise GatewayError(GatewayError.INVALID, "panel_channel_is_announcement")
        missing = _missing_perms(parent.permissions_for(guild.me),
                                 ("view_channel", "send_messages", "read_message_history") + THREAD_FALLBACK_PERMS)
        if missing:
            raise GatewayError(GatewayError.FORBIDDEN, "missing_thread_permissions:" + ",".join(missing))
        name = f"{render_channel_name(panel.channel_name_template, ticket.number, owner_name, panel.name)[:80]} ·t{ticket.id}"
        try:
            thread = await parent.create_thread(name=name, type=discord.ChannelType.private_thread, invitable=False,
                                                auto_archive_duration=10080, reason=f"Tazkara ticket {ticket.id}")
        except DISCORD_ERRORS as exc:
            raise map_discord_error(exc) from exc
        try:
            await thread.add_user(discord.Object(id=ticket.owner_id))
        except DISCORD_ERRORS as exc:
            error = map_discord_error(exc)
            try:  # compensate: a thread the owner cannot see is useless
                await thread.delete(reason=f"Tazkara: could not add owner to ticket {ticket.id}")
            except DISCORD_ERRORS as del_exc:
                log.warning("thread.compensation_failed ticket=%s kind=%s (orphan cleanup will remove it)",
                            ticket.id, map_discord_error(del_exc).kind)
            raise error from exc
        return thread.id

    async def add_ticket_member(self, channel_id: int, user_id: int) -> bool:
        """Add a member to a private-thread ticket. Returns False for channel tickets (access is via roles)."""
        container = await self._text_channel(channel_id)
        if not isinstance(container, discord.Thread):
            return False
        try:
            if container.archived:
                await container.edit(archived=False)
            await container.add_user(discord.Object(id=user_id))
        except DISCORD_ERRORS as exc:
            raise map_discord_error(exc) from exc
        return True

    async def find_ticket_channel(self, guild_id: int, ticket_id: int) -> Optional[int]:
        for channel_id, marked_ticket in await self.list_marked_channels(guild_id):
            if marked_ticket == ticket_id:
                return channel_id
        return None

    async def list_marked_channels(self, guild_id: int) -> list[tuple[int, int]]:
        guild = self._guild(guild_id)
        found = []
        for channel in guild.text_channels:
            match = _TOPIC_MARKER_RE.search(channel.topic or "")
            if match:
                found.append((channel.id, int(match.group(1))))
        me_id = guild.me.id
        for thread in guild.threads:  # active threads (cached)
            match = _THREAD_MARKER_RE.search(thread.name)
            if match and thread.type == discord.ChannelType.private_thread and thread.owner_id == me_id:
                found.append((thread.id, int(match.group(1))))
        return found

    async def channel_exists(self, channel_id: int) -> bool:
        if not channel_id:
            return False
        if self.bot.get_channel(channel_id) is not None:
            return True
        try:
            await self.bot.fetch_channel(channel_id)
        except discord.NotFound:
            return False
        except discord.Forbidden:
            return True  # exists but hidden: never treat as deleted
        except DISCORD_ERRORS as exc:
            raise map_discord_error(exc) from exc
        return True

    async def delete_channel(self, channel_id: int, reason: str) -> None:
        channel = await self._text_channel(channel_id)
        try:
            await channel.delete(reason=reason)
        except DISCORD_ERRORS as exc:
            raise map_discord_error(exc) from exc

    async def send_control_message(self, ticket: Ticket, panel: Panel) -> int:
        channel = await self._text_channel(ticket.channel_id)
        try:
            message = await channel.send(
                content=f"<@{ticket.owner_id}>", embed=ticket_embed(ticket, panel), view=ticket_view(ticket.id),
                allowed_mentions=discord.AllowedMentions(users=[discord.Object(ticket.owner_id)], roles=False,
                                                         everyone=False))
        except DISCORD_ERRORS as exc:
            raise map_discord_error(exc) from exc
        return message.id

    async def update_control_message(self, ticket: Ticket, panel: Panel) -> None:
        channel = await self._text_channel(ticket.channel_id)
        try:
            await channel.get_partial_message(ticket.control_message_id).edit(
                embed=ticket_embed(ticket, panel), view=ticket_view(ticket.id))
        except DISCORD_ERRORS as exc:
            raise map_discord_error(exc) from exc

    async def set_channel_locked(self, ticket: Ticket, roles: PanelRoles, locked: bool) -> None:
        channel = await self._text_channel(ticket.channel_id)
        if isinstance(channel, discord.Thread):  # threads: Discord's own lock (only moderators/the bot can write)
            try:
                await channel.edit(locked=locked, archived=False,
                                   reason=f"Tazkara: {'lock' if locked else 'unlock'} ticket {ticket.id}")
            except DISCORD_ERRORS as exc:
                raise map_discord_error(exc) from exc
            return
        overwrites = dict(channel.overwrites)
        targets: list[Any] = [discord.Object(id=ticket.owner_id, type=discord.Member)]
        targets += [r for r in (channel.guild.get_role(rid) for rid in roles.all) if r is not None]
        for target in targets:
            key = next((k for k in overwrites if k.id == target.id), target)
            overwrite = overwrites.get(key, discord.PermissionOverwrite())
            overwrite.update(send_messages=not locked, view_channel=True)
            overwrites[key] = overwrite
        try:
            await channel.edit(overwrites=overwrites, reason=f"Tazkara: {'lock' if locked else 'unlock'} ticket {ticket.id}")
        except DISCORD_ERRORS as exc:
            raise map_discord_error(exc) from exc

    async def post_notice(self, channel_id: int, text: str, *, mention_role_ids: Sequence[int] = (),
                          mention_user_ids: Sequence[int] = (), ack_archive_id: Optional[int] = None,
                          join_ticket_id: Optional[int] = None) -> None:
        channel = await self._text_channel(channel_id)
        prefix = " ".join(f"<@&{r}>" for r in mention_role_ids if r)
        content = f"{prefix}\n{text}" if prefix else text
        allowed = discord.AllowedMentions(everyone=False, users=[discord.Object(u) for u in mention_user_ids],
                                          roles=[discord.Object(r) for r in mention_role_ids if r])
        try:
            if ack_archive_id:
                await channel.send(content[:2000], allowed_mentions=allowed, view=archive_ack_view(ack_archive_id))
            elif join_ticket_id:
                await channel.send(content[:2000], allowed_mentions=allowed, view=join_ticket_view(join_ticket_id))
            else:
                await channel.send(content[:2000], allowed_mentions=allowed)
        except DISCORD_ERRORS as exc:
            raise map_discord_error(exc) from exc

    async def collect_transcript(self, ticket: Ticket, panel: Panel, attachment_budget: int) -> TranscriptCollection:
        channel = await self._text_channel(ticket.channel_id)
        if not self.bot.intents.message_content:
            return TranscriptCollection([], None, channel.guild.name, channel.name, str(ticket.owner_id),
                                        fatal_reason="MESSAGE_CONTENT intent is disabled")
        messages: list[TranscriptMessage] = []
        omissions: list[str] = []
        used, last_id, owner_name = 0, None, str(ticket.owner_id)
        try:
            async for msg in channel.history(limit=MAX_TRANSCRIPT_MESSAGES + 1, oldest_first=True):
                if len(messages) >= MAX_TRANSCRIPT_MESSAGES:
                    return TranscriptCollection([], None, channel.guild.name, channel.name, owner_name,
                                                fatal_reason=f"more than {MAX_TRANSCRIPT_MESSAGES} messages")
                attachments: list[TranscriptAttachment] = []
                for att in msg.attachments:
                    if att.size > MAX_ATTACHMENT_BYTES or used + att.size > attachment_budget:
                        attachments.append(TranscriptAttachment(att.filename, att.size, None, "size limit"))
                        omissions.append(att.filename[:40])
                        continue
                    try:
                        data = await att.read()
                    except discord.NotFound:
                        attachments.append(TranscriptAttachment(att.filename, att.size, None, "no longer available"))
                        omissions.append(att.filename[:40])
                        continue
                    used += len(data)
                    attachments.append(TranscriptAttachment(att.filename, att.size, data))
                content = msg.content or ""
                if msg.stickers:
                    content += "".join(f" [sticker: {s.name}]" for s in msg.stickers)
                if msg.author.id == ticket.owner_id:
                    owner_name = msg.author.display_name
                messages.append(TranscriptMessage(
                    id=msg.id, author_id=msg.author.id, author_name=msg.author.display_name, is_bot=msg.author.bot,
                    created_at=int(msg.created_at.timestamp()), content=content,
                    embeds=[(e.title or "", e.description or "") for e in msg.embeds if e.title or e.description],
                    attachments=attachments, edited=msg.edited_at is not None))
                last_id = msg.id
        except DISCORD_ERRORS as exc:
            raise map_discord_error(exc) from exc
        return TranscriptCollection(messages, last_id, channel.guild.name, channel.name, owner_name, None, omissions)

    async def human_messages_after(self, channel_id: int, message_id: int) -> bool:
        channel = await self._text_channel(channel_id)
        try:
            after = discord.Object(id=message_id) if message_id else None
            async for msg in channel.history(limit=None, after=after, oldest_first=True):
                if not msg.author.bot:
                    return True
        except DISCORD_ERRORS as exc:
            raise map_discord_error(exc) from exc
        return False

    async def upload_limit(self, guild_id: int) -> int:
        return int(self._guild(guild_id).filesize_limit)

    async def upload_log_copy(self, log_channel_id: int, filename: str, data: bytes, summary: dict[str, Any],
                              marker: str) -> int:
        channel = await self._text_channel(log_channel_id)
        embed = discord.Embed(title=f"📁 Transcript — Ticket #{summary['ticket_number']:04d}", color=EMBED_COLOR)
        embed.add_field(name="Ticket ID", value=str(summary["ticket_id"]))
        embed.add_field(name="Owner", value=f"<@{summary['owner_id']}> (`{summary['owner_id']}`)")
        embed.add_field(name="Closed by", value=f"<@{summary['closed_by']}>" if summary["closed_by"] else "system")
        embed.add_field(name="Panel", value=discord.utils.escape_markdown(str(summary["panel"]))[:1024])
        embed.add_field(name="Messages", value=str(summary["messages"]))
        embed.add_field(name="Reason", value=discord.utils.escape_markdown(summary["reason"] or "-")[:1024])
        embed.add_field(name="SHA-256", value=f"`{summary['sha256']}`", inline=False)
        try:
            message = await channel.send(content=marker, embed=embed, file=discord.File(io.BytesIO(data), filename=filename),
                                         allowed_mentions=discord.AllowedMentions.none())
        except DISCORD_ERRORS as exc:
            raise map_discord_error(exc) from exc
        return message.id

    async def find_log_copy(self, log_channel_id: int, marker: str) -> Optional[int]:
        channel = await self._text_channel(log_channel_id)
        try:
            async for msg in channel.history(limit=100):
                if self.bot.user and msg.author.id == self.bot.user.id and msg.content.startswith(marker):
                    return msg.id
        except DISCORD_ERRORS as exc:
            raise map_discord_error(exc) from exc
        return None

    async def download_log_copy(self, log_channel_id: int, message_id: int) -> Optional[bytes]:
        try:
            channel = await self._text_channel(log_channel_id)
        except GatewayError as exc:
            if exc.kind == GatewayError.NOT_FOUND:
                return None
            raise
        try:
            message = await channel.fetch_message(message_id)
            if not message.attachments:
                return None
            return await message.attachments[0].read()
        except discord.NotFound:
            return None
        except DISCORD_ERRORS as exc:
            raise map_discord_error(exc) from exc

    async def send_dm(self, user_id: int, text: str) -> None:
        try:
            user = self.bot.get_user(user_id) or await self.bot.fetch_user(user_id)
            await user.send(text, allowed_mentions=discord.AllowedMentions.none())
        except DISCORD_ERRORS as exc:
            raise map_discord_error(exc) from exc

    async def member_present(self, guild_id: int, user_id: int) -> bool:
        guild = self._guild(guild_id)
        try:
            await guild.fetch_member(user_id)
        except discord.NotFound:
            return False
        except DISCORD_ERRORS as exc:
            raise map_discord_error(exc) from exc
        return True

    async def check_panel_resources(self, panel: Panel) -> list[str]:
        guild = self._guild(panel.guild_id)
        me = guild.me
        problems: list[str] = []
        category = guild.get_channel(panel.category_id)
        if not isinstance(category, discord.CategoryChannel):
            problems.append("category_missing")
        elif missing := _missing_perms(category.permissions_for(me), REQUIRED_CATEGORY_PERMS):
            problems.append("category_permissions:" + ",".join(missing))
        for label, channel_id, required in (("log_channel", panel.log_channel_id, REQUIRED_LOG_CHANNEL_PERMS),
                                            ("panel_channel", panel.panel_channel_id, REQUIRED_PANEL_CHANNEL_PERMS)):
            channel = guild.get_channel(channel_id)
            if not isinstance(channel, discord.TextChannel):
                problems.append(f"{label}_missing")
            elif missing := _missing_perms(channel.permissions_for(me), required):
                problems.append(f"{label}_permissions:" + ",".join(missing))
        return problems


# ------------------------------------------------------------------ UI helpers

def actor_from_interaction(interaction: discord.Interaction) -> Actor:
    """Build the actor from data Discord sends with THIS interaction (live roles/permissions)."""
    user = interaction.user
    role_ids = frozenset(r.id for r in user.roles) if isinstance(user, discord.Member) else frozenset()
    perms = interaction.permissions
    return Actor(user.id, role_ids, bool(perms.manage_guild or perms.administrator))


def is_setup_authorized(interaction: discord.Interaction) -> bool:
    return interaction.guild is not None and bool(interaction.permissions.manage_guild or interaction.permissions.administrator)


async def safe_reply(interaction: discord.Interaction, text: str, **kwargs: Any) -> None:
    """Ephemeral reply that works whether or not the interaction was already acknowledged."""
    try:
        if interaction.response.is_done():
            await interaction.followup.send(text[:2000], ephemeral=True, **kwargs)
        else:
            await interaction.response.send_message(text[:2000], ephemeral=True, **kwargs)
    except DISCORD_ERRORS as exc:
        log.warning("ui.reply_failed kind=%s", map_discord_error(exc).kind)


def _core(interaction: discord.Interaction) -> Optional[TazkaraCore]:
    return getattr(interaction.client, "core", None)


def ticket_embed(ticket: Ticket, panel: Panel) -> discord.Embed:
    embed = discord.Embed(title=f"🎫 تيكت #{ticket.number:04d}",
                          description=f"البانل: **{discord.utils.escape_markdown(panel.name)}**", color=EMBED_COLOR)
    embed.add_field(name="صاحب التيكت", value=f"<@{ticket.owner_id}> (`{ticket.owner_id}`)", inline=True)
    embed.add_field(name="الحالة", value=STATE_LABELS.get(ticket.state, ticket.state), inline=True)
    embed.add_field(name="المستلم", value=f"<@{ticket.claimed_by}>" if ticket.claimed_by else "—", inline=True)
    embed.add_field(name="وقت الإنشاء", value=f"<t:{ticket.created_at}:F>", inline=False)
    embed.set_footer(text=f"Tazkara • ticket id {ticket.id}")
    return embed


class TicketActionButton(discord.ui.DynamicItem[discord.ui.Button],
                         template=r"tazkara:t:(?P<action>claim|close|hold|reopen):(?P<ticket_id>[0-9]{1,19})"):
    """Persistent ticket button. custom_id is only a hint; everything is re-validated."""

    STYLES = {
        "claim": ("Claim", discord.ButtonStyle.success, "🙋"),
        "close": ("Close", discord.ButtonStyle.danger, "🔒"),
        "hold": ("Hold / Resume", discord.ButtonStyle.secondary, "⏸️"),
        "reopen": ("Reopen", discord.ButtonStyle.primary, "🔓"),
    }

    def __init__(self, action: str, ticket_id: int) -> None:
        label, style, emoji = self.STYLES[action]
        super().__init__(discord.ui.Button(label=label, style=style, emoji=emoji,
                                           custom_id=f"tazkara:t:{action}:{ticket_id}"))
        self.action, self.ticket_id = action, ticket_id

    @classmethod
    async def from_custom_id(cls, interaction: discord.Interaction, item: discord.ui.Button,
                             match: re.Match[str]) -> "TicketActionButton":
        return cls(match["action"], int(match["ticket_id"]))

    async def callback(self, interaction: discord.Interaction) -> None:
        await handle_ticket_action(interaction, self.action, self.ticket_id)


def ticket_view(ticket_id: int) -> discord.ui.View:
    view = discord.ui.View(timeout=None)
    for action in ("claim", "close", "hold", "reopen"):
        view.add_item(TicketActionButton(action, ticket_id))
    return view


async def handle_ticket_action(interaction: discord.Interaction, action: str, ticket_id: int) -> None:
    core = _core(interaction)
    if core is None or interaction.guild is None or not isinstance(interaction.user, discord.Member):
        await safe_reply(interaction, "غير متاح هنا.")
        return
    actor = actor_from_interaction(interaction)
    try:
        if action == "close":
            pre = core.tickets.check_close(ticket_id, actor, interaction.guild.id, interaction.channel_id)
            if not pre.ok:
                await safe_reply(interaction, pre.message)
                return
            await interaction.response.send_message(
                "هل تريد إغلاق التيكت؟ سيتم إنشاء أرشيف، ولن تُحذف القناة إلا بعد التحقق من نسختي الأرشيف.",
                view=CloseConfirmView(ticket_id, interaction.user.id), ephemeral=True)
            return
        await interaction.response.defer(ephemeral=True, thinking=True)
        handler = {"claim": core.tickets.claim, "hold": core.tickets.toggle_hold, "reopen": core.tickets.reopen}[action]
        result = await handler(ticket_id, actor, interaction.guild.id, interaction.channel_id)
    except sqlite3.Error:
        log.exception("ui.ticket_action_db_error action=%s ticket=%s", action, ticket_id)
        result = _fail("db_error")
    await safe_reply(interaction, result.message)


class CloseConfirmView(discord.ui.View):
    """Ephemeral confirmation; permissions/state are checked again on confirm."""

    def __init__(self, ticket_id: int, requester_id: int) -> None:
        super().__init__(timeout=60)
        self.ticket_id, self.requester_id = ticket_id, requester_id

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        return interaction.user.id == self.requester_id

    @discord.ui.button(label="تأكيد الإغلاق", style=discord.ButtonStyle.danger, emoji="🔒")
    async def confirm(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        core = _core(interaction)
        if core is None or interaction.guild is None:
            return
        await interaction.response.edit_message(content="⏳ جارٍ الإغلاق...", view=None)
        try:
            result = await core.tickets.request_close(self.ticket_id, actor_from_interaction(interaction),
                                                      interaction.guild.id, interaction.channel_id,
                                                      f"closed via button by {interaction.user.id}")
        except sqlite3.Error:
            log.exception("ui.close_db_error ticket=%s", self.ticket_id)
            result = _fail("db_error")
        await interaction.edit_original_response(content=result.message)
        self.stop()

    @discord.ui.button(label="إلغاء", style=discord.ButtonStyle.secondary)
    async def cancel(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        await interaction.response.edit_message(content="تم الإلغاء.", view=None)
        self.stop()


class PanelOpenButton(discord.ui.DynamicItem[discord.ui.Button], template=r"tazkara:open:(?P<panel_id>[0-9]{1,19})"):
    """Persistent "open ticket" button on a panel message."""

    def __init__(self, panel_id: int, label: str = "فتح تيكت") -> None:
        super().__init__(discord.ui.Button(label=label[:80], style=discord.ButtonStyle.primary, emoji="🎫",
                                           custom_id=f"tazkara:open:{panel_id}"))
        self.panel_id = panel_id

    @classmethod
    async def from_custom_id(cls, interaction: discord.Interaction, item: discord.ui.Button,
                             match: re.Match[str]) -> "PanelOpenButton":
        return cls(int(match["panel_id"]), item.label or "فتح تيكت")

    async def callback(self, interaction: discord.Interaction) -> None:
        core = _core(interaction)
        if core is None or interaction.guild is None or interaction.message is None:
            await safe_reply(interaction, "غير متاح هنا.")
            return
        await interaction.response.defer(ephemeral=True, thinking=True)
        try:
            result = await core.tickets.open_ticket(interaction.guild.id, self.panel_id, interaction.user.id,
                                                    interaction.user.display_name, interaction.message.id)
        except sqlite3.Error:
            log.exception("ui.open_db_error panel=%s", self.panel_id)
            result = _fail("db_error")
        await safe_reply(interaction, result.message)


class ArchiveAckButton(discord.ui.DynamicItem[discord.ui.Button], template=r"tazkara:ack:(?P<archive_id>[0-9]{1,19})"):
    """Admin-only explicit acknowledgement of missing attachments."""

    def __init__(self, archive_id: int) -> None:
        super().__init__(discord.ui.Button(label="إقرار الأدمن والمتابعة", style=discord.ButtonStyle.danger,
                                           custom_id=f"tazkara:ack:{archive_id}"))
        self.archive_id = archive_id

    @classmethod
    async def from_custom_id(cls, interaction: discord.Interaction, item: discord.ui.Button,
                             match: re.Match[str]) -> "ArchiveAckButton":
        return cls(int(match["archive_id"]))

    async def callback(self, interaction: discord.Interaction) -> None:
        core = _core(interaction)
        if core is None or interaction.guild is None:
            await safe_reply(interaction, "غير متاح هنا.")
            return
        await interaction.response.defer(ephemeral=True, thinking=True)
        try:
            result = await core.archive.acknowledge_omissions(self.archive_id, actor_from_interaction(interaction),
                                                              interaction.guild.id, interaction.channel_id)
        except sqlite3.Error:
            log.exception("ui.ack_db_error archive=%s", self.archive_id)
            result = _fail("db_error")
        await safe_reply(interaction, result.message)


class JoinTicketButton(discord.ui.DynamicItem[discord.ui.Button], template=r"tazkara:join:(?P<ticket_id>[0-9]{1,19})"):
    """Staff-only button (log channel) to join a private-thread ticket."""

    def __init__(self, ticket_id: int) -> None:
        super().__init__(discord.ui.Button(label="انضم للتيكت", style=discord.ButtonStyle.primary, emoji="🧵",
                                           custom_id=f"tazkara:join:{ticket_id}"))
        self.ticket_id = ticket_id

    @classmethod
    async def from_custom_id(cls, interaction: discord.Interaction, item: discord.ui.Button,
                             match: re.Match[str]) -> "JoinTicketButton":
        return cls(int(match["ticket_id"]))

    async def callback(self, interaction: discord.Interaction) -> None:
        core = _core(interaction)
        if core is None or interaction.guild is None or not isinstance(interaction.user, discord.Member):
            await safe_reply(interaction, "غير متاح هنا.")
            return
        await interaction.response.defer(ephemeral=True, thinking=True)
        try:
            result = await core.tickets.join_ticket(self.ticket_id, actor_from_interaction(interaction),
                                                    interaction.guild.id)
        except sqlite3.Error:
            log.exception("ui.join_db_error ticket=%s", self.ticket_id)
            result = _fail("db_error")
        await safe_reply(interaction, result.message)


def join_ticket_view(ticket_id: int) -> discord.ui.View:
    view = discord.ui.View(timeout=None)
    view.add_item(JoinTicketButton(ticket_id))
    return view


def archive_ack_view(archive_id: int) -> discord.ui.View:
    view = discord.ui.View(timeout=None)
    view.add_item(ArchiveAckButton(archive_id))
    return view


# ------------------------------------------------------------- panel publish

async def publish_panel(bot: "TazkaraBot", panel_id: int, *, force_new: bool = False,
                        old_channel_id: Optional[int] = None) -> tuple[bool, str]:
    """Send or update the public panel message. Old messages become stale (rejected)."""
    db = bot.db
    panel = db.get_panel(panel_id) if db else None
    if panel is None:
        return False, "البانل غير موجودة."
    guild = bot.get_guild(panel.guild_id)
    channel = guild.get_channel(panel.panel_channel_id) if guild else None
    if not isinstance(channel, discord.TextChannel):
        return False, "قناة النشر غير موجودة."
    embed = discord.Embed(title=panel.embed_title, description=panel.embed_description, color=EMBED_COLOR)
    embed.set_footer(text="Tazkara")
    view = discord.ui.View(timeout=None)
    view.add_item(PanelOpenButton(panel.id, panel.button_label))
    old_id = panel.panel_message_id
    try:
        if old_id and not force_new and old_channel_id in (None, panel.panel_channel_id):
            try:
                await channel.get_partial_message(old_id).edit(embed=embed, view=view)
                return True, f"✅ تم تحديث رسالة البانل في {channel.mention}."
            except discord.NotFound:
                old_id = None
        message = await channel.send(embed=embed, view=view)
    except DISCORD_ERRORS as exc:
        err = map_discord_error(exc)
        return False, f"تعذّر نشر البانل ({err.kind}). تحقق من صلاحيات البوت في {channel.mention}."
    db.set_panel_message(panel.id, message.id)
    if old_id:
        old_channel = guild.get_channel(old_channel_id or panel.panel_channel_id)
        if isinstance(old_channel, discord.TextChannel):
            try:
                await old_channel.get_partial_message(old_id).delete()
            except DISCORD_ERRORS as exc:  # old message becomes stale anyway (id no longer matches)
                log.info("panel.old_message_not_deleted panel=%s kind=%s", panel.id, map_discord_error(exc).kind)
    return True, f"✅ تم نشر البانل في {channel.mention}."


def validate_draft_discord(guild: discord.Guild, d: PanelDraft) -> list[str]:
    """Verify channels/roles belong to THIS guild and the bot has the needed permissions."""
    errors: list[str] = []
    me = guild.me
    category = guild.get_channel(d.category_id or 0)
    if not isinstance(category, discord.CategoryChannel):
        errors.append("الكاتيجوري غير موجودة في هذا السيرفر.")
    elif missing := _missing_perms(category.permissions_for(me), REQUIRED_CATEGORY_PERMS):
        errors.append("صلاحيات البوت ناقصة في الكاتيجوري: " + ", ".join(missing))
    for label, channel_id, required in (("قناة النشر", d.panel_channel_id, REQUIRED_PANEL_CHANNEL_PERMS),
                                        ("قناة اللوج", d.log_channel_id, REQUIRED_LOG_CHANNEL_PERMS)):
        channel = guild.get_channel(channel_id or 0)
        if not isinstance(channel, discord.TextChannel):
            errors.append(f"{label} غير موجودة في هذا السيرفر أو ليست قناة نصية.")
        elif missing := _missing_perms(channel.permissions_for(me), required):
            errors.append(f"صلاحيات البوت ناقصة في {label}: " + ", ".join(missing))
    fields: list[tuple[str, str, int]] = (
        [("رولات الستاف", "الخطوة 2", r) for r in d.staff_role_ids]
        + [("رولات الإدارة", "الخطوة 2", r) for r in d.admin_role_ids]
        + ([("رول التصعيد", "هذه الخطوة", d.escalation_role_id)] if d.escalation_role_id else []))
    for field_name, step, role_id in fields:
        role = guild.get_role(role_id)
        if role is None:
            errors.append(f"رول غير موجودة في هذا السيرفر ({field_name}): {role_id}")
        elif role.is_default():
            errors.append(f"لا يمكن استخدام @everyone في «{field_name}». أزِلها من {step}.")
        elif role.tags is not None and role.tags.bot_id == me.id:
            errors.append(f"الرول {role.name} هي رول البوت نفسه، ولا داعي لإضافتها لأن البوت يملك الوصول تلقائيًا. "
                          f"أزِلها من «{field_name}»: اضغط «رجوع» حتى تصل إلى {step}.")
        elif role.managed:
            errors.append(f"الرول {role.name} تابعة لبوت أو تكامل آخر ولا يمكن استخدامها. "
                          f"أزِلها من «{field_name}» ({step}).")
    if d.panel_channel_id and d.panel_channel_id == d.log_channel_id:
        errors.append("يجب أن تكون قناة اللوج مختلفة عن قناة النشر (اللوج يحتوي محادثات خاصة).")
    return errors


def hierarchy_warnings(guild: discord.Guild, d: PanelDraft) -> list[str]:
    """Role-hierarchy review (non-blocking).

    The bot never edits or assigns roles; it only writes channel permission
    overwrites, which Discord allows for roles above the bot as long as the bot
    has Manage Roles/Permissions and holds every permission it grants (both are
    hard-checked in ``validate_draft_discord``). Roles above the bot's top role
    and roles with Administrator are reported so the admin understands who can
    see ticket channels regardless of overwrites.
    """
    notes: list[str] = []
    top = guild.me.top_role
    role_ids = list(d.staff_role_ids) + list(d.admin_role_ids) + ([d.escalation_role_id] if d.escalation_role_id else [])
    for role_id in dict.fromkeys(role_ids):
        role = guild.get_role(role_id)
        if role is None:
            continue
        if role >= top:
            notes.append(f"الرول {role.name} أعلى من رول البوت أو تساويها (لا يمنع العمل، لكن البوت لا يستطيع إدارتها).")
        if role.permissions.administrator:
            notes.append(f"الرول {role.name} تملك Administrator وسترى كل التيكتات بغض النظر عن الإعدادات.")
    return notes


def thread_fallback_notes(guild: discord.Guild, d: PanelDraft) -> list[str]:
    """Non-blocking: tell the admin if the private-thread fallback cannot work in the panel channel."""
    if not THREAD_FALLBACK_ENABLED:
        return []
    channel = guild.get_channel(d.panel_channel_id or 0)
    if not isinstance(channel, discord.TextChannel):
        return []
    if channel.is_news():
        return ["قناة النشر من نوع Announcement، فلا يمكن فتح التيكت كـ Thread خاص عند تقييد Discord لإنشاء القنوات."]
    missing = _missing_perms(channel.permissions_for(guild.me), THREAD_FALLBACK_PERMS)
    if missing:
        return ["الخطة البديلة (Thread خاص عند تقييد Discord لإنشاء القنوات) معطلة: امنح البوت في قناة النشر: "
                + ", ".join(missing)]
    return []


async def save_and_publish(bot: "TazkaraBot", guild: discord.Guild, draft: PanelDraft, actor_id: int) -> tuple[bool, str]:
    errors = validate_draft_fields(draft) + validate_draft_discord(guild, draft)
    if errors:
        return False, "❌ لم يتم الحفظ:\n" + "\n".join(f"• {e}" for e in errors)
    db = bot.db
    old = db.get_panel(draft.panel_id) if draft.panel_id else None
    if draft.panel_id and (old is None or old.guild_id != guild.id):
        return False, "البانل غير موجودة في هذا السيرفر."
    try:
        panel_id = db.save_panel(draft, actor_id)
    except sqlite3.IntegrityError as exc:
        if "panels.guild_id, panels.name" in str(exc) or "ux_panels_name" in str(exc):
            return False, "❌ يوجد بانل بنفس الاسم في هذا السيرفر."
        log.warning("setup.integrity_error err=%s", type(exc).__name__)
        return False, "❌ بيانات غير صالحة."
    except (sqlite3.Error, ValueError):
        log.exception("setup.save_failed guild=%s", guild.id)
        return False, MSG["db_error"]
    draft.panel_id = panel_id
    ok, text = await publish_panel(bot, panel_id, old_channel_id=old.panel_channel_id if old else None)
    prefix = "✅ تم حفظ الإعدادات." if ok else "⚠️ تم حفظ الإعدادات لكن النشر فشل."
    notes = hierarchy_warnings(guild, draft) + thread_fallback_notes(guild, draft)
    extra = ("\nℹ️ ملاحظات:\n" + "\n".join(f"• {n}" for n in notes)) if notes else ""
    return ok, f"{prefix}\n{text}{extra}"


# ------------------------------------------------------------------- /setup UI

class GuardedView(discord.ui.View):
    """Setup views: only the invoking manager can use them; permission re-checked on every click."""

    def __init__(self, bot: "TazkaraBot", author_id: int, timeout: float = WIZARD_TIMEOUT) -> None:
        super().__init__(timeout=timeout)
        self.bot, self.author_id = bot, author_id

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self.author_id:
            await safe_reply(interaction, "هذه اللوحة ليست لك.")
            return False
        if not is_setup_authorized(interaction):
            await safe_reply(interaction, MSG["forbidden"])
            return False
        return True

    async def on_error(self, interaction: discord.Interaction, error: Exception, item: discord.ui.Item[Any]) -> None:
        log.error("ui.view_error view=%s", type(self).__name__, exc_info=error)
        await safe_reply(interaction, "حدث خطأ غير متوقع وتم تسجيله.")


class GuardedModal(discord.ui.Modal):
    def __init__(self, bot: "TazkaraBot", draft: PanelDraft, author_id: int, title: str) -> None:
        super().__init__(title=title, timeout=WIZARD_TIMEOUT)
        self.bot, self.draft, self.author_id = bot, draft, author_id

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self.author_id or not is_setup_authorized(interaction):
            await safe_reply(interaction, MSG["forbidden"])
            return False
        return True

    async def on_error(self, interaction: discord.Interaction, error: Exception) -> None:
        log.error("ui.modal_error modal=%s", type(self).__name__, exc_info=error)
        await safe_reply(interaction, "حدث خطأ غير متوقع وتم تسجيله.")


class RetryModalView(GuardedView):
    def __init__(self, bot: "TazkaraBot", author_id: int, factory: Callable[[], discord.ui.Modal]) -> None:
        super().__init__(bot, author_id)
        self.factory = factory

    @discord.ui.button(label="تعديل المدخلات", style=discord.ButtonStyle.primary, emoji="✏️")
    async def retry(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        await interaction.response.send_modal(self.factory())


def _draft_summary(d: PanelDraft) -> discord.Embed:
    def roles(ids: Sequence[int]) -> str:
        return " ".join(f"<@&{r}>" for r in ids) or "—"

    embed = discord.Embed(title=f"ملخص البانل: {discord.utils.escape_markdown(d.name) or '—'}"[:256], color=EMBED_COLOR)
    embed.add_field(name="رولات الإدارة", value=roles(d.admin_role_ids)[:1024])
    embed.add_field(name="رولات الستاف", value=roles(d.staff_role_ids)[:1024])
    embed.add_field(name="الكاتيجوري", value=f"<#{d.category_id}>" if d.category_id else "—")
    embed.add_field(name="قناة النشر", value=f"<#{d.panel_channel_id}>" if d.panel_channel_id else "—")
    embed.add_field(name="قناة اللوج", value=f"<#{d.log_channel_id}>" if d.log_channel_id else "—")
    embed.add_field(name="قالب الاسم", value=f"`{d.channel_name_template}`")
    embed.add_field(name="حد التيكتات المفتوحة", value=str(d.max_open_tickets))
    embed.add_field(name="الخمول", value=f"{d.inactivity_timeout_min} د (تحذير قبلها بـ {d.inactivity_warning_min} د)"
                    if d.inactivity_enabled else "معطّل")
    embed.add_field(name="SLA", value=f"{d.sla_first_response_min} د" if d.sla_enabled else "معطّل")
    embed.add_field(name="التصعيد", value=(f"<@&{d.escalation_role_id}> بعد {d.escalation_after_min} د"
                                           if d.escalation_role_id else "—"))
    embed.add_field(name="إغلاق عند مغادرة صاحب التيكت", value="مفعّل" if d.close_on_owner_leave else "معطّل")
    return embed


class PanelTextModal(GuardedModal):
    """Wizard step 1/4: texts and channel-name template."""

    def __init__(self, bot: "TazkaraBot", draft: PanelDraft, author_id: int) -> None:
        super().__init__(bot, draft, author_id, "إعداد البانل (1/4): النصوص")
        self.name_in = discord.ui.TextInput(label="اسم البانل", max_length=50, default=draft.name or None)
        self.title_in = discord.ui.TextInput(label="عنوان الـ Embed", max_length=256, default=draft.embed_title or None)
        self.desc_in = discord.ui.TextInput(label="وصف الـ Embed", style=discord.TextStyle.paragraph, max_length=2000,
                                            default=draft.embed_description or None)
        self.button_in = discord.ui.TextInput(label="نص زر فتح التيكت", max_length=80, default=draft.button_label)
        self.template_in = discord.ui.TextInput(label="قالب اسم القناة", max_length=60, default=draft.channel_name_template,
                                                placeholder="مثال: ticket-{number} أو {panel}-{user}-{number}")
        for item in (self.name_in, self.title_in, self.desc_in, self.button_in, self.template_in):
            self.add_item(item)

    async def on_submit(self, interaction: discord.Interaction) -> None:
        d = self.draft
        d.name = clean_text(self.name_in.value)
        d.embed_title = clean_text(self.title_in.value)
        d.embed_description = clean_text(self.desc_in.value, multiline=True)
        d.button_label = clean_text(self.button_in.value)
        d.channel_name_template = clean_text(self.template_in.value)
        errors = validate_draft_text(d)
        if errors:
            await interaction.response.send_message(
                "\n".join(f"• {e}" for e in errors), ephemeral=True,
                view=RetryModalView(self.bot, self.author_id, lambda: PanelTextModal(self.bot, d, self.author_id)))
            return
        await interaction.response.edit_message(content="**(2/4)** اختر الرولات والكاتيجوري:", embed=None,
                                                view=RolesStepView(self.bot, d, self.author_id))


def _select_cb(setter: Callable[[Sequence[Any]], None], select: Any) -> Callable[[discord.Interaction], Awaitable[None]]:
    async def callback(interaction: discord.Interaction) -> None:
        setter(select.values)
        await interaction.response.defer()
    return callback


class RolesStepView(GuardedView):
    """Wizard step 2/4: admin roles, staff roles, category."""

    def __init__(self, bot: "TazkaraBot", draft: PanelDraft, author_id: int) -> None:
        super().__init__(bot, author_id)
        self.draft = draft
        admin = discord.ui.RoleSelect(placeholder="رولات الإدارة (اختياري)", min_values=0, max_values=10, row=0,
                                      default_values=[discord.Object(r) for r in draft.admin_role_ids][:10])
        staff = discord.ui.RoleSelect(placeholder="رولات الستاف (مطلوب)", min_values=1, max_values=10, row=1,
                                      default_values=[discord.Object(r) for r in draft.staff_role_ids][:10])
        category = discord.ui.ChannelSelect(placeholder="Category التيكتات", channel_types=[discord.ChannelType.category],
                                            min_values=1, max_values=1, row=2,
                                            default_values=[discord.Object(draft.category_id)] if draft.category_id else [])
        admin.callback = _select_cb(lambda vals: setattr(draft, "admin_role_ids", [v.id for v in vals]), admin)
        staff.callback = _select_cb(lambda vals: setattr(draft, "staff_role_ids", [v.id for v in vals]), staff)
        category.callback = _select_cb(lambda vals: setattr(draft, "category_id", vals[0].id if vals else None), category)
        for item in (admin, staff, category):
            self.add_item(item)

    @discord.ui.button(label="التالي", style=discord.ButtonStyle.primary, row=3)
    async def next_step(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        if not self.draft.staff_role_ids or not self.draft.category_id:
            await safe_reply(interaction, "اختر رول ستاف واحدة على الأقل والكاتيجوري.")
            return
        await interaction.response.edit_message(content="**(3/4)** اختر قناة النشر وقناة اللوج:",
                                                view=ChannelsStepView(self.bot, self.draft, self.author_id))

    @discord.ui.button(label="إلغاء", style=discord.ButtonStyle.secondary, row=3)
    async def cancel(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        await interaction.response.edit_message(content="تم إلغاء المعالج.", embed=None, view=None)
        self.stop()


class ChannelsStepView(GuardedView):
    """Wizard step 3/4: panel channel and log channel."""

    def __init__(self, bot: "TazkaraBot", draft: PanelDraft, author_id: int) -> None:
        super().__init__(bot, author_id)
        self.draft = draft
        text_types = [discord.ChannelType.text, discord.ChannelType.news]
        panel_ch = discord.ui.ChannelSelect(
            placeholder="قناة نشر البانل", channel_types=text_types, min_values=1, max_values=1, row=0,
            default_values=[discord.Object(draft.panel_channel_id)] if draft.panel_channel_id else [])
        log_ch = discord.ui.ChannelSelect(
            placeholder="قناة اللوج (خاصة بالإدارة)", channel_types=[discord.ChannelType.text], min_values=1,
            max_values=1, row=1, default_values=[discord.Object(draft.log_channel_id)] if draft.log_channel_id else [])
        panel_ch.callback = _select_cb(lambda v: setattr(draft, "panel_channel_id", v[0].id if v else None), panel_ch)
        log_ch.callback = _select_cb(lambda v: setattr(draft, "log_channel_id", v[0].id if v else None), log_ch)
        self.add_item(panel_ch)
        self.add_item(log_ch)

    @discord.ui.button(label="التالي", style=discord.ButtonStyle.primary, row=2)
    async def next_step(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        if not self.draft.panel_channel_id or not self.draft.log_channel_id:
            await safe_reply(interaction, "اختر القناتين أولًا.")
            return
        await interaction.response.send_modal(LimitsModal(self.bot, self.draft, self.author_id))

    @discord.ui.button(label="رجوع", style=discord.ButtonStyle.secondary, row=2)
    async def back(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        await interaction.response.edit_message(content="**(2/4)** اختر الرولات والكاتيجوري:",
                                                view=RolesStepView(self.bot, self.draft, self.author_id))


class LimitsModal(GuardedModal):
    """Wizard step 4/4 (a): limits and automation timers."""

    def __init__(self, bot: "TazkaraBot", draft: PanelDraft, author_id: int) -> None:
        super().__init__(bot, draft, author_id, "إعداد البانل (4/4): الحدود والأتمتة")
        self.max_in = discord.ui.TextInput(label="حد التيكتات المفتوحة (1-50)", max_length=2,
                                           default=str(draft.max_open_tickets))
        self.inact_in = discord.ui.TextInput(label="مهلة خمول العميل بالدقائق (0 = تعطيل)", max_length=5,
                                             default=str(draft.inactivity_timeout_min if draft.inactivity_enabled else 0))
        self.warn_in = discord.ui.TextInput(label="التحذير قبل الإغلاق بالدقائق", max_length=5,
                                            default=str(draft.inactivity_warning_min))
        self.sla_in = discord.ui.TextInput(label="SLA مهلة أول رد بالدقائق (0 = تعطيل)", max_length=5,
                                           default=str(draft.sla_first_response_min if draft.sla_enabled else 0))
        self.esc_in = discord.ui.TextInput(label="التصعيد بعد تجاوز SLA بالدقائق", max_length=5,
                                           default=str(draft.escalation_after_min))
        for item in (self.max_in, self.inact_in, self.warn_in, self.sla_in, self.esc_in):
            self.add_item(item)

    async def on_submit(self, interaction: discord.Interaction) -> None:
        d = self.draft
        parsed = [
            parse_int_field(self.max_in.value, "حد التيكتات", 1, 50),
            parse_int_field(self.inact_in.value, "مهلة الخمول", 10, 43200, allow_zero=True),
            parse_int_field(self.warn_in.value, "مدة التحذير", 1, 43199),
            parse_int_field(self.sla_in.value, "مهلة SLA", 5, 10080, allow_zero=True),
            parse_int_field(self.esc_in.value, "مهلة التصعيد", 0, 10080, allow_zero=True),
        ]
        errors = [err for _value, err in parsed if err]
        if not errors:
            max_open, inact, warn, sla, esc = (value for value, _err in parsed)
            d.max_open_tickets = max_open or 1
            d.inactivity_enabled = bool(inact)
            d.inactivity_timeout_min = inact or 1440
            d.inactivity_warning_min = warn or 60
            if not d.inactivity_enabled and d.inactivity_warning_min >= d.inactivity_timeout_min:
                d.inactivity_warning_min = 60
            d.sla_enabled = bool(sla)
            d.sla_first_response_min = sla or 60
            d.escalation_after_min = esc or 0
            if not d.sla_enabled:
                d.escalation_role_id = None
            errors = [e for e in validate_draft_fields(d) if "التصعيد" not in e]
        if errors:
            await interaction.response.send_message(
                "\n".join(f"• {e}" for e in errors), ephemeral=True,
                view=RetryModalView(self.bot, self.author_id, lambda: LimitsModal(self.bot, d, self.author_id)))
            return
        await interaction.response.edit_message(content="**(4/4)** راجع الملخص ثم احفظ:", embed=_draft_summary(d),
                                                view=FinalStepView(self.bot, d, self.author_id))


class FinalStepView(GuardedView):
    """Wizard step 4/4 (b): escalation role, owner-left toggle (default OFF), save & publish."""

    def __init__(self, bot: "TazkaraBot", draft: PanelDraft, author_id: int) -> None:
        super().__init__(bot, author_id)
        self.draft = draft
        if draft.sla_enabled:
            esc = discord.ui.RoleSelect(
                placeholder="رول التصعيد (اختياري، يتطلب SLA)", min_values=0, max_values=1, row=0,
                default_values=[discord.Object(draft.escalation_role_id)] if draft.escalation_role_id else [])
            esc.callback = _select_cb(lambda v: setattr(draft, "escalation_role_id", v[0].id if v else None), esc)
            self.add_item(esc)
        self._sync_toggle_label()

    def _sync_toggle_label(self) -> None:
        self.toggle_leave.label = ("إغلاق عند مغادرة صاحب التيكت: مفعّل" if self.draft.close_on_owner_leave
                                   else "إغلاق عند مغادرة صاحب التيكت: معطّل")

    @discord.ui.button(label="toggle", style=discord.ButtonStyle.secondary, row=1)
    async def toggle_leave(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        self.draft.close_on_owner_leave = not self.draft.close_on_owner_leave
        self._sync_toggle_label()
        await interaction.response.edit_message(embed=_draft_summary(self.draft), view=self)

    @discord.ui.button(label="حفظ ونشر", style=discord.ButtonStyle.success, emoji="💾", row=2)
    async def save(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        await interaction.response.defer()
        ok, text = await save_and_publish(self.bot, interaction.guild, self.draft, interaction.user.id)
        await interaction.edit_original_response(content=text[:2000], embed=None if ok else _draft_summary(self.draft),
                                                 view=None if ok else self)
        if ok:
            self.stop()

    @discord.ui.button(label="رجوع", style=discord.ButtonStyle.secondary, row=2)
    async def back(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        await interaction.response.edit_message(content="**(3/4)** اختر قناة النشر وقناة اللوج:", embed=None,
                                                view=ChannelsStepView(self.bot, self.draft, self.author_id))

    @discord.ui.button(label="إلغاء", style=discord.ButtonStyle.secondary, row=2)
    async def cancel(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        await interaction.response.edit_message(content="تم إلغاء المعالج.", embed=None, view=None)
        self.stop()


def _home_embed() -> discord.Embed:
    embed = discord.Embed(title="🎫 Tazkara — لوحة التحكم",
                          description="أنشئ بانل جديدة، أو أدِر البانلات الحالية، أو اعرض الإحصائيات.", color=EMBED_COLOR)
    embed.set_footer(text="هذه اللوحة مرئية لك فقط")
    return embed


class SetupHomeView(GuardedView):
    @discord.ui.button(label="بانل جديدة", style=discord.ButtonStyle.success, emoji="➕")
    async def new_panel(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        await interaction.response.send_modal(PanelTextModal(self.bot, PanelDraft(guild_id=interaction.guild.id),
                                                             self.author_id))

    @discord.ui.button(label="إدارة البانلات", style=discord.ButtonStyle.primary, emoji="📋")
    async def manage(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        panels = self.bot.db.list_panels(interaction.guild.id)
        if not panels:
            await safe_reply(interaction, "لا توجد بانلات بعد.")
            return
        await interaction.response.edit_message(embed=_home_embed(), view=PanelPickView(self.bot, self.author_id, panels))

    @discord.ui.button(label="الإحصائيات", style=discord.ButtonStyle.secondary, emoji="📊")
    async def stats(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        s = self.bot.db.stats(interaction.guild.id)
        embed = discord.Embed(title="📊 إحصائيات التيكتات", color=EMBED_COLOR)
        for state in ALL_STATES:
            embed.add_field(name=STATE_LABELS[state], value=str(s["by_state"].get(state, 0)))
        avg = s["avg_first_response_s"]
        embed.add_field(name="متوسط أول رد", value=f"{avg / 60:.1f} دقيقة" if avg else "—")
        embed.add_field(name="آخر 7 أيام", value=str(s["last_7_days"]))
        embed.add_field(name="تجاوزات SLA", value=str(s["sla_breaches"]))
        embed.add_field(name="أرشفة معلّقة", value=str(s["archives_pending"]))
        embed.add_field(name="نسخ محلية محتجزة (Retention hold)", value=str(s["retention_holds"]))
        await safe_reply(interaction, "الإحصائيات:", embed=embed)


class PanelPickView(GuardedView):
    def __init__(self, bot: "TazkaraBot", author_id: int, panels: list[Panel]) -> None:
        super().__init__(bot, author_id)
        options = [discord.SelectOption(label=p.name[:100], value=str(p.id), description=f"#{p.id} • {p.status}")
                   for p in panels[:25]]
        select = discord.ui.Select(placeholder="اختر بانل", options=options, min_values=1, max_values=1)

        async def on_pick(interaction: discord.Interaction) -> None:
            panel = self.bot.db.get_panel(int(select.values[0]))
            if panel is None or panel.guild_id != interaction.guild.id:
                await safe_reply(interaction, "البانل غير موجودة.")
                return
            await interaction.response.edit_message(content=None, embed=panel_info_embed(self.bot, panel),
                                                    view=PanelManageView(self.bot, self.author_id, panel.id))
        select.callback = on_pick
        self.add_item(select)


def panel_info_embed(bot: "TazkaraBot", panel: Panel) -> discord.Embed:
    embed = _draft_summary(bot.db.draft_from_panel(panel))
    embed.description = (f"الحالة: **{panel.status}** • التيكتات النشطة: "
                         f"{bot.db.count_panel_tickets(panel.id, ACTIVE_STATES)}")
    return embed


class ConfirmActionView(GuardedView):
    def __init__(self, bot: "TazkaraBot", author_id: int, action: Callable[[discord.Interaction], Awaitable[str]]) -> None:
        super().__init__(bot, author_id, timeout=60)
        self.action = action

    @discord.ui.button(label="تأكيد", style=discord.ButtonStyle.danger)
    async def confirm(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        await interaction.response.defer()
        text = await self.action(interaction)
        await interaction.edit_original_response(content=text, embed=None, view=None)
        self.stop()

    @discord.ui.button(label="إلغاء", style=discord.ButtonStyle.secondary)
    async def cancel(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        await interaction.response.edit_message(content="تم الإلغاء.", embed=None, view=None)
        self.stop()


class PanelManageView(GuardedView):
    def __init__(self, bot: "TazkaraBot", author_id: int, panel_id: int) -> None:
        super().__init__(bot, author_id)
        self.panel_id = panel_id

    def _panel(self, interaction: discord.Interaction) -> Optional[Panel]:
        panel = self.bot.db.get_panel(self.panel_id)
        if panel is None or panel.guild_id != interaction.guild.id or panel.status in ("ARCHIVED", "DELETED"):
            return None
        return panel

    @discord.ui.button(label="تعديل", style=discord.ButtonStyle.primary, emoji="✏️", row=0)
    async def edit(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        panel = self._panel(interaction)
        if panel is None:
            await safe_reply(interaction, "البانل غير متاحة.")
            return
        await interaction.response.send_modal(PanelTextModal(self.bot, self.bot.db.draft_from_panel(panel), self.author_id))

    @discord.ui.button(label="إعادة نشر", style=discord.ButtonStyle.secondary, emoji="📢", row=0)
    async def republish(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        if self._panel(interaction) is None:
            await safe_reply(interaction, "البانل غير متاحة.")
            return
        await interaction.response.defer(ephemeral=True, thinking=True)
        _ok, text = await publish_panel(self.bot, self.panel_id, force_new=True)
        await safe_reply(interaction, text)

    @discord.ui.button(label="إيقاف / تفعيل", style=discord.ButtonStyle.secondary, emoji="⏯️", row=0)
    async def toggle(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        panel = self._panel(interaction)
        if panel is None:
            await safe_reply(interaction, "البانل غير متاحة.")
            return
        await interaction.response.defer(ephemeral=True, thinking=True)
        if panel.status == "ACTIVE":
            self.bot.db.set_panel_status(panel.id, "PAUSED", expected=("ACTIVE",), actor_id=interaction.user.id)
            await safe_reply(interaction, "⏸️ تم إيقاف البانل مؤقتًا.")
            return
        try:
            problems = await self.bot.core.gw.check_panel_resources(panel)
        except GatewayError as exc:
            await safe_reply(interaction, f"تعذّر التحقق الآن ({exc.kind}). حاول لاحقًا.")
            return
        if problems:
            await safe_reply(interaction, "لا يمكن التفعيل قبل إصلاح: " + ", ".join(problems) + "\nاستخدم «تعديل».")
            return
        self.bot.db.set_panel_status(panel.id, "ACTIVE", expected=("PAUSED", "MISCONFIGURED"), actor_id=interaction.user.id)
        await safe_reply(interaction, "▶️ تم تفعيل البانل.")

    async def _retire(self, interaction: discord.Interaction, delete: bool) -> str:
        panel = self._panel(interaction)
        if panel is None:
            return "البانل غير متاحة."
        error = self.bot.db.retire_panel(panel.id, delete=delete, actor_id=interaction.user.id)
        if error == "has_active_tickets":
            return "❌ لا يمكن ذلك: توجد تيكتات نشطة أو قيد الأرشفة مرتبطة بهذه البانل."
        if error:
            return "البانل غير موجودة."
        channel = interaction.guild.get_channel(panel.panel_channel_id)
        if panel.panel_message_id and isinstance(channel, discord.TextChannel):
            try:
                await channel.get_partial_message(panel.panel_message_id).delete()
            except DISCORD_ERRORS as exc:
                log.info("panel.message_delete_skipped panel=%s kind=%s", panel.id, map_discord_error(exc).kind)
        return "🗑️ تم حذف إعدادات البانل." if delete else "📦 تمت أرشفة البانل."

    @discord.ui.button(label="أرشفة", style=discord.ButtonStyle.danger, emoji="📦", row=1)
    async def archive(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        await interaction.response.edit_message(content="تأكيد أرشفة البانل؟", embed=None, view=ConfirmActionView(
            self.bot, self.author_id, lambda i: self._retire(i, False)))

    @discord.ui.button(label="حذف الإعدادات", style=discord.ButtonStyle.danger, emoji="🗑️", row=1)
    async def delete(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        await interaction.response.edit_message(content="تأكيد حذف إعدادات البانل؟ (السجلات التاريخية تبقى)", embed=None,
                                                view=ConfirmActionView(self.bot, self.author_id,
                                                                       lambda i: self._retire(i, True)))

    @discord.ui.button(label="رجوع", style=discord.ButtonStyle.secondary, row=1)
    async def back(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        await interaction.response.edit_message(content=None, embed=_home_embed(),
                                                view=SetupHomeView(self.bot, self.author_id))


@app_commands.command(name="setup", description="لوحة تحكم Tazkara (للإدارة فقط)")
@app_commands.guild_only()
@app_commands.default_permissions(manage_guild=True)
async def setup_command(interaction: discord.Interaction) -> None:
    bot = interaction.client
    if not is_setup_authorized(interaction) or not isinstance(bot, TazkaraBot) or bot.core is None:
        await safe_reply(interaction, MSG["forbidden"])
        return
    await interaction.response.send_message(embed=_home_embed(), view=SetupHomeView(bot, interaction.user.id),
                                            ephemeral=True)


def build_intents() -> discord.Intents:
    """Only what is needed. message_content is privileged and REQUIRED for full transcripts."""
    intents = discord.Intents.none()
    intents.guilds = True
    intents.guild_messages = True
    intents.message_content = True
    intents.members = ENABLE_MEMBERS_INTENT
    return intents


class TazkaraBot(discord.Client):
    def __init__(self, vault: ArchiveVault) -> None:
        super().__init__(intents=build_intents(), allowed_mentions=discord.AllowedMentions.none(),
                         max_ratelimit_timeout=60.0)
        self.tree = app_commands.CommandTree(self)
        self.vault = vault
        self.db: Optional[Database] = None
        self.core: Optional[TazkaraCore] = None
        self._started = False

    async def setup_hook(self) -> None:
        self.db = Database(DB_PATH)
        if not self.db.integrity_ok():
            raise RuntimeError("data.db failed PRAGMA integrity_check — restore from backup")
        ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
        self.core = TazkaraCore(self.db, DiscordGateway(self), self.vault, ARCHIVE_DIR)
        self.add_dynamic_items(PanelOpenButton, TicketActionButton, ArchiveAckButton, JoinTicketButton)
        self.tree.add_command(setup_command)
        self.tree.on_error = self.on_app_command_error  # type: ignore[assignment]
        if SYNC_COMMANDS_ON_START:
            if DEV_GUILD_ID:
                guild = discord.Object(id=DEV_GUILD_ID)
                self.tree.copy_global_to(guild=guild)
                await self.tree.sync(guild=guild)
            else:
                await self.tree.sync()
        log.info("bot.setup_done")

    async def on_ready(self) -> None:
        log.info("bot.ready user_id=%s guilds=%d", self.user.id if self.user else 0, len(self.guilds))
        if self._started or self.core is None:
            return
        self._started = True
        try:
            await self.core.reconciler.reconcile_all()
        except (sqlite3.Error, GatewayError):
            log.exception("reconcile.failed (will be retried by the scheduler's jobs)")
        finally:
            self.core.scheduler.start()  # always start: persisted jobs must run even if reconcile failed

    async def on_message(self, message: discord.Message) -> None:
        if message.guild is None or message.author.bot or self.core is None:
            return
        author = message.author
        is_member = isinstance(author, discord.Member)
        role_ids = [r.id for r in author.roles] if is_member else []
        manager = is_member and (author.guild_permissions.manage_guild or author.guild_permissions.administrator)
        try:
            self.core.tickets.record_activity(message.channel.id, author.id, role_ids, bool(manager))
        except sqlite3.Error:
            log.exception("activity.record_failed channel=%s", message.channel.id)

    async def on_guild_channel_delete(self, channel: discord.abc.GuildChannel) -> None:
        if self.core is None or self.db is None:
            return
        try:
            await self.core.tickets.handle_channel_deleted(channel.id)
            for panel in self.db.panels_using_channel(channel.id):
                if channel.id == panel.panel_channel_id:
                    self.db.set_panel_message(panel.id, None)
                self.db.set_panel_status(panel.id, "MISCONFIGURED", expected=("ACTIVE", "PAUSED"),
                                         reason=f"channel {channel.id} deleted")
                if channel.id != panel.log_channel_id:
                    await best_effort(self.core.gw.post_notice(panel.log_channel_id, MSG["panel_problem"].format(
                        name=panel.name, problems=f"deleted channel {channel.name}")), "panel_problem_notice")
                log.warning("panel.channel_deleted panel=%s channel=%s", panel.id, channel.id)
        except sqlite3.Error:
            log.exception("event.channel_delete_failed channel=%s", channel.id)

    async def on_raw_thread_delete(self, payload: discord.RawThreadDeleteEvent) -> None:
        """A private-thread ticket was deleted by hand -> same handling as a deleted channel."""
        if self.core is None:
            return
        try:
            await self.core.tickets.handle_channel_deleted(payload.thread_id)
        except sqlite3.Error:
            log.exception("event.thread_delete_failed thread=%s", payload.thread_id)

    async def on_raw_message_delete(self, payload: discord.RawMessageDeleteEvent) -> None:
        if self.db is None or self.core is None:
            return
        panel = self.db.panel_by_message(payload.message_id)
        if panel:
            self.db.set_panel_message(panel.id, None)
            await best_effort(self.core.gw.post_notice(panel.log_channel_id, MSG["panel_problem"].format(
                name=panel.name, problems="رسالة البانل حُذفت — استخدم «إعادة نشر» من /setup")), "panel_msg_notice")

    async def on_raw_member_remove(self, payload: discord.RawMemberRemoveEvent) -> None:
        """Only fires when ENABLE_MEMBERS_INTENT=True; otherwise the periodic job covers it."""
        if self.core is not None:
            await self.core.automation.owner_left(payload.guild_id, payload.user.id)

    async def on_app_command_error(self, interaction: discord.Interaction, error: app_commands.AppCommandError) -> None:
        log.error("command.error command=%s", interaction.command.name if interaction.command else "?", exc_info=error)
        await safe_reply(interaction, "حدث خطأ غير متوقع وتم تسجيله.")

    async def close(self) -> None:
        """Graceful shutdown: stop the scheduler (jobs stay persisted), then close the DB."""
        log.info("bot.shutdown_begin")
        if self.core is not None:
            await self.core.scheduler.stop()
        await super().close()
        if self.db is not None:
            self.db.close()
            self.db = None
        log.info("bot.shutdown_done")


# =============================================================================
# 11. ENTRY POINT
# =============================================================================

def validate_token_setting(token: str) -> Optional[str]:
    """Refuse the placeholder / obviously invalid tokens without ever printing the value."""
    token = (token or "").strip()
    if not token or token.lower() in {"placeholder", "your_token_here", "token", "changeme"}:
        return ("BOT_TOKEN is still the placeholder. Open main.py, set BOT_TOKEN to your real bot token, "
                "and NEVER share or publish that copy of the file.")
    if token.count(".") != 2 or len(token) < 50 or any(c.isspace() for c in token):
        return "BOT_TOKEN does not look like a Discord bot token (value not shown)."
    return None


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Tazkara Discord ticket bot")
    parser.add_argument("--init-key", action="store_true", help="create the archive encryption key")
    parser.add_argument("--decrypt", nargs=2, metavar=("ENC_FILE", "OUT_HTML"), help="decrypt a local archive")
    parser.add_argument("--check", action="store_true", help="validate configuration and exit")
    args = parser.parse_args(argv)
    setup_logging()
    key_path = configured_key_path()

    if args.init_key:
        try:
            created = init_key_file(key_path)
        except (FileExistsError, VaultError, OSError) as exc:
            log.error("init-key failed: %s", exc)
            return 2
        print(f"Key created at: {created}\nBack it up OFFLINE, separately from data.db/archives. "
              "Losing it makes local archives unreadable.")
        return 0

    if args.decrypt:
        try:
            vault = ArchiveVault.load(key_path, ARCHIVE_DIR)
            Path(args.decrypt[1]).write_bytes(vault.decrypt(Path(args.decrypt[0]).read_bytes()))
        except (VaultError, OSError) as exc:
            log.error("decrypt failed: %s", exc)
            return 2
        print("Decrypted. Treat the output as confidential (contains ticket conversations).")
        return 0

    token_error = validate_token_setting(BOT_TOKEN)
    if token_error:
        log.error(token_error)
        return 2
    REDACTOR.add_secret(BOT_TOKEN.strip())
    try:
        vault = ArchiveVault.load(key_path, ARCHIVE_DIR)
    except VaultError as exc:
        log.error("archive key problem: %s", exc)
        return 2
    if args.check:
        db = Database(DB_PATH)
        ok = db.integrity_ok()
        db.close()
        print(f"config OK, db integrity={'ok' if ok else 'FAILED'}, permissions integer={bot_permissions_value()}")
        return 0 if ok else 2

    bot = TazkaraBot(vault)
    try:
        bot.run(BOT_TOKEN.strip(), log_handler=None)
    except discord.LoginFailure:
        log.error("Login failed: the token was rejected by Discord (value not shown). Reset it in the Developer Portal.")
        return 3
    except discord.PrivilegedIntentsRequired:
        log.error("Enable 'MESSAGE CONTENT INTENT' (and SERVER MEMBERS if ENABLE_MEMBERS_INTENT=True) in the "
                  "Developer Portal -> Bot -> Privileged Gateway Intents.")
        return 3
    return 0



# =============================================================================
# 12. TESTS — run with:  pytest main.py -q
# =============================================================================
# The services are exercised through FakeGateway, which can inject every
# Discord failure mode. No network access or real token is needed.

try:
    import pytest
except ImportError:  # pytest is only needed to run the tests, not the bot
    pytest = None  # type: ignore[assignment]

class FakeClock:
    def __init__(self, start: int = 1_700_000_000) -> None:
        self.t = start

    def __call__(self) -> int:
        return self.t


class FakeGateway:
    """In-memory Discord stand-in with failure injection (``fail[method] = [GatewayError, ...]``)."""

    def __init__(self) -> None:
        self.channels: dict[int, dict[str, Any]] = {}
        self.log_messages: dict[int, dict[int, tuple[str, bytes]]] = {}
        self.log_channels: set[int] = {8001}
        self.fail: dict[str, list[GatewayError]] = {}
        self.calls: list[str] = []
        self.notices: list[tuple[int, str, dict[str, Any]]] = []
        self.dms: list[tuple[int, str]] = []
        self.next_id = 10_000
        self.create_delay = 0.0
        self.create_then_fail: Optional[GatewayError] = None
        self.upload_then_fail: Optional[GatewayError] = None
        self.member_is_present = True
        self.omissions: list[str] = []
        self.fatal: Optional[str] = None
        self.panel_problems: list[str] = []
        self.upload_limit_value = 10 * 1024 * 1024
        self.on_final_check: Optional[Callable[[], Awaitable[None]]] = None

    def _hit(self, name: str) -> None:
        self.calls.append(name)
        queue = self.fail.get(name)
        if queue:
            raise queue.pop(0)

    def _new_id(self) -> int:
        self.next_id += 1
        return self.next_id

    def add_message(self, channel_id: int, author_id: int, content: str, *, is_bot: bool = False,
                    attachments: Optional[list[TranscriptAttachment]] = None) -> None:
        self.channels[channel_id]["messages"].append(TranscriptMessage(
            self._new_id(), author_id, f"user{author_id}", is_bot, 1_700_000_000, content,
            attachments=attachments or []))

    async def create_ticket_channel(self, panel: Panel, roles: PanelRoles, ticket: Ticket, owner_name: str) -> int:
        if self.create_delay:
            await asyncio.sleep(self.create_delay)
        self._hit("create_ticket_channel")
        channel_id = self._new_id()
        self.channels[channel_id] = {"guild": panel.guild_id, "ticket": ticket.id, "messages": [], "locked": False}
        if self.create_then_fail:
            error, self.create_then_fail = self.create_then_fail, None
            raise error
        return channel_id

    async def create_ticket_thread(self, panel: Panel, ticket: Ticket, owner_name: str) -> int:
        self._hit("create_ticket_thread")
        thread_id = self._new_id()
        self.channels[thread_id] = {"guild": panel.guild_id, "ticket": ticket.id, "messages": [], "locked": False,
                                    "thread": True, "parent": panel.panel_channel_id, "members": {ticket.owner_id}}
        return thread_id

    async def add_ticket_member(self, channel_id: int, user_id: int) -> bool:
        self._hit("add_ticket_member")
        if channel_id not in self.channels:
            raise GatewayError(GatewayError.NOT_FOUND, "gone")
        if not self.channels[channel_id].get("thread"):
            return False
        self.channels[channel_id]["members"].add(user_id)
        return True

    async def find_ticket_channel(self, guild_id: int, ticket_id: int) -> Optional[int]:
        return next((cid for cid, ch in self.channels.items() if ch["ticket"] == ticket_id), None)

    async def list_marked_channels(self, guild_id: int) -> list[tuple[int, int]]:
        return [(cid, ch["ticket"]) for cid, ch in self.channels.items()]

    async def channel_exists(self, channel_id: int) -> bool:
        self._hit("channel_exists")
        return channel_id in self.channels

    async def delete_channel(self, channel_id: int, reason: str) -> None:
        self._hit("delete_channel")
        if channel_id not in self.channels:
            raise GatewayError(GatewayError.NOT_FOUND, "gone")
        del self.channels[channel_id]

    async def send_control_message(self, ticket: Ticket, panel: Panel) -> int:
        self._hit("send_control_message")
        return self._new_id()

    async def update_control_message(self, ticket: Ticket, panel: Panel) -> None:
        self._hit("update_control_message")

    async def set_channel_locked(self, ticket: Ticket, roles: PanelRoles, locked: bool) -> None:
        self._hit("set_channel_locked")
        if ticket.channel_id in self.channels:
            self.channels[ticket.channel_id]["locked"] = locked

    async def post_notice(self, channel_id: int, text: str, **kwargs: Any) -> None:
        self._hit("post_notice")
        self.notices.append((channel_id, text, kwargs))

    async def collect_transcript(self, ticket: Ticket, panel: Panel, attachment_budget: int) -> TranscriptCollection:
        self._hit("collect_transcript")
        msgs = list(self.channels[ticket.channel_id]["messages"])
        return TranscriptCollection(msgs, msgs[-1].id if msgs else None, "Guild <b>", "chan", "owner",
                                    self.fatal, list(self.omissions))

    async def human_messages_after(self, channel_id: int, message_id: int) -> bool:
        self._hit("human_messages_after")
        if self.on_final_check:
            hook, self.on_final_check = self.on_final_check, None
            await hook()
        return any(not m.is_bot and m.id > message_id for m in self.channels.get(channel_id, {"messages": []})["messages"])

    async def upload_limit(self, guild_id: int) -> int:
        return self.upload_limit_value

    async def upload_log_copy(self, log_channel_id: int, filename: str, data: bytes, summary: dict[str, Any],
                              marker: str) -> int:
        self._hit("upload_log_copy")
        if log_channel_id not in self.log_channels:
            raise GatewayError(GatewayError.NOT_FOUND, "log channel missing")
        message_id = self._new_id()
        self.log_messages.setdefault(log_channel_id, {})[message_id] = (marker, data)
        if self.upload_then_fail:
            error, self.upload_then_fail = self.upload_then_fail, None
            raise error
        return message_id

    async def find_log_copy(self, log_channel_id: int, marker: str) -> Optional[int]:
        return next((mid for mid, (mk, _d) in self.log_messages.get(log_channel_id, {}).items() if mk == marker), None)

    async def download_log_copy(self, log_channel_id: int, message_id: int) -> Optional[bytes]:
        self._hit("download_log_copy")
        entry = self.log_messages.get(log_channel_id, {}).get(message_id)
        return entry[1] if entry else None

    async def send_dm(self, user_id: int, text: str) -> None:
        self._hit("send_dm")
        self.dms.append((user_id, text))

    async def member_present(self, guild_id: int, user_id: int) -> bool:
        self._hit("member_present")
        return self.member_is_present

    async def check_panel_resources(self, panel: Panel) -> list[str]:
        return list(self.panel_problems)

    def log_uploads(self) -> int:
        return sum(len(v) for v in self.log_messages.values())


T_GUILD, T_OWNER, T_STAFF_ROLE, T_ADMIN_ROLE, T_STAFF, T_ADMIN, T_RANDOM, T_LOG = (
    111, 501, 9001, 9002, 601, 602, 701, 8001)
T_STAFF_ACTOR = Actor(T_STAFF, frozenset({T_STAFF_ROLE}), False)
T_ADMIN_ACTOR = Actor(T_ADMIN, frozenset({T_ADMIN_ROLE}), False)
T_OWNER_ACTOR = Actor(T_OWNER, frozenset(), False)
T_RANDOM_ACTOR = Actor(T_RANDOM, frozenset(), False)


@dataclass
class _Env:
    tmp: Path
    clock: FakeClock
    db: Database
    gw: FakeGateway
    vault: ArchiveVault
    core: TazkaraCore
    panel_id: int


def _make_env(tmp: Path, vault: Optional[ArchiveVault] = None, **panel_overrides: Any) -> _Env:
    clock = FakeClock()
    db = Database(tmp / "data.db", clock)
    gw = FakeGateway()
    vault = vault or ArchiveVault(Fernet.generate_key())
    core = TazkaraCore(db, gw, vault, tmp / "archives", clock)
    fields: dict[str, Any] = dict(guild_id=T_GUILD, name="Support", embed_title="Help", embed_description="Open one",
                                  button_label="Open", channel_name_template="ticket-{number}",
                                  admin_role_ids=[T_ADMIN_ROLE], staff_role_ids=[T_STAFF_ROLE], category_id=7001,
                                  panel_channel_id=7002, log_channel_id=T_LOG)
    fields.update(panel_overrides)
    panel_id = db.save_panel(PanelDraft(**fields), actor_id=1)
    db.set_panel_message(panel_id, 5555)
    return _Env(tmp, clock, db, gw, vault, core, panel_id)


def _restart(env: _Env) -> _Env:
    """Simulate a process restart: new DB connection + new services, same disk and same 'Discord'."""
    db = Database(env.tmp / "data.db", env.clock)
    core = TazkaraCore(db, env.gw, env.vault, env.tmp / "archives", env.clock)
    return _Env(env.tmp, env.clock, db, env.gw, env.vault, core, env.panel_id)


async def _open(env: _Env, owner: int = T_OWNER) -> OpResult:
    return await env.core.tickets.open_ticket(T_GUILD, env.panel_id, owner, f"Owner{owner}", 5555)


async def _drain(env: _Env, rounds: int = 40) -> int:
    total = 0
    for _ in range(rounds):
        ran = await env.core.scheduler.run_once()
        total += ran
        if ran == 0:
            break
    return total


async def _close(env: _Env, ticket: Ticket, actor: Actor = T_OWNER_ACTOR) -> OpResult:
    return await env.core.tickets.request_close(ticket.id, actor, T_GUILD, ticket.channel_id, "done")


def _count(db: Database, sql: str, params: tuple[Any, ...] = ()) -> int:
    return int(db.conn.execute(sql, params).fetchone()[0])


# ---- 1 ----------------------------------------------------------------------
def test_01_open_ticket_normal(tmp_path: Path) -> None:
    async def scenario() -> None:
        env = _make_env(tmp_path)
        res = await _open(env)
        assert res.ok and res.code == "created"
        t = env.db.get_ticket(res.ticket.id)
        assert t.state == S_OPEN and t.number == 1 and t.channel_id in env.gw.channels
        assert t.control_message_id is not None
        assert _count(env.db, "SELECT COUNT(*) FROM ticket_events WHERE ticket_id=? AND event_type='ticket_opened'", (t.id,)) == 1
    asyncio.run(scenario())


# ---- 2 ----------------------------------------------------------------------
def test_02_duplicate_ticket_blocked_in_python_and_db(tmp_path: Path) -> None:
    async def scenario() -> None:
        env = _make_env(tmp_path)
        first = await _open(env)
        second = await _open(env)
        assert first.ok and not second.ok and second.code == "duplicate"
        assert len(env.gw.channels) == 1
        with pytest.raises(sqlite3.IntegrityError):  # the database itself refuses a second active row
            env.db.conn.execute("INSERT INTO tickets(guild_id, panel_id, number, owner_id, state, create_op_key, "
                                "created_at, updated_at) VALUES(?,?,99,?,'CREATING','x',1,1)",
                                (T_GUILD, env.panel_id, T_OWNER))
        other = await _open(env, owner=999)  # another user is unaffected
        assert other.ok
    asyncio.run(scenario())


# ---- 3 ----------------------------------------------------------------------
def test_03_concurrent_open_clicks(tmp_path: Path) -> None:
    async def scenario() -> None:
        env = _make_env(tmp_path)
        env.gw.create_delay = 0.02
        results = await asyncio.gather(*(_open(env) for _ in range(10)))
        assert sum(r.ok for r in results) == 1
        assert all(r.code == "duplicate" for r in results if not r.ok)
        assert len(env.gw.channels) == 1
        # Bypass the in-memory lock entirely: second service on a second DB connection.
        db2 = Database(tmp_path / "data.db", env.clock)
        svc2 = TicketService(db2, env.gw, env.clock)
        results = await asyncio.gather(
            env.core.tickets.open_ticket(T_GUILD, env.panel_id, 777, "x", 5555),
            svc2.open_ticket(T_GUILD, env.panel_id, 777, "x", 5555))
        assert sum(r.ok for r in results) == 1
        assert _count(env.db, "SELECT COUNT(*) FROM tickets WHERE owner_id=777 AND state IN ('CREATING','OPEN','ON_HOLD')") == 1
    asyncio.run(scenario())


# ---- 4 ----------------------------------------------------------------------
def test_04_unprivileged_user_cannot_use_staff_buttons(tmp_path: Path) -> None:
    async def scenario() -> None:
        env = _make_env(tmp_path)
        t = (await _open(env)).ticket
        ch = t.channel_id
        for actor in (T_RANDOM_ACTOR, T_OWNER_ACTOR):
            assert (await env.core.tickets.claim(t.id, actor, T_GUILD, ch)).code == "forbidden"
            assert (await env.core.tickets.toggle_hold(t.id, actor, T_GUILD, ch)).code == "forbidden"
        assert (await env.core.tickets.request_close(t.id, T_RANDOM_ACTOR, T_GUILD, ch, "x")).code == "forbidden"
        assert env.core.tickets.check_close(t.id, T_RANDOM_ACTOR, T_GUILD, ch).code == "forbidden"
        after = env.db.get_ticket(t.id)
        assert after.state == S_OPEN and after.claimed_by is None
        ok = await env.core.tickets.claim(t.id, T_STAFF_ACTOR, T_GUILD, ch)
        assert ok.ok and env.db.get_ticket(t.id).claimed_by == T_STAFF
        assert (await env.core.tickets.claim(t.id, T_ADMIN_ACTOR, T_GUILD, ch)).code == "already_claimed"
        await _close(env, t)
        assert (await env.core.tickets.reopen(t.id, T_OWNER_ACTOR, T_GUILD, ch)).code == "forbidden"
        assert (await env.core.tickets.reopen(t.id, T_RANDOM_ACTOR, T_GUILD, ch)).code == "forbidden"
    asyncio.run(scenario())


# ---- 5 ----------------------------------------------------------------------
def test_05_stale_interactions_after_close_do_not_change_state(tmp_path: Path) -> None:
    async def scenario() -> None:
        env = _make_env(tmp_path)
        t = (await _open(env)).ticket
        ch = t.channel_id
        await _close(env, t)
        await _drain(env)
        assert env.db.get_ticket(t.id).state == S_CLOSED
        events_before = _count(env.db, "SELECT COUNT(*) FROM ticket_events WHERE ticket_id=?", (t.id,))
        for call in (env.core.tickets.claim, env.core.tickets.toggle_hold, env.core.tickets.reopen):
            res = await call(t.id, T_STAFF_ACTOR, T_GUILD, ch)
            assert not res.ok and res.code == "bad_state"
        assert not (await _close(env, env.db.get_ticket(t.id), T_STAFF_ACTOR)).ok
        assert env.db.get_ticket(t.id).state == S_CLOSED
        assert _count(env.db, "SELECT COUNT(*) FROM ticket_events WHERE ticket_id=?", (t.id,)) == events_before
        # custom_id pointing at a ticket of another channel/guild is rejected as stale
        t2 = (await _open(env, owner=888)).ticket
        assert (await env.core.tickets.claim(t2.id, T_STAFF_ACTOR, T_GUILD, 424242)).code == "stale"
        assert (await env.core.tickets.claim(t2.id, T_STAFF_ACTOR, 999, t2.channel_id)).code == "stale"
    asyncio.run(scenario())


# ---- 6 ----------------------------------------------------------------------
def test_06_channel_creation_failure(tmp_path: Path) -> None:
    async def scenario() -> None:
        env = _make_env(tmp_path)
        env.gw.fail["create_ticket_channel"] = [GatewayError(GatewayError.FORBIDDEN, "missing_permissions:manage_roles")]
        res = await _open(env)
        assert res.code == "channel_failed" and not env.gw.channels
        assert _count(env.db, "SELECT COUNT(*) FROM tickets WHERE state='FAILED'") == 1
        assert env.db.get_panel(env.panel_id).status == "MISCONFIGURED"
        assert (await _open(env)).code == "panel_misconfigured"
        env.db.set_panel_status(env.panel_id, "ACTIVE")
        assert (await _open(env)).ok  # FAILED is not "active": user can retry
    asyncio.run(scenario())


def test_06b_uncertain_creation_is_reconciled_not_duplicated(tmp_path: Path) -> None:
    async def scenario() -> None:
        env = _make_env(tmp_path)
        env.gw.create_then_fail = GatewayError(GatewayError.UNCERTAIN, "http=503")  # channel WAS created
        res = await _open(env)
        assert res.code == "uncertain"
        assert (await _open(env)).code == "duplicate"  # no second channel while unresolved
        assert len(env.gw.channels) == 1
        env.clock.t += CREATION_RECONCILE_DELAY + 1
        await _drain(env)
        t = env.db.get_ticket(res.ticket.id if res.ticket else 1)
        assert t.state == S_OPEN and t.channel_id in env.gw.channels and len(env.gw.channels) == 1
        # Uncertain + channel really NOT created -> FAILED after grace, user may retry.
        env.gw.fail["create_ticket_channel"] = [GatewayError(GatewayError.UNCERTAIN, "timeout")]
        res2 = await _open(env, owner=321)
        assert res2.code == "uncertain"
        env.clock.t += CREATION_GRACE_SECONDS + 5
        await _drain(env)
        assert _count(env.db, "SELECT COUNT(*) FROM tickets WHERE owner_id=321 AND state='FAILED'") == 1
    asyncio.run(scenario())


# ---- 7 ----------------------------------------------------------------------
def test_07_db_write_failure(tmp_path: Path) -> None:
    async def scenario() -> None:
        env = _make_env(tmp_path)
        original_create = env.db.create_ticket

        def broken_create(*a: Any, **k: Any) -> Ticket:
            raise sqlite3.OperationalError("disk I/O error")
        env.db.create_ticket = broken_create  # type: ignore[method-assign]
        res = await _open(env)
        assert res.code == "db_error" and "create_ticket_channel" not in env.gw.calls  # no Discord call without a row
        env.db.create_ticket = original_create  # type: ignore[method-assign]

        original_transition = env.db.transition
        state = {"failed": False}

        def flaky_transition(ticket_id: int, from_states: Sequence[str], to_state: str, **kw: Any) -> Optional[Ticket]:
            if to_state == S_OPEN and not state["failed"]:
                state["failed"] = True
                raise sqlite3.OperationalError("database is locked")
            return original_transition(ticket_id, from_states, to_state, **kw)
        env.db.transition = flaky_transition  # type: ignore[method-assign]
        res = await _open(env)
        assert res.code == "db_error"
        assert not env.gw.channels  # compensation removed the created channel
        assert _count(env.db, "SELECT COUNT(*) FROM tickets WHERE state='FAILED'") == 1

        # Compensation itself fails -> ticket stays CREATING; reconciliation adopts the channel later.
        state["failed"] = False
        env.gw.fail["delete_channel"] = [GatewayError(GatewayError.TRANSIENT, "429")]
        res = await _open(env, owner=654)
        assert res.code == "db_error" and len(env.gw.channels) == 1
        env.db.transition = original_transition  # type: ignore[method-assign]
        stuck = env.db.get_active_ticket(T_GUILD, env.panel_id, 654)
        assert stuck.state == S_CREATING
        await env.core.reconciler.reconcile_creating(stuck)
        adopted = env.db.get_ticket(stuck.id)
        assert adopted.state == S_OPEN and adopted.channel_id in env.gw.channels
    asyncio.run(scenario())


# ---- 8 ----------------------------------------------------------------------
def test_08_restart_with_open_tickets(tmp_path: Path) -> None:
    async def scenario() -> None:
        env = _make_env(tmp_path)
        a = (await _open(env, owner=1001)).ticket
        b = (await _open(env, owner=1002)).ticket
        c = env.db.create_ticket(T_GUILD, env.panel_id, 1003)  # crashed mid-creation...
        env.gw.channels[55555] = {"guild": T_GUILD, "ticket": c.id, "messages": [], "locked": False}  # ...after the channel existed
        del env.gw.channels[b.channel_id]  # b's channel was deleted by hand while the bot was offline
        channels_before = len(env.gw.channels)
        env.clock.t += 3600
        env2 = _restart(env)
        await env2.core.reconciler.reconcile_all()
        assert env2.db.get_ticket(a.id).state == S_OPEN
        assert env2.db.get_ticket(b.id).state == S_LOST
        assert env2.db.get_ticket(c.id).state == S_OPEN and env2.db.get_ticket(c.id).channel_id == 55555
        assert len(env.gw.channels) == channels_before  # nothing duplicated
        assert "create_ticket_channel" not in env.gw.calls[env.gw.calls.index("channel_exists"):]
    asyncio.run(scenario())


# ---- 9 ----------------------------------------------------------------------
def test_09_buttons_and_jobs_restored_after_restart(tmp_path: Path) -> None:
    async def scenario() -> None:
        env = _make_env(tmp_path, sla_enabled=True, sla_first_response_min=30)
        t = (await _open(env)).ticket
        job = env.db.get_job(f"sla:{t.id}")
        assert job and job.status == "PENDING"
        env.clock.t += 31 * 60
        leased = env.db.claim_due_jobs(env.clock(), 10)  # crash while RUNNING
        assert any(j.kind == "sla" for j in leased)
        env2 = _restart(env)
        summary = await env2.core.reconciler.reconcile_all()
        assert summary["jobs_reset"] >= 1
        await _drain(env2)
        assert env2.db.get_ticket(t.id).sla_breached_at is not None
        assert any(text.startswith(MSG["sla_breach"].split("(")[0]) for _c, text, _k in env.gw.notices)
        # Persistent custom_ids round-trip through the registered DynamicItem templates.
        view = ticket_view(t.id)
        ids = [item.custom_id for item in view.children]
        assert all(TicketActionButton.__discord_ui_compiled_template__.fullmatch(cid) for cid in ids)
        assert PanelOpenButton.__discord_ui_compiled_template__.fullmatch(PanelOpenButton(5).item.custom_id)
        assert ArchiveAckButton.__discord_ui_compiled_template__.fullmatch(ArchiveAckButton(3).item.custom_id)
        for bad in ("tazkara:t:delete:1", "tazkara:t:claim:1;DROP", "tazkara:open:abc", "tazkara:t:claim:" + "9" * 30):
            assert not TicketActionButton.__discord_ui_compiled_template__.fullmatch(bad)
            assert not PanelOpenButton.__discord_ui_compiled_template__.fullmatch(bad)
    asyncio.run(scenario())


# ---- 10 ---------------------------------------------------------------------
def test_10_log_upload_failure_keeps_channel_then_recovers(tmp_path: Path) -> None:
    async def scenario() -> None:
        env = _make_env(tmp_path)
        t = (await _open(env)).ticket
        env.gw.add_message(t.channel_id, T_OWNER, "hello")
        env.gw.fail["upload_log_copy"] = [GatewayError(GatewayError.TRANSIENT, "429")]
        await _close(env, t)
        await _drain(env)
        a = env.db.get_live_archive(t.id)
        assert a.log_status == "FAILED" and a.local_status == "VERIFIED"
        assert env.db.get_ticket(t.id).state == S_CLOSING and t.channel_id in env.gw.channels
        assert "delete_channel" not in env.gw.calls
        env.clock.t += RETRY_MAX_SECONDS
        await _drain(env)
        assert env.db.get_ticket(t.id).state == S_CLOSED and t.channel_id not in env.gw.channels
        done = env.db.archives_for_ticket(t.id)[-1]
        assert done.status == "COMPLETE" and done.local_attempts == 1 and env.gw.log_uploads() == 1
    asyncio.run(scenario())


def test_10b_uncertain_upload_is_found_by_marker_not_duplicated(tmp_path: Path) -> None:
    async def scenario() -> None:
        env = _make_env(tmp_path)
        t = (await _open(env)).ticket
        env.gw.upload_then_fail = GatewayError(GatewayError.UNCERTAIN, "http=502")
        await _close(env, t)
        await _drain(env)
        assert env.db.get_live_archive(t.id).log_status == "SENDING"
        env.clock.t += RETRY_MAX_SECONDS
        await _drain(env)
        assert env.db.get_ticket(t.id).state == S_CLOSED
        assert env.gw.log_uploads() == 1  # outbox marker prevented a duplicate upload
    asyncio.run(scenario())


# ---- 11 ---------------------------------------------------------------------
def test_11_local_write_failure_keeps_channel_then_recovers(tmp_path: Path) -> None:
    async def scenario() -> None:
        env = _make_env(tmp_path)
        t = (await _open(env)).ticket
        original = env.vault.write_verified
        calls = {"n": 0}

        def flaky(path: Path, plaintext: bytes, sha: str) -> str:
            calls["n"] += 1
            if calls["n"] == 1:
                raise OSError(28, "No space left on device")
            return original(path, plaintext, sha)
        env.vault.write_verified = flaky  # type: ignore[method-assign]
        await _close(env, t)
        await _drain(env)
        a = env.db.get_live_archive(t.id)
        assert a.local_status == "FAILED" and a.log_status == "VERIFIED"
        assert t.channel_id in env.gw.channels and env.db.get_ticket(t.id).state == S_CLOSING
        env.clock.t += RETRY_MAX_SECONDS
        await _drain(env)
        done = env.db.archives_for_ticket(t.id)[-1]
        assert done.status == "COMPLETE" and env.gw.log_uploads() == 1  # recovered from the log copy, same hash
        assert (env.tmp / "archives" / done.local_path).is_file()
    asyncio.run(scenario())


# ---- 12 ---------------------------------------------------------------------
class _CorruptingVault(ArchiveVault):
    def encrypt(self, data: bytes) -> bytes:
        token = super().encrypt(data)
        return token[:-8] + (b"A" * 8 if not token.endswith(b"A" * 8) else b"B" * 8)


def test_12_encryption_or_integrity_failure_never_claims_success(tmp_path: Path) -> None:
    async def scenario() -> None:
        env = _make_env(tmp_path, vault=_CorruptingVault(Fernet.generate_key()))
        t = (await _open(env)).ticket
        await _close(env, t)
        await _drain(env)
        a = env.db.get_live_archive(t.id)
        assert a.local_status == "FAILED" and "integrity" in (a.local_error or "")
        assert not list((env.tmp / "archives").rglob("*.enc"))  # corrupt file removed, never kept as "valid"
        assert env.db.get_ticket(t.id).state == S_CLOSING and t.channel_id in env.gw.channels
        other = ArchiveVault(Fernet.generate_key())
        with pytest.raises(VaultError):
            other.decrypt(ArchiveVault(Fernet.generate_key()).encrypt(b"secret"))
        with pytest.raises(VaultError):
            ArchiveVault(b"not-a-key")
    asyncio.run(scenario())


# ---- 13 ---------------------------------------------------------------------
def test_13_channel_never_deleted_before_both_archives(tmp_path: Path) -> None:
    async def scenario() -> None:
        env = _make_env(tmp_path)
        t = (await _open(env)).ticket
        env.gw.fail["upload_log_copy"] = [GatewayError(GatewayError.FORBIDDEN, "x") for _ in range(5)]

        def always_fail(*a: Any) -> str:
            raise OSError(13, "Permission denied")
        env.vault.write_verified = always_fail  # type: ignore[method-assign]
        await _close(env, t)
        for _ in range(5):
            await _drain(env)
            env.clock.t += RETRY_MAX_SECONDS
        assert "delete_channel" not in env.gw.calls and t.channel_id in env.gw.channels
        assert env.db.get_ticket(t.id).state == S_CLOSING
        a = env.db.get_live_archive(t.id)
        assert not env.db.complete_archive_and_close(t.id, a.id)
        with pytest.raises(sqlite3.IntegrityError):  # CHECK constraint: COMPLETE requires both verified copies
            env.db.conn.execute("UPDATE archives SET status='COMPLETE' WHERE id=?", (a.id,))
        job = env.db.get_job(f"delete_channel:{t.id}")
        assert job is None
        fake = Job(0, "delete_channel", "x", T_GUILD, t.id, 0, "RUNNING", None, 1, 1, "{}", None)
        assert (await env.core.post_close.delete_channel(fake)).status == "done"
        assert t.channel_id in env.gw.channels  # handler refuses: ticket not CLOSED
    asyncio.run(scenario())


# ---- 14 ---------------------------------------------------------------------
def test_14_html_injection_is_neutralised(tmp_path: Path) -> None:
    evil = '<script>alert(1)</script><img src=x onerror=alert(2)><a href="javascript:alert(3)">x</a>'
    meta = TranscriptMeta('G"><script>', 1, "<b>chan</b>", 1, 1, "<i>p</i>", 2, "<svg onload=alert(4)>", 0, None,
                          "</td><script>", 0)
    svg = TranscriptAttachment('a"onmouseover="x.svg', 50, b'<svg xmlns="http://www.w3.org/2000/svg" onload="alert(5)"/>')
    png = TranscriptAttachment("ok.png", 20, b"\x89PNG\r\n\x1a\n" + b"0" * 12)
    msgs = [TranscriptMessage(1, 2, '<img src=x onerror="alert(6)">', False, 0, evil + "\nhttps://evil.example/x.js",
                              embeds=[("<script>", "<iframe src='https://evil.example'>")], attachments=[svg, png])]
    out = build_transcript_html(meta, msgs).decode()
    assert "<script" not in out.lower() and "<iframe" not in out.lower() and "<svg" not in out.lower()
    assert "<img src=x" not in out and 'href="javascript' not in out
    assert "default-src 'none'" in out
    for attr in re.findall(r'(?:src|href)="([^"]*)"', out):
        assert attr.startswith("data:"), attr  # no external resources at all
    assert out.count("<img ") == 1 and 'src="data:image/png;base64,' in out  # only the real PNG is an image

    async def scenario() -> None:  # end-to-end: what reaches the log channel is escaped too
        env = _make_env(tmp_path)
        t = (await _open(env)).ticket
        env.gw.add_message(t.channel_id, T_OWNER, evil)
        await _close(env, t)
        await _drain(env)
        data = next(iter(env.gw.log_messages[T_LOG].values()))[1].decode()
        assert "<script>alert(1)" not in data and "&lt;script&gt;" in data
    asyncio.run(scenario())


# ---- 15 ---------------------------------------------------------------------
def test_15_sql_injection_inputs_are_inert(tmp_path: Path) -> None:
    async def scenario() -> None:
        evil = "x'); DROP TABLE tickets;--"
        env = _make_env(tmp_path, name=evil, embed_title=evil, embed_description=evil + "\n' OR '1'='1")
        panel = env.db.get_panel(env.panel_id)
        assert panel.name == evil
        t = (await _open(env)).ticket
        await env.core.tickets.request_close(t.id, T_OWNER_ACTOR, T_GUILD, t.channel_id, "'; DELETE FROM panels;--")
        assert env.db.get_ticket(t.id).close_reason == "'; DELETE FROM panels;--"
        assert _count(env.db, "SELECT COUNT(*) FROM sqlite_master WHERE name IN ('tickets','panels')") == 2
        assert env.db.integrity_ok()
        with pytest.raises(ValueError):
            env.db.update_ticket_if(t.id, ALL_STATES, {"state='OPEN'; DROP TABLE tickets;--": 1})
        with pytest.raises(ValueError):
            env.db.update_archive(1, **{"status=1 --": 1})
    asyncio.run(scenario())
    assert validate_name_template("{0.__class__}") is not None
    assert validate_name_template("t-{number}-{__import__('os')}") is not None
    assert validate_name_template("t-{number") is not None
    assert validate_name_template("{panel}-{number}") is None
    assert render_channel_name("t-{number}-{user}", 7, "{panel}<script>", "x") == "t-0007-panel-script"


# ---- 16 ---------------------------------------------------------------------
_WARN = "لم يصلنا ردك"


def test_16_inactivity_timer_frozen_during_hold(tmp_path: Path) -> None:
    async def scenario() -> None:
        env = _make_env(tmp_path, inactivity_enabled=True, inactivity_timeout_min=60, inactivity_warning_min=10)
        t = (await _open(env)).ticket
        env.core.tickets.record_activity(t.channel_id, T_STAFF, [T_STAFF_ROLE], False)  # staff spoke -> timer armed
        assert env.db.get_ticket(t.id).inactivity_deadline == env.clock() + 3600
        env.clock.t += 30 * 60
        assert (await env.core.tickets.toggle_hold(t.id, T_STAFF_ACTOR, T_GUILD, t.channel_id)).code == "held"
        env.clock.t += 10 * 3600  # far past the original deadline, but on hold
        await _drain(env)
        held = env.db.get_ticket(t.id)
        assert held.state == S_ON_HOLD and held.inactivity_remaining == 1800
        assert not any(_WARN in text for _c, text, _k in env.gw.notices)
        await env.core.tickets.toggle_hold(t.id, T_STAFF_ACTOR, T_GUILD, t.channel_id)
        resumed = env.db.get_ticket(t.id)
        assert resumed.inactivity_deadline == env.clock() + 1800 and resumed.total_hold_seconds == 36000
        env.clock.t += 1800 - 600 - 1
        await _drain(env)
        assert not any(_WARN in text for _c, text, _k in env.gw.notices)
        env.clock.t += 1
        await _drain(env)
        assert any(_WARN in text for _c, text, _k in env.gw.notices)  # warning before close
        assert env.db.get_ticket(t.id).state == S_OPEN
        env.clock.t += 600
        await _drain(env)
        assert env.db.get_ticket(t.id).state in (S_CLOSING, S_CLOSED)
        # Owner activity disarms the timer.
        t2 = (await _open(env, owner=4242)).ticket
        env.core.tickets.record_activity(t2.channel_id, T_STAFF, [T_STAFF_ROLE], False)
        env.core.tickets.record_activity(t2.channel_id, 4242, [], False)
        assert env.db.get_ticket(t2.id).inactivity_deadline is None
    asyncio.run(scenario())


# ---- 17 ---------------------------------------------------------------------
def test_17_dm_failure_does_not_block_archiving(tmp_path: Path) -> None:
    async def scenario() -> None:
        env = _make_env(tmp_path)
        t = (await _open(env)).ticket
        env.gw.fail["send_dm"] = [GatewayError(GatewayError.FORBIDDEN, "50007 cannot DM")]
        await _close(env, t)
        await _drain(env)
        assert env.db.get_ticket(t.id).state == S_CLOSED and t.channel_id not in env.gw.channels
        assert env.db.op_get(f"dm:{t.id}:1")["status"] == "FAILED" and not env.gw.dms
        t2 = (await _open(env, owner=2020)).ticket
        await _close(env, t2, Actor(2020, frozenset(), False))
        await _drain(env)
        assert len(env.gw.dms) == 1 and "#" in env.gw.dms[0][1]
        assert "hello" not in env.gw.dms[0][1]  # summary only, never the transcript
    asyncio.run(scenario())


# ---- 18 ---------------------------------------------------------------------
def test_18_rate_limits_and_api_errors(tmp_path: Path) -> None:
    async def scenario() -> None:
        env = _make_env(tmp_path)
        t = (await _open(env)).ticket
        env.gw.fail["channel_exists"] = [GatewayError(GatewayError.TRANSIENT, "429")]
        env.gw.fail["collect_transcript"] = [GatewayError(GatewayError.UNCERTAIN, "503")]
        await _close(env, t)
        await _drain(env)
        job = env.db.get_job(f"archive:{t.id}")
        assert job.status == "PENDING" and job.run_at > env.clock() and job.attempts == 1
        env.clock.t += RETRY_MAX_SECONDS
        await _drain(env)
        env.clock.t += RETRY_MAX_SECONDS
        await _drain(env)
        assert env.db.get_ticket(t.id).state == S_CLOSED

        async def crashing(job: Job) -> JobOutcome:
            raise RuntimeError("boom")
        sched = Scheduler(env.db, {"retention_sweep": crashing}, env.clock)
        env.db.schedule_job("retention_sweep", "retention_sweep", env.clock())
        await sched.run_once()
        job = env.db.get_job("retention_sweep")
        assert job.status == "PENDING" and job.last_error == "RuntimeError" and job.run_at > env.clock()
    asyncio.run(scenario())

    resp = lambda status: type("R", (), {"status": status, "reason": "x"})()  # noqa: E731
    assert map_discord_error(discord.HTTPException(resp(429), "slow down")).kind == GatewayError.TRANSIENT
    assert map_discord_error(discord.RateLimited(30.0)).kind == GatewayError.TRANSIENT
    assert map_discord_error(discord.DiscordServerError(resp(503), "down")).kind == GatewayError.UNCERTAIN
    assert map_discord_error(discord.NotFound(resp(404), "gone")).kind == GatewayError.NOT_FOUND
    assert map_discord_error(discord.Forbidden(resp(403), "no")).kind == GatewayError.FORBIDDEN
    assert map_discord_error(discord.HTTPException(resp(400), "bad")).kind == GatewayError.INVALID
    assert map_discord_error(asyncio.TimeoutError()).kind == GatewayError.UNCERTAIN
    assert backoff_delay(1) == RETRY_BASE_SECONDS and backoff_delay(50) == RETRY_MAX_SECONDS


# ---- 19 ---------------------------------------------------------------------
def test_19_category_or_log_channel_changed_or_deleted(tmp_path: Path) -> None:
    async def scenario() -> None:
        env = _make_env(tmp_path)
        t = (await _open(env)).ticket
        env.gw.log_channels.clear()  # log channel deleted by hand
        await _close(env, t)
        await _drain(env)
        assert env.db.get_live_archive(t.id).log_status == "FAILED"
        assert env.db.get_panel(env.panel_id).status == "MISCONFIGURED"
        assert t.channel_id in env.gw.channels and env.db.get_ticket(t.id).state == S_CLOSING
        assert (await _open(env, owner=3030)).code == "panel_misconfigured"
        draft = env.db.draft_from_panel(env.db.get_panel(env.panel_id))  # admin picks a new log channel
        draft.log_channel_id = 8002
        env.gw.log_channels.add(8002)
        env.db.save_panel(draft, actor_id=1)
        assert env.db.get_panel(env.panel_id).status == "ACTIVE"
        env.clock.t += RETRY_MAX_SECONDS
        await _drain(env)
        assert env.db.get_ticket(t.id).state == S_CLOSED and 8002 in env.gw.log_messages

        env.gw.fail["create_ticket_channel"] = [GatewayError(GatewayError.NOT_FOUND, "category_missing")]
        assert (await _open(env, owner=3031)).code == "channel_failed"
        assert env.db.get_panel(env.panel_id).status == "MISCONFIGURED"
        env.db.set_panel_status(env.panel_id, "ACTIVE")
        env.gw.panel_problems = ["category_missing"]
        await env.core.reconciler.reconcile_all()
        assert env.db.get_panel(env.panel_id).status == "MISCONFIGURED"
    asyncio.run(scenario())


# ---- 20 ---------------------------------------------------------------------
def test_20_retention_never_deletes_the_only_valid_copy(tmp_path: Path) -> None:
    async def scenario() -> None:
        env = _make_env(tmp_path)
        t1 = (await _open(env, owner=1)).ticket
        t2 = (await _open(env, owner=2)).ticket
        for t, actor in ((t1, Actor(1, frozenset(), False)), (t2, Actor(2, frozenset(), False))):
            await _close(env, t, actor)
        await _drain(env)
        a1, a2 = env.db.archives_for_ticket(t1.id)[-1], env.db.archives_for_ticket(t2.id)[-1]
        assert a1.status == a2.status == "COMPLETE"
        del env.gw.log_messages[T_LOG][a1.log_message_id]  # someone deleted t1's log copy
        env.clock.t += 29 * 86400
        await env.core.retention.sweep()
        assert env.db.get_archive(a1.id).local_status == "VERIFIED"  # not yet 30 days
        env.clock.t += 2 * 86400
        await env.core.retention.sweep()
        k1, k2 = env.db.get_archive(a1.id), env.db.get_archive(a2.id)
        assert k1.local_status == "RETENTION_HOLD" and (env.tmp / "archives" / k1.local_path).is_file()
        assert k2.local_status == "EXPIRED" and not (env.tmp / "archives" / k2.local_path).exists()
        # A partial archive of a LOST ticket is also kept.
        t3 = (await _open(env, owner=3)).ticket
        env.gw.fail["upload_log_copy"] = [GatewayError(GatewayError.FORBIDDEN, "x")]
        await _close(env, t3, Actor(3, frozenset(), False))
        await _drain(env)
        del env.gw.channels[t3.channel_id]
        await env.core.tickets.handle_channel_deleted(t3.channel_id)
        env.clock.t += 31 * 86400
        await env.core.retention.sweep()
        a3 = env.db.archives_for_ticket(t3.id)[-1]
        assert a3.status == "SUPERSEDED" and a3.local_status == "RETENTION_HOLD"
    asyncio.run(scenario())


# ---- extra hardening tests ---------------------------------------------------
def test_db_triggers_enforce_state_machine(tmp_path: Path) -> None:
    db = Database(tmp_path / "d.db", FakeClock())
    pid = db.save_panel(PanelDraft(guild_id=1, name="p", embed_title="t", embed_description="d", staff_role_ids=[5],
                                   category_id=1, panel_channel_id=2, log_channel_id=3, max_open_tickets=1), 1)
    with pytest.raises(sqlite3.IntegrityError, match="invalid_initial_state"):
        db.conn.execute("INSERT INTO tickets(guild_id,panel_id,number,owner_id,state,create_op_key,created_at,updated_at)"
                        " VALUES(1,?,50,11,'OPEN','k',1,1)", (pid,))
    t = db.create_ticket(1, pid, 10)
    with pytest.raises(sqlite3.IntegrityError, match="invalid_transition"):
        db.conn.execute("UPDATE tickets SET state='CLOSED', channel_id=5 WHERE id=?", (t.id,))
    with pytest.raises(PanelLimitReached):
        db.create_ticket(1, pid, 11)  # max_open_tickets=1
    with pytest.raises(InvalidTransition):
        db.transition(t.id, (S_CREATING,), S_CLOSED)
    assert db.conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1


def test_reopen_racing_archive_completion_wins_cleanly(tmp_path: Path) -> None:
    async def scenario() -> None:
        env = _make_env(tmp_path)
        t = (await _open(env)).ticket

        async def staff_reopens() -> None:
            res = await env.core.tickets.reopen(t.id, T_STAFF_ACTOR, T_GUILD, t.channel_id)
            assert res.ok
        env.gw.on_final_check = staff_reopens
        await _close(env, t)
        await _drain(env)
        assert env.db.get_ticket(t.id).state == S_OPEN and t.channel_id in env.gw.channels
        assert env.db.archives_for_ticket(t.id)[-1].status == "SUPERSEDED"
        assert "delete_channel" not in env.gw.calls
    asyncio.run(scenario())


def test_new_messages_after_transcript_force_rebuild(tmp_path: Path) -> None:
    async def scenario() -> None:
        env = _make_env(tmp_path)
        t = (await _open(env)).ticket

        async def late_message() -> None:
            env.gw.add_message(t.channel_id, T_STAFF, "late reply")
        env.gw.on_final_check = late_message
        await _close(env, t)
        await _drain(env)
        archives = env.db.archives_for_ticket(t.id)
        assert [a.status for a in archives] == ["SUPERSEDED", "COMPLETE"]
        final = next(iter(env.gw.log_messages[T_LOG].values()) for _ in [0])
        assert any(b"late reply" in data for _m, data in env.gw.log_messages[T_LOG].values())
        assert final is not None
    asyncio.run(scenario())


def test_missing_attachments_require_explicit_admin_ack(tmp_path: Path) -> None:
    async def scenario() -> None:
        env = _make_env(tmp_path)
        t = (await _open(env)).ticket
        env.gw.omissions = ["huge.zip"]
        await _close(env, t)
        await _drain(env)
        a = env.db.get_live_archive(t.id)
        assert a.status == "BLOCKED" and t.channel_id in env.gw.channels
        assert any(k.get("ack_archive_id") == a.id for _c, _t, k in env.gw.notices)
        for actor in (T_RANDOM_ACTOR, T_STAFF_ACTOR, T_OWNER_ACTOR):
            assert (await env.core.archive.acknowledge_omissions(a.id, actor, T_GUILD, t.channel_id)).code == "forbidden"
        assert (await env.core.archive.acknowledge_omissions(a.id, T_ADMIN_ACTOR, T_GUILD, t.channel_id)).ok
        await _drain(env)
        assert env.db.get_ticket(t.id).state == S_CLOSED
        html_doc = next(iter(env.gw.log_messages[T_LOG].values()))[1].decode()
        assert "acknowledged" in html_doc
    asyncio.run(scenario())


def test_missing_message_content_intent_blocks_deletion(tmp_path: Path) -> None:
    async def scenario() -> None:
        env = _make_env(tmp_path)
        t = (await _open(env)).ticket
        env.gw.fatal = "MESSAGE_CONTENT intent is disabled"
        await _close(env, t)
        await _drain(env)
        assert env.db.get_ticket(t.id).state == S_CLOSING and t.channel_id in env.gw.channels
        assert env.db.get_live_archive(t.id).transcript_sha256 is None
    asyncio.run(scenario())


def test_secrets_never_logged_and_placeholder_refused(tmp_path: Path) -> None:
    fake_token = "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA.GAbCdE.abcdefghijklmnopqrstuvwxyz0123456789AB"
    assert validate_token_setting("placeholder") is not None
    assert validate_token_setting("") is not None
    assert validate_token_setting("short.bad.token") is not None
    assert validate_token_setting(fake_token) is None
    rf = RedactingFilter()
    rf.add_secret("my-super-secret-fernet-key")
    record = logging.LogRecord("t", logging.ERROR, __file__, 1, "token=%s key=%s", (fake_token, "my-super-secret-fernet-key"), None)
    rf.filter(record)
    text = record.getMessage()
    assert fake_token not in text and "my-super-secret-fernet-key" not in text and "REDACTED" in text
    with pytest.raises(VaultError):
        ArchiveVault.load(tmp_path / "archives" / "k.key", tmp_path / "archives")


def test_main_refuses_placeholder_token(monkeypatch: Any) -> None:
    monkeypatch.setattr(sys.modules[__name__], "setup_logging", lambda *a, **k: None)
    monkeypatch.setattr(sys.modules[__name__], "BOT_TOKEN", "placeholder")
    assert main([]) == 2


def test_permissions_are_minimal() -> None:
    perms = discord.Permissions(bot_permissions_value())
    assert not perms.administrator and perms.manage_channels and perms.manage_roles
    assert not perms.mention_everyone and not perms.manage_guild and not perms.ban_members
    assert perms.create_private_threads and perms.send_messages_in_threads and perms.manage_threads
    assert not perms.create_public_threads and not perms.manage_messages
    intents = build_intents()
    assert intents.message_content and intents.guilds and intents.guild_messages
    assert not intents.presences and intents.members == ENABLE_MEMBERS_INTENT


def test_long_discord_rate_limit_on_channel_creation(tmp_path: Path, monkeypatch: Any) -> None:
    """Real-server finding: Discord can refuse channel creation for ~24h (retry_after≈86400). Fallback OFF."""
    monkeypatch.setattr(sys.modules[__name__], "THREAD_FALLBACK_ENABLED", False)

    async def scenario() -> None:
        env = _make_env(tmp_path)
        env.gw.fail["create_ticket_channel"] = [
            GatewayError(GatewayError.TRANSIENT, "rate_limited retry_after=86348s", retry_after=86348.0)]
        res = await _open(env)
        assert res.code == "create_rate_limited" and "<t:" in res.message
        assert env.db.get_panel(env.panel_id).status == "ACTIVE"  # NOT a configuration problem
        assert sum("Discord" in text for _c, text, _k in env.gw.notices) == 1  # admins told once
        calls_before = env.gw.calls.count("create_ticket_channel")
        rows_before = _count(env.db, "SELECT COUNT(*) FROM tickets")
        for owner in (11, 12, 13):  # more clicks while blocked: no API call, no new rows/numbers
            assert (await _open(env, owner=owner)).code == "create_rate_limited"
        assert env.gw.calls.count("create_ticket_channel") == calls_before
        assert _count(env.db, "SELECT COUNT(*) FROM tickets") == rows_before
        assert sum("Discord" in text for _c, text, _k in env.gw.notices) == 1
        env.clock.t += 86349
        ok = await _open(env)
        assert ok.ok and ok.ticket.number == 2  # numbering continues without a gap per blocked click
        env.gw.fail["create_ticket_channel"] = [GatewayError(GatewayError.TRANSIENT, "http=429", retry_after=3.0)]
        assert (await _open(env, owner=77)).code == "channel_failed_temporary"
        assert env.core.tickets.creation_blocked_until(T_GUILD) is None  # short limits do not block
    asyncio.run(scenario())
    resp = type("R", (), {"status": 429, "reason": "x", "headers": {"Retry-After": "86400"}})()
    assert map_discord_error(discord.HTTPException(resp, "slow")).retry_after == 86400.0
    assert map_discord_error(discord.RateLimited(120.0)).retry_after == 120.0


def test_rate_limit_falls_back_to_private_threads(tmp_path: Path) -> None:
    """With the fallback ON, a 24h channel block does not stop users from opening tickets."""
    async def scenario() -> None:
        env = _make_env(tmp_path)
        env.gw.fail["create_ticket_channel"] = [
            GatewayError(GatewayError.TRANSIENT, "rate_limited retry_after=86348s", retry_after=86348.0)]
        res = await _open(env)
        assert res.ok and res.code == "created_thread"
        thread = env.gw.channels[res.ticket.channel_id]
        assert thread["thread"] and thread["members"] == {T_OWNER} and thread["parent"] == 7002
        assert env.db.get_ticket(res.ticket.id).state == S_OPEN
        assert env.db.get_panel(env.panel_id).status == "ACTIVE"
        joins = [k for _c, _t, k in env.gw.notices if k.get("join_ticket_id")]
        assert len(joins) == 1 and joins[0]["mention_role_ids"] == [T_STAFF_ROLE]
        assert sum("Thread" in text and "Discord" in text and "حد" in text for _c, text, _k in env.gw.notices) == 1
        channel_calls = env.gw.calls.count("create_ticket_channel")
        for owner in (21, 22, 23):  # while blocked: straight to threads, no channel API calls
            r = await _open(env, owner=owner)
            assert r.ok and r.code == "created_thread"
        assert env.gw.calls.count("create_ticket_channel") == channel_calls
        assert (await _open(env, owner=21)).code == "duplicate"  # one active ticket rule still holds
        env.clock.t += 86349  # block over: back to normal channels
        r = await _open(env, owner=30)
        assert r.ok and r.code == "created" and not env.gw.channels[r.ticket.channel_id].get("thread")
    asyncio.run(scenario())


def test_staff_join_button_is_checked_server_side(tmp_path: Path) -> None:
    async def scenario() -> None:
        env = _make_env(tmp_path)
        env.gw.fail["create_ticket_channel"] = [GatewayError(GatewayError.INVALID, "category_full")]
        t = (await _open(env)).ticket
        members = env.gw.channels[t.channel_id]["members"]
        for actor in (T_RANDOM_ACTOR, T_OWNER_ACTOR):
            assert (await env.core.tickets.join_ticket(t.id, actor, T_GUILD)).code == "forbidden"
        assert T_RANDOM not in members
        assert (await env.core.tickets.join_ticket(t.id, T_STAFF_ACTOR, 999)).code == "stale"  # other guild
        res = await env.core.tickets.join_ticket(t.id, T_STAFF_ACTOR, T_GUILD)
        assert res.ok and res.code == "joined" and T_STAFF in members
        # staff can now act inside the thread exactly like in a channel
        assert (await env.core.tickets.claim(t.id, T_STAFF_ACTOR, T_GUILD, t.channel_id)).ok
        await _close(env, t)
        await _drain(env)
        assert env.db.get_ticket(t.id).state == S_CLOSED and t.channel_id not in env.gw.channels
        assert (await env.core.tickets.join_ticket(t.id, T_STAFF_ACTOR, T_GUILD)).code == "bad_state"
        # join on a normal channel ticket is a harmless no-op
        c = (await _open(env, owner=55)).ticket
        assert (await env.core.tickets.join_ticket(c.id, T_STAFF_ACTOR, T_GUILD)).code == "join_not_needed"
    asyncio.run(scenario())


def test_thread_fallback_failure_does_not_misconfigure_panel(tmp_path: Path) -> None:
    async def scenario() -> None:
        env = _make_env(tmp_path)
        env.gw.fail["create_ticket_channel"] = [
            GatewayError(GatewayError.TRANSIENT, "rate_limited", retry_after=5000.0)]
        env.gw.fail["create_ticket_thread"] = [
            GatewayError(GatewayError.FORBIDDEN, "missing_thread_permissions:manage_threads"),
            GatewayError(GatewayError.FORBIDDEN, "missing_thread_permissions:manage_threads")]
        res = await _open(env)
        assert res.code == "create_rate_limited"  # user sees the real reason + when to retry
        assert env.db.get_panel(env.panel_id).status == "ACTIVE"
        assert _count(env.db, "SELECT COUNT(*) FROM tickets WHERE state='FAILED'") == 1
        assert not env.gw.channels  # nothing orphaned
        assert (await _open(env, owner=66)).code == "create_rate_limited"
        assert sum("Manage Threads" in text for _c, text, _k in env.gw.notices) == 1  # admins told once
        # uncertain thread creation is reconciled like a channel (no duplicate)
        env.gw.fail["create_ticket_thread"] = [GatewayError(GatewayError.UNCERTAIN, "503")]
        assert (await _open(env, owner=67)).code == "uncertain"
        assert (await _open(env, owner=67)).code == "duplicate"
    asyncio.run(scenario())


def test_server_channel_cap_maps_to_thread_fallback() -> None:
    resp = type("R", (), {"status": 400, "reason": "x"})()
    err = map_discord_error(discord.HTTPException(resp, {"code": 30013, "message": "Maximum number of guild channels"}))
    assert err.kind == GatewayError.INVALID and err.detail == "guild_channel_limit"
    assert TicketService._fallback_reason(err) == "guild_channel_limit"
    assert TicketService._fallback_reason(GatewayError(GatewayError.FORBIDDEN, "x")) is None
    assert _THREAD_MARKER_RE.search("ticket-0007 ·t42").group(1) == "42"
    assert not _THREAD_MARKER_RE.search("ticket-0007 t42")


if __name__ == "__main__":
    sys.exit(main())
