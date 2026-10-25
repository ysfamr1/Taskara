# Tazkara — وثيقة التصميم (المرحلة الأولى)

> هذه الوثيقة كُتبت **قبل** كتابة `main.py`، ثم نُفِّذ الكود مطابقًا لها. أي اختلاف لاحق موثّق في القسم 9.

---

## 0. القرارات التقنية

| البند | القرار | السبب |
|---|---|---|
| Python | 3.12 موصى به (متوافق 3.11 – 3.13) | اختُبر فعليًا على 3.13 في بيئة التطوير |
| مكتبة Discord | `discord.py>=2.4,<3` (اختُبر على 2.7.1) | `DynamicItem` (للأزرار الدائمة ذات المعرّفات المتغيرة) و `default_values` للقوائم متوفرة منذ 2.4 |
| التشفير | `cryptography` → **Fernet** (AES-128-CBC + HMAC-SHA256، تشفير موثّق Authenticated) | مكتبة معتمدة؛ أي تلاعب بالملف يفشل عند فك التشفير |
| الاختبارات | `pytest` فقط (بدون pytest-asyncio؛ الاختبارات غير المتزامنة تستخدم `asyncio.run`) | أقل اعتماديات |
| قاعدة البيانات | `sqlite3` المدمجة، اتصال واحد، WAL، `busy_timeout=5000`، `foreign_keys=ON`، `synchronous=FULL` | سلامة البيانات قبل السرعة |
| مفتاح التشفير | ملف منفصل **خارج** مجلد المشروع والأرشيف (`%LOCALAPPDATA%\Tazkara\keys\archive.key` على Windows)، يُنشأ صراحةً بالأمر `python main.py --init-key`، ويمكن تغيير مساره بمتغير البيئة `TAZKARA_ARCHIVE_KEY_FILE` | المتطلب يمنع `.env` و `config.py` لكنه يشترط فصل المفتاح عن الملفات المشفرة |

### بنية الملف الواحد `main.py`
```
1. الثوابت والإعدادات (BOT_TOKEN = "placeholder")
2. Logging مع فلتر إخفاء الأسرار
3. أدوات مساعدة نقية (وقت، تحقق، قوالب أسماء القنوات)
4. Schema + طبقة Database (لا تعرف شيئًا عن Discord)
5. آلة الحالات + سياسة الصلاحيات (نقية)
6. منطق المؤقتات (نقي، قابل للاختبار بساعة وهمية)
7. Vault التشفير + بناء Transcript (نقي)
8. Gateway Protocol: واجهة مجردة لكل عملية Discord خارجية
9. الخدمات: TicketService, ArchiveService, AutomationService, RetentionService, Reconciler, Scheduler
10. طبقة Discord: DiscordGateway, Views/DynamicItems, /setup Wizard, Bot, Events
11. نقطة الدخول (CLI)
12. اختبارات pytest (FakeGateway + قاعدة بيانات مؤقتة)
```
الخدمات تتعامل مع Discord **فقط** عبر `Gateway`، لذلك تُختبر كل سيناريوهات الفشل (فشل إنشاء القناة، Rate limit، فشل الرفع...) بـ `FakeGateway` دون اتصال حقيقي.

---

## 1. Schema قاعدة البيانات

```sql
-- إعدادات السيرفر + عدّاد أرقام التيكتات لكل سيرفر
guild_settings(guild_id PK CHECK>0, next_ticket_number CHECK>=1, created_at, updated_at)

-- البانلات
panels(
  id PK, guild_id FK→guild_settings,
  name CHECK len 1..50, embed_title 1..256, embed_description 1..2000, button_label 1..80,
  category_id, panel_channel_id, log_channel_id, panel_message_id NULL,
  channel_name_template 1..60, max_open_tickets CHECK 1..50,
  status CHECK IN ('ACTIVE','PAUSED','MISCONFIGURED','ARCHIVED','DELETED'),
  inactivity_enabled 0/1, inactivity_timeout_min 10..43200, inactivity_warning_min (1..timeout-1),
  sla_enabled 0/1, sla_first_response_min 5..10080,
  escalation_role_id NULL, escalation_after_min 0..10080,
  close_on_owner_leave 0/1 DEFAULT 0,      -- معطّل افتراضيًا
  created_by, created_at, updated_at)
UNIQUE INDEX (guild_id, name) WHERE status <> 'DELETED'

panel_roles(panel_id FK ON DELETE CASCADE, role_id, kind CHECK IN ('admin','staff'), PK(panel_id, role_id, kind))

-- جدول الانتقالات المسموحة (تستخدمه Trigger لفرض آلة الحالات داخل SQLite نفسها)
ticket_transitions(from_state, to_state, PK(from_state,to_state))

tickets(
  id PK, guild_id FK, panel_id FK ON DELETE RESTRICT, number, owner_id,
  channel_id UNIQUE NULL, control_message_id NULL,
  state CHECK IN ('CREATING','OPEN','ON_HOLD','CLOSING','CLOSED','FAILED','LOST'),
  version (قفل تفاؤلي), create_op_key UNIQUE, creation_uncertain 0/1,
  claimed_by, claimed_at, created_at, opened_at,
  close_seq (يزيد مع كل طلب إغلاق), closed_by, close_reason, close_requested_at, closed_at,
  first_response_at,
  inactivity_deadline, inactivity_remaining, inactivity_warned,
  sla_deadline, sla_remaining, sla_breached_at,
  escalation_deadline, escalation_remaining, escalated_at,
  hold_started_at, total_hold_seconds, channel_deleted 0/1, updated_at,
  UNIQUE(guild_id, number),
  CHECK(state NOT IN ('OPEN','ON_HOLD','CLOSING','CLOSED') OR channel_id IS NOT NULL),
  CHECK(state <> 'ON_HOLD' OR hold_started_at IS NOT NULL))

UNIQUE INDEX ux_one_active_ticket ON tickets(guild_id, panel_id, owner_id)
  WHERE state IN ('CREATING','OPEN','ON_HOLD');               -- منع التكرار على مستوى DB

TRIGGER: INSERT يجب أن يبدأ بـ CREATING
TRIGGER: UPDATE OF state يُرفض إن لم يكن الزوج موجودًا في ticket_transitions
TRIGGER: حد التيكتات المفتوحة لكل بانل عند INSERT وعند إعادة الفتح

ticket_events(id, guild_id, ticket_id NULL, panel_id NULL, actor_id, event_type,
              from_state, to_state, details JSON CHECK json_valid, created_at)
              -- لا يُخزَّن أي محتوى رسائل

archives(
  id PK, ticket_id FK, close_seq, attempt, 
  status CHECK IN ('BUILDING','PENDING_COPIES','BLOCKED','COMPLETE','SUPERSEDED'),
  transcript_sha256 (64 hex), transcript_size, message_count, last_message_id,
  transcript_complete 0/1, incomplete_reason, omissions_ack_by,
  log_status CHECK IN ('PENDING','SENDING','VERIFIED','FAILED'), log_channel_id, log_message_id,
  log_attempts, log_error, log_verified_at,
  local_status CHECK IN ('PENDING','VERIFIED','FAILED','EXPIRED','RETENTION_HOLD'),
  local_path, local_cipher_sha256, local_attempts, local_error, local_verified_at,
  expires_at, local_deleted_at, created_at, completed_at,
  UNIQUE(ticket_id, close_seq, attempt))
UNIQUE INDEX one live archive per ticket WHERE status IN ('BUILDING','PENDING_COPIES','BLOCKED')

scheduled_jobs(
  id PK, kind CHECK IN (...), dedupe_key UNIQUE, guild_id, ticket_id FK NULL,
  run_at, status CHECK IN ('PENDING','RUNNING','DONE','FAILED','CANCELLED'),
  lease_token, attempts, max_attempts, payload JSON, last_error, created_at, updated_at)

-- Outbox / سجل العمليات الخارجية لتقليل التكرار
external_ops(op_key PK, kind, ticket_id FK NULL,
  status CHECK IN ('STARTED','SUCCEEDED','FAILED','UNCERTAIN'), external_id, attempts, last_error, created_at, updated_at)
```

---

## 2. حالات التيكت والانتقالات

```
            ┌──────────── FAILED (فشل مؤكد لإنشاء القناة)
            │
CREATING ───┼──► OPEN ◄──► ON_HOLD
            │     │  ▲        │
            │     ▼  │(Reopen)▼
            │    CLOSING ◄────┘
            │     │
            │     ▼
            │   CLOSED  (نهائي: الأرشيفان مؤكدان، ثم تُحذف القناة)
            │
 أي حالة نشطة (CREATING/OPEN/ON_HOLD/CLOSING) ──► LOST  (القناة حُذفت يدويًا)
```

| من | إلى | من يستطيع | الشرط |
|---|---|---|---|
| CREATING | OPEN | النظام | تأكيد وجود القناة |
| CREATING | FAILED | النظام | فشل مؤكد، أو مرور مهلة المصالحة بلا قناة |
| OPEN | ON_HOLD | Staff/Admin | — |
| ON_HOLD | OPEN | Staff/Admin | — |
| OPEN / ON_HOLD | CLOSING | صاحب التيكت، Staff، Admin، الأتمتة | بعد تأكيد |
| CLOSING | OPEN | Staff/Admin فقط | قبل اكتمال الأرشفة وما دامت القناة موجودة، ولا يوجد تيكت نشط آخر للمستخدم |
| CLOSING | CLOSED | خدمة الأرشفة فقط | الأرشيفان VERIFIED + لا رسائل بشرية بعد آخر رسالة في الـ Transcript |
| CREATING/OPEN/ON_HOLD/CLOSING | LOST | النظام | القناة غير موجودة فعليًا |

- **الحالات "النشطة"** للقيد الفريد: `CREATING, OPEN, ON_HOLD`. حالة `CLOSING` ليست نشطة، فيستطيع المستخدم فتح تيكت جديد أثناء أرشفة القديم، وإذا حاول Staff إعادة فتح القديم سيرفض القيد ذلك برسالة واضحة.
- **Claim** ليس حالة بل حقل: `UPDATE ... SET claimed_by=? WHERE id=? AND claimed_by IS NULL AND state IN ('OPEN','ON_HOLD')`.
- كل انتقال ينفَّذ كـ `UPDATE tickets SET state=?, version=version+1 WHERE id=? AND state=?` داخل معاملة؛ إن كانت `rowcount=0` فالطلب خسر السباق ويُبلَّغ المستخدم. والـ Trigger يرفض أي انتقال غير مسموح حتى لو أخطأ كود Python.

---

## 3. منع التكرار والتزامن

1. **قفل في الذاكرة** لكل `(guild, panel, user)` لامتصاص الضغطات السريعة (خط دفاع أول فقط).
2. **`BEGIN IMMEDIATE`** عند حجز رقم التيكت وإدراج السجل → عدّاد أرقام بلا تكرار.
3. **Unique Partial Index** يمنع تيكتين نشطين لنفس `(guild, panel, owner)` — هو الضامن الحقيقي، حتى لو عملت نسختان من البوت على نفس الملف.
4. **Trigger** لحد التيكتات المفتوحة لكل بانل.
5. **ترتيب العمليات عند الفتح:**
   1. إدراج السجل `CREATING` مع `create_op_key` (UUID) → يُحفظ قبل أي عملية خارجية.
   2. إنشاء القناة مع `topic` يحتوي `tazkara-ticket-id:<id>` (علامة للمصالحة).
   3. `CREATING → OPEN` + `channel_id`.
   - فشل مؤكد (403/400) → `FAILED`، لا قناة.
   - نتيجة غير محسومة (5xx/timeout) → يبقى `CREATING` مع `creation_uncertain=1`، وتُجدول مصالحة: إن وُجدت قناة بالعلامة تُتبنّى، وإلا بعد مهلة → `FAILED`. لا يُنشأ تيكت إضافي لأن القيد الفريد يمنع ذلك.
   - فشل كتابة DB بعد إنشاء القناة → حذف القناة تعويضيًا؛ إن فشل الحذف أيضًا تتبنّاها المصالحة لاحقًا (لا قنوات يتيمة ولا سجلات يتيمة في النهاية).
6. **الأزرار:** `custom_id` يحمل رقم التيكت/البانل فقط كمؤشر. كل تفاعل يعيد: قراءة السجل، مطابقة `guild_id` و `channel_id` و (للبانل) `panel_message_id`، فحص الحالة الحالية، وفحص صلاحيات العضو الفعلية من أدواره الحالية.
7. **المجدول:** كل مهمة تُحجز بـ `lease_token`؛ الإنهاء يتم فقط إذا تطابق الرمز، فإعادة الجدولة أثناء التنفيذ لا تضيع. معالجات المهام **تعيد الحساب من حالة التيكت** (idempotent) بدل الثقة بوقت المهمة.

---

## 4. بروتوكول الأرشفة المزدوجة وسياسة حذف القناة

```
CLOSING
  │ 1. قفل القناة (منع الإرسال لصاحبها ورولات الستاف)
  │ 2. إنشاء/استئناف سجل archive حي (فريد لكل تيكت)
  │ 3. بناء Transcript HTML كامل:
  │      - كل الرسائل (oldest_first) — يتطلب MESSAGE_CONTENT
  │      - المرفقات تُحمَّل وتُضمَّن كـ data: URI ضمن حدود الحجم
  │      - مرفق تعذّر حفظه ⇒ Transcript "ناقص" ⇒ BLOCKED (لا حذف) حتى يقرّ Admin صراحة
  │ 4. نسخة اللوج: رفع → تحميل المرفق المرفوع → مقارنة SHA-256 ⇒ VERIFIED
  │      (حالة SENDING تعني نتيجة غير محسومة ⇒ يُبحث عن الرسالة بالعلامة قبل إعادة الرفع)
  │ 5. النسخة المحلية: Fernet → ملف مؤقت → fsync → os.replace → قراءة → فك → مقارنة SHA-256 ⇒ VERIFIED
  │ 6. إن نجحت واحدة وفشلت الأخرى: القناة تبقى، تُسجَّل النتيجتان، إعادة محاولة الفاشلة فقط
  │      (المحتوى يُستعاد من النسخة الناجحة نفسها والتحقق من بصمتها ⇒ نفس الـ SHA)
  │ 7. إن كانت هناك رسائل بشرية بعد آخر رسالة في الـ Transcript ⇒ SUPERSEDED وبناء جديد
  │ 8. معاملة واحدة: archive=COMPLETE + tickets CLOSING→CLOSED (مشروطة)
  ▼
CLOSED ⇒ مهمة delete_channel (مع إعادة المحاولة) + مهمة DM (ملخص فقط، فشلها لا يؤثر)
```

- **لا تُحذف القناة إلا بعد `CLOSED`**، و `CLOSED` لا تُكتب إلا داخل نفس المعاملة التي تتحقق من `log_status='VERIFIED' AND local_status='VERIFIED' AND transcript_complete=1`.
- Reopen أثناء الأرشفة: `CLOSING→OPEN` مشروطة؛ إن فازت، تصبح الأرشفة الجارية SUPERSEDED ويفشل انتقالها إلى CLOSED فلا تُحذف القناة.
- الاستئناف بعد إعادة التشغيل: حالة كل نسخة محفوظة؛ المهمة `archive` تبقى PENDING وتُستأنف.
- إعادة المحاولة: Backoff أسّي حتى ساعة، بلا حد نهائي (القناة تبقى حتى النجاح أو تدخل بشري).

### سياسة الاحتفاظ
| البيانات | المدة | الآلية |
|---|---|---|
| النسخة المحلية المشفرة | 30 يومًا من التحقق | تُحذف **فقط** بعد التحقق من أن نسخة اللوج ما زالت موجودة وبصمتها مطابقة. إن لم تكن ⇒ `RETENTION_HOLD` + تنبيه، ولا حذف |
| `ticket_events` | 180 يومًا | حذف دوري |
| `scheduled_jobs` / `external_ops` المنتهية | 30 يومًا | حذف دوري |
| سجل الملف `tazkara.log` | دوّار 5×5MB | لا يحتوي محتوى رسائل أو أسرار |
| رسائل قناة اللوج في Discord | مسؤولية إدارة السيرفر | البوت لا يحذفها لأنها النسخة الثانية |

---

## 5. صلاحيات Discord والـ Intents

**صلاحيات البوت (Integer = 268553232):**
`View Channels`, `Send Messages`, `Embed Links`, `Attach Files`, `Read Message History`, `Manage Channels`, `Manage Roles` (لضبط Permission Overwrites).
**لا** `Administrator`. لا `Mention Everyone` (اجعل رولات الستاف قابلة للمنشن إن أردت التنبيه).

Scopes: `bot` + `applications.commands`.

| Intent | مطلوب؟ | السبب |
|---|---|---|
| `guilds` | نعم | القنوات/الرولات/أحداث حذف القنوات |
| `guild_messages` | نعم | تعريف "النشاط" للأتمتة (من كتب ومتى) |
| `message_content` (مميز) | **نعم** | بدونه يصل محتوى الرسائل فارغًا ⇒ Transcript ناقص ⇒ لن تُحذف أي قناة. يجب تفعيله في Developer Portal |
| `members` (مميز) | لا (اختياري، `ENABLE_MEMBERS_INTENT=False`) | خيار "إغلاق عند مغادرة صاحب التيكت" يعمل بفحص دوري عبر `fetch_member` دون هذا الـ Intent؛ تفعيله يجعل الاستجابة فورية |
| `presences` | لا | غير مستخدم |

تراتبية الرولات: Permission Overwrites على القنوات لا تتأثر بترتيب الرولات، لكن البوت يرفض: `@everyone` كرول ستاف، والرولات المُدارة (Managed/Integration)، ويتحقق من صلاحياته الفعلية `permissions_for(guild.me)` في الكاتيجوري وقناة البانل وقناة اللوج قبل الحفظ وقبل كل عملية.

### سياسة الصلاحيات للأزرار
| الإجراء | صاحب التيكت | Staff | Admin البانل / Manage Server |
|---|---|---|---|
| Claim | ✗ | ✓ | ✓ |
| Hold / Resume | ✗ | ✓ | ✓ |
| Close | ✓ (تيكته فقط) | ✓ | ✓ |
| Reopen | ✗ | ✓ | ✓ |
| إقرار أرشفة رغم مرفقات ناقصة | ✗ | ✗ | ✓ |
| `/setup` | ✗ | ✗ | Manage Server فقط |

---

## 6. اختبارات الأمان والاعتمادية

كل البنود العشرون المطلوبة مغطاة باختبارات pytest داخل `main.py` (انظر قسم 9 في README لنتيجة التشغيل الفعلية)، إضافة إلى:
- Trigger يرفض انتقالات غير مسموحة على مستوى SQLite.
- سباق Reopen ضد اكتمال الأرشفة.
- رفض التوكن الوهمي، وإخفاء التوكن في السجلات.
- قوالب أسماء القنوات: رفض `{0.__class__}` وأي placeholder غير معروف (لا يُستخدم `str.format` مع مدخلات المستخدم).
- رسائل بشرية بعد إنشاء الـ Transcript ⇒ إعادة البناء.

---

## 7. تعارضات المتطلبات وكيف حُلّت

| التعارض | الحل |
|---|---|
| "ملف Python واحد" مقابل "اختبارات pytest" | الاختبارات داخل `main.py` وتُشغَّل بـ `pytest main.py` (تُعرّف فقط عند الاستيراد، لا تؤثر على التشغيل) |
| "لا `.env` ولا `config.py`" مقابل "مفتاح منفصل عن الملفات المشفرة" | ملف مفتاح خارج مجلد المشروع، مع متغير بيئة نظامي اختياري لمساره فقط (ليس ملف .env) |
| "لا تحذف القناة إذا كان الـ Transcript ناقصًا" مقابل مرفقات أكبر من حد الرفع | الحالة `BLOCKED` + زر إقرار صريح لـ Admin يُسجَّل في الأحداث وتُذكر المرفقات المحذوفة داخل الـ Transcript. بدون الإقرار لا حذف |
| "حذف النسخة المحلية بعد 30 يومًا" مقابل "عدم حذف النسخة الوحيدة الصالحة" | التحقق من نسخة اللوج قبل الحذف؛ وإلا `RETENTION_HOLD` |
| "تيكت نشط واحد" مقابل تيكت عالق في الأرشفة | `CLOSING` ليست حالة نشطة للقيد |
| "Exactly-once" | غير مُدّعى. DM: at-most-once (لا إعادة عند عدم اليقين). رفع اللوج: بحث بالعلامة قبل إعادة الرفع. إنشاء القناة: علامة `topic` + مصالحة |
| الاستعلامات المتزامنة مع SQLite | اتصال واحد في حلقة asyncio؛ لا `await` داخل أي معاملة، فلا تتداخل المعاملات |

---

## 8. خارج النطاق (عمدًا)
Dashboard ويب، اشتراكات، ميزات مدفوعة، تقسيم الملفات/Cogs، Node.js.

## 9. فروقات بين التصميم والتنفيذ
ما تغيّر أثناء التنفيذ والمراجعة (موثّق بصدق):

| البند | التصميم الأصلي | التنفيذ الفعلي | السبب |
|---|---|---|---|
| حد التيكتات المفتوحة لكل بانل | 1..500 | **1..50** (CHECK في القاعدة + المُدقِّق + حقل الإدخال، الافتراضي 25) | الكاتيجوري في Discord تحتمل 50 قناة كحد أقصى؛ قيمة أكبر كانت ستفشل عند إنشاء القناة |
| فحص تراتبية الرولات | رفض `@everyone` والرولات المُدارة | نفس الرفض + **تنبيه غير مانع** عند الحفظ للرولات الأعلى من رول البوت أو التي تملك `Administrator` | البوت لا يعدّل الرولات ولا يمنحها؛ منع الحفظ كان سيرفض إعدادات صحيحة. التنبيه يوضح للأدمن من يرى التيكتات دائمًا |
| بدء الـ Scheduler بعد إعادة التشغيل | بعد المصالحة | داخل `finally` بعد المصالحة | اكتُشف في المراجعة: فشل المصالحة كان سيمنع تشغيل المهام المحفوظة |
| البحث عن نسخة اللوج بعد رفع غير مؤكد | بالـ marker | بالـ marker في **آخر 100 رسالة** من قناة اللوج | حدّ عملي لتكلفة الـ API؛ في قناة لوج مزدحمة جدًا قد ينتج رفع مكرر (تكرار وليس فقدان) |
| ربط القناة بالتيكت عند المصالحة | علامة في الـ topic | نفس الشيء | العلامة ليست حدًّا أمنيًا: فقط من يملك Manage Channels يستطيع تعديل الـ topic، وهو يستطيع حذف القنوات أصلًا |

