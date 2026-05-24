# Healthcare & Regulated Security Code Review Guide

> Cross-cutting security overlay for healthcare (NEN 7510), OWASP Top 10, PII/PHI detection, audit-trail verification, and AVG/GDPR compliance. Language-agnostic — use alongside language-specific review guides.

## Table of Contents

- [NEN 7510 Control Mapping](#nen-7510-control-mapping)
- [OWASP Top 10 Mapping](#owasp-top-10-mapping)
- [PII / PHI Detection Patterns](#pii--phi-detection-patterns)
- [Audit Trail Verification](#audit-trail-verification)
- [Evidence Tier Integration (EV)](#evidence-tier-integration-ev)
- [AVG / GDPR Compliance Checks](#avg--gdpr-compliance-checks)
- [Session & Access Management](#session--access-management)
- [Encryption & Key Management](#encryption--key-management)
- [Third-Party Integration Security](#third-party-integration-security)
- [Logging Discipline](#logging-discipline)
- [Review Checklist](#review-checklist)

---

## NEN 7510 Control Mapping

NEN 7510 is the Dutch information security standard for healthcare, based on ISO 27001/27002 with healthcare-specific extensions. Each section below maps findings to NEN 7510 control areas.

### Access Control (NEN 7510 §9)

```
Review focus: Every data-access endpoint must enforce authentication AND authorization.

❌ Endpoint accessible without authentication [blocking]
   // Any controller/route that returns patient data without auth check
   // NEN 7510 §9.1.1: Access control policy violation

❌ Horizontal privilege escalation — user A can access user B's data [blocking]
   // GET /api/patients/123 returns data regardless of requesting user's scope
   // NEN 7510 §9.4.1: Information access restriction

❌ Role check only — no data-level authorization [important]
   // User has "doctor" role but accesses patients outside their department
   // NEN 7510 §9.4.1 + §9.1.2: Access to networks and services

✅ Three-layer authorization check
   1. Authentication (is the user who they claim to be?)
   2. Role authorization (does this role allow this action type?)
   3. Data authorization (does this user have access to THIS specific record?)
```

```python
# ❌ Role-only check — any doctor sees all patients [blocking]
@require_role("doctor")
def get_patient(patient_id):
    return Patient.query.get(patient_id)

# ✅ Data-level authorization — doctor sees only their patients
@require_role("doctor")
def get_patient(patient_id):
    patient = Patient.query.get(patient_id)
    if patient.department_id not in current_user.department_ids:
        raise ForbiddenError("Not authorized for this patient")
    return patient
```

### User Management (NEN 7510 §9.2)

```
❌ No account lockout after failed attempts [important]
   // NEN 7510 §9.4.2: Secure log-on procedures
   // Healthcare: max 5 attempts, then lockout 15+ minutes

❌ Shared accounts for clinical systems [blocking]
   // NEN 7510 §9.2.1: User registration and de-registration
   // Every clinical action MUST be attributable to an individual

❌ No password complexity enforcement [important]
   // NEN 7510 §9.4.3: Password management system
   // Minimum: 12 chars, mixed case + numbers + special

✅ Individual accounts + MFA for PHI access
   // NEN 7510 §9.4.2: MFA recommended for remote/elevated access
```

### Physical and Environmental (NEN 7510 §11)

```
❌ API returns full patient record to mobile/public-facing UI [important]
   // NEN 7510 §11.2.6: Security of equipment off-premises
   // Return only fields needed for the specific view

✅ Minimal data exposure per endpoint
   // API returns only name + appointment time for waiting room display
   // Full record only on authenticated clinical workstation views
```

---

## OWASP Top 10 Mapping

Each finding should be tagged with the corresponding OWASP category for standardized reporting.

### A01:2021 — Broken Access Control

```
Map to: NEN 7510 §9

❌ Missing function-level access control [blocking]
   // Admin endpoint accessible to regular users
   // IDOR: /api/patients/{id} enumerable without ownership check

❌ CORS misconfiguration allowing any origin [blocking]
   // Access-Control-Allow-Origin: *
   // On healthcare API with authentication cookies
```

### A02:2021 — Cryptographic Failures

```
Map to: NEN 7510 §10, §14

❌ PHI transmitted over HTTP (no TLS) [blocking]
❌ Weak hashing for passwords (MD5, SHA1) [blocking]
❌ Encryption keys hardcoded in source [blocking]
❌ PII stored in plaintext in database [important for regulated]

✅ TLS 1.2+ for all data in transit
✅ AES-256 or ChaCha20 for data at rest
✅ bcrypt/scrypt/Argon2 for passwords
✅ Keys in HSM or secret manager (Infisical, Vault, AWS KMS)
```

### A03:2021 — Injection

```
Map to: Language-specific guide (SQL injection, XSS, command injection)

❌ String concatenation in SQL with user input [blocking]
❌ Template output not escaped [blocking]
❌ User input in OS commands [blocking]
❌ LDAP injection in directory lookups (common in hospital AD integration) [blocking]
```

```java
// ❌ LDAP injection in Active Directory lookup [blocking]
String filter = "(uid=" + username + ")";
// Attacker: username = "*)(|(objectClass=*)"

// ✅ Escape LDAP special characters
String safeUsername = LdapEncoder.filterEncode(username);
String filter = "(uid=" + safeUsername + ")";
```

### A04:2021 — Insecure Design

```
❌ No rate limiting on authentication endpoints [important]
❌ No re-authentication for sensitive operations (e.g., viewing BSN) [important]
❌ Business logic allows bulk data export without approval workflow [important]
```

### A05:2021 — Security Misconfiguration

```
❌ Debug mode enabled in production [blocking]
❌ Default credentials on admin interfaces [blocking]
❌ Directory listing enabled on web server [important]
❌ Stack traces returned in API error responses [important]
❌ CORS Allow-Origin: * on authenticated endpoints [blocking]
```

### A06:2021 — Vulnerable and Outdated Components

```
❌ Known CVE in dependency (check with composer audit / npm audit / pip-audit) [blocking]
❌ Framework version out of security support [important]
❌ End-of-life runtime (PHP 7.4, .NET Framework 4.6.1, Python 3.7) [important]
```

### A07:2021 — Identification and Authentication Failures

```
❌ Session ID in URL parameters [blocking]
❌ No session timeout for PHI-accessing sessions [blocking]
❌ Password reset token with no expiry [important]
❌ Credential stuffing possible (no rate limit + no MFA) [important]
```

### A08:2021 — Software and Data Integrity Failures

```
❌ Deserialization of untrusted data (unserialize, pickle.loads, ObjectInputStream) [blocking]
❌ No integrity verification on software updates / plugins [important]
❌ CI/CD pipeline without signed commits or verified artifacts [nit for healthcare]
```

### A09:2021 — Security Logging and Monitoring Failures

```
Map to: NEN 7510 §12, Audit Trail section below

❌ No logging of authentication events [blocking]
❌ No logging of PHI access [blocking for NEN 7510]
❌ Logs not centralized or tamper-evident [important]
❌ No alerting on anomalous access patterns [important]
```

### A10:2021 — Server-Side Request Forgery (SSRF)

```
❌ URL parameter passed to server-side HTTP client without validation [blocking]
   // Attacker uses internal URLs to access metadata service or internal APIs

✅ Whitelist allowed target hosts for server-side requests
✅ Block requests to internal IP ranges (10.x, 172.16-31.x, 192.168.x, 169.254.x)
```

---

## PII / PHI Detection Patterns

Every code review of healthcare software must check for unintended PII/PHI exposure. These patterns should trigger immediate attention.

### BSN (Burgerservicenummer) Detection

```
BSN is the Dutch citizen service number — 9 digits with an 11-check.

❌ BSN in URL query string [blocking]
   GET /api/patient?bsn=123456789
   // Logged in access logs, browser history, referer headers

❌ BSN in client-side JavaScript variable or localStorage [blocking]
   var patientBSN = "123456789";
   localStorage.setItem("bsn", bsn);

❌ BSN in log output [blocking]
   logger.info(f"Processing patient BSN={bsn}")

✅ BSN transmitted only in POST body over TLS
✅ BSN stored encrypted at rest
✅ BSN masked in UI (show only last 3 digits: ******789)
✅ BSN never appears in log files — use internal patient ID instead
```

```python
# Regex for BSN detection in code review (9 digits, may have separators)
import re
BSN_PATTERN = re.compile(r'\b\d{9}\b')  # Simple: 9 consecutive digits
BSN_PATTERN_SEP = re.compile(r'\b\d{3}[-.\s]?\d{3}[-.\s]?\d{3}\b')  # With separators

# ❌ Patterns to grep for in codebase:
# - log.*bsn
# - print.*bsn
# - console.log.*bsn
# - query.*bsn.*=
# - localStorage.*bsn
# - sessionStorage.*bsn
```

### Patient Name in Logs

```
❌ Patient name in application logs [blocking]
   logger.info(f"Appointment created for {patient.name}")
   console.log(`Processing ${patient.firstName} ${patient.lastName}`)

✅ Use anonymized identifiers in logs
   logger.info(f"Appointment created for patient_id={patient.id}")
   // Patient name → only in audit log with proper access control
```

### Medical Codes in Client-Side Code

```
❌ DBC/ICD-10 diagnosis codes in client-side JavaScript bundle [important]
   // Patient's diagnosis visible in browser dev tools
   const diagnosis = { code: "F32.1", description: "Major Depressive Disorder" };

❌ Medical data in HTML data-attributes
   <div data-diagnosis="F32.1" data-medication="Sertraline 50mg">

✅ Medical codes fetched on-demand from authenticated API
✅ Never included in initial page load or JavaScript bundles
✅ Server-side rendering for sensitive medical data
```

### Email and Phone in Query Strings

```
❌ PII in URL parameters [blocking]
   /search?email=patient@example.com&phone=0612345678
   // Visible in server logs, browser history, proxy logs, analytics

✅ PII transmitted via POST body or encrypted path segments
   POST /api/search { "email": "patient@example.com" }
```

---

## Audit Trail Verification

NEN 7510 §12.4 requires comprehensive audit logging for all PHI access and modification.

### Every Data Mutation Has an Audit Event

```python
# ❌ Data modified without audit event [blocking]
def update_patient(patient_id, data):
    patient = Patient.query.get(patient_id)
    patient.update(data)
    db.session.commit()
    # No audit trail — who changed what, when?

# ✅ Audit event emitted for every mutation
def update_patient(patient_id, data):
    patient = Patient.query.get(patient_id)
    before = patient.to_dict()
    patient.update(data)
    db.session.commit()
    audit_log.emit(AuditEvent(
        actor=current_user.id,
        action="patient.update",
        target=f"patient:{patient_id}",
        timestamp=datetime.utcnow(),
        before=before,
        after=patient.to_dict(),
        ip_address=request.remote_addr,
        session_id=session.sid,
    ))
```

### Audit Events Are Append-Only

```sql
-- ❌ Audit table allows UPDATE and DELETE [blocking]
GRANT ALL PRIVILEGES ON audit_events TO app_user;

-- ✅ Audit table is INSERT-only
GRANT INSERT, SELECT ON audit_events TO app_user;
-- No UPDATE, no DELETE — audit trail is immutable

-- ✅ Additional protection: database trigger to prevent UPDATE/DELETE
CREATE TRIGGER prevent_audit_modification
BEFORE UPDATE OR DELETE ON audit_events
FOR EACH ROW EXECUTE FUNCTION raise_exception('Audit events are immutable');
```

### Required Audit Fields

```
Every audit event MUST contain:

✅ actor        — WHO performed the action (user ID, not name)
✅ action       — WHAT was done (verb: create, read, update, delete, export, print)
✅ target       — ON WHAT (resource type + ID)
✅ timestamp    — WHEN (UTC, millisecond precision)
✅ before/after — STATE CHANGE (for mutations, not reads)
✅ ip_address   — FROM WHERE
✅ session_id   — WHICH SESSION
✅ reason       — WHY (for break-glass / emergency access)

Optional but recommended:
- user_agent
- correlation_id (trace across microservices)
- data_classification (PHI, PII, public)
```

### Read Access Logging

```python
# ❌ Only mutations logged — reads of PHI are invisible [blocking for NEN 7510]
def get_patient(patient_id):
    return Patient.query.get(patient_id)
    # No audit: who viewed this patient record?

# ✅ PHI read access logged (NEN 7510 §12.4.1)
def get_patient(patient_id):
    patient = Patient.query.get(patient_id)
    audit_log.emit(AuditEvent(
        actor=current_user.id,
        action="patient.read",
        target=f"patient:{patient_id}",
        timestamp=datetime.utcnow(),
    ))
    return patient
```

### Break-Glass / Emergency Access

```python
# ❌ No emergency access mechanism — users share admin credentials in emergencies [blocking]

# ✅ Break-glass access with mandatory justification and elevated logging
def emergency_access(patient_id, reason):
    if not reason or len(reason) < 20:
        raise ValueError("Emergency access requires detailed justification (min 20 chars)")

    audit_log.emit(AuditEvent(
        actor=current_user.id,
        action="patient.emergency_read",
        target=f"patient:{patient_id}",
        reason=reason,
        alert_level="HIGH",  # Triggers immediate notification to privacy officer
    ))
    # Notify privacy officer in real-time
    notify_privacy_officer(current_user, patient_id, reason)
    return Patient.query.get(patient_id)
```

---

## Evidence Tier Integration (EV)

MarQed ADR-022 defines evidence tiers for claims and findings. Code review findings should be tagged with the appropriate tier.

### Tier Definitions for Code Review Findings

```
EV1 — Deterministic, machine-verifiable
   Examples: linter output, type checker error, failing test, static analysis
   Review action: cite tool + output as evidence

EV2 — Deterministic, human-verified
   Examples: SQL injection (reviewer confirmed string concatenation),
             missing auth check (reviewer confirmed no guard),
             plaintext password in source (reviewer confirmed)
   Review action: cite line numbers + reproduction steps

EV3 — LLM-derived (default for AI-assisted review)
   Examples: "this pattern may lead to race condition",
             "this error handling may be insufficient"
   Review action: flag as EV3, recommend human verification

EV4 — Cross-LLM Gate validated
   Examples: finding confirmed by second LLM with independent analysis
   Review action: note Gate result (pass/fail + model used)

EV5 — Expert-validated
   Examples: finding confirmed by domain expert (security auditor, clinician)
   Review action: cite expert + date of validation
```

### Applying EV Tiers in Review Comments

```markdown
## Example review comments with EV tier tags

[blocking] [EV2] SQL injection in patient search endpoint
Line 42: `query = f"SELECT * FROM patients WHERE name = '{request.args['name']}'"``
Confirmed by manual review — user input directly interpolated into SQL.
Fix: use parameterized query.

[important] [EV3] Potential session fixation after login
Line 89: `session['user_id'] = user.id` without `session.regenerate()`
LLM-derived finding — recommend manual verification that session ID
is not reused from pre-authentication state.

[blocking] [EV1] Known CVE in dependency
`pip-audit` output: Jinja2 3.1.2 has CVE-2024-34064 (XSS via xmlattr filter)
Fix: upgrade to Jinja2 >= 3.1.4
```

---

## AVG / GDPR Compliance Checks

### Data Minimization

```python
# ❌ Collecting more data than needed (AVG Art. 5(1)(c)) [important]
class PatientRegistrationForm:
    fields = ['name', 'bsn', 'email', 'phone', 'religion', 'ethnicity',
              'marital_status', 'sexual_orientation', 'political_views']
    # Religion/ethnicity/etc. are special category data (Art. 9)
    # Only collect if strictly necessary for treatment

# ✅ Collect only what is necessary for the stated purpose
class PatientRegistrationForm:
    fields = ['name', 'bsn', 'email', 'phone', 'date_of_birth']
    # Special category data collected only in specific clinical context
    # with explicit consent and documented legal basis
```

### Right to Erasure (Soft-Delete + Retention)

```python
# ❌ Hard delete without considering legal retention requirements [blocking]
def delete_patient(patient_id):
    Patient.query.filter_by(id=patient_id).delete()
    db.session.commit()
    # Medical records have LEGAL retention period (15-20 years in NL)
    # Hard delete violates Wet BIG / WGBO

# ❌ No delete capability at all — violates AVG Art. 17
# Patient requests erasure but system has no mechanism

# ✅ Soft-delete with retention policy
def anonymize_patient(patient_id, reason):
    patient = Patient.query.get(patient_id)

    # Check retention period (WGBO: 20 years after last treatment)
    if patient.last_treatment_date + timedelta(years=20) > datetime.now():
        raise RetentionPeriodActiveError(
            "Medical records must be retained for 20 years (WGBO Art. 454)"
        )

    # Anonymize PII, retain medical data structure for aggregate analysis
    patient.name = "ANONYMIZED"
    patient.bsn = None
    patient.email = None
    patient.phone = None
    patient.is_anonymized = True
    patient.anonymized_at = datetime.utcnow()
    patient.anonymization_reason = reason

    audit_log.emit(AuditEvent(
        actor=current_user.id,
        action="patient.anonymize",
        target=f"patient:{patient_id}",
        reason=reason,
    ))
    db.session.commit()
```

### Verwerkingsovereenkomst (Data Processing Agreement)

```python
# ❌ Sending PII to third-party API without DPA check [blocking]
def enrich_patient_data(patient):
    response = requests.post("https://api.external-service.com/enrich", json={
        "name": patient.name,
        "bsn": patient.bsn,
        "dob": str(patient.date_of_birth),
    })
    # Is there a verwerkingsovereenkomst with this service?
    # Is the service within EU/EEA? Adequate protection level?
    # Is there a legal basis for this data sharing?

# ✅ Third-party integrations with PII require documented checks
def enrich_patient_data(patient):
    # Verify DPA exists and is current
    if not ThirdPartyRegistry.has_valid_dpa("external-service"):
        raise ComplianceError("No valid verwerkingsovereenkomst for external-service")

    # Only send minimum necessary data
    response = requests.post("https://api.external-service.com/enrich", json={
        "reference_id": patient.external_ref,  # Pseudonymized reference
        "dob": str(patient.date_of_birth),     # Only if needed for enrichment
    })
    # BSN NEVER sent to third parties without explicit legal basis
```

### Consent Management

```python
# ❌ Processing special category data without explicit consent [blocking]
def record_diagnosis(patient_id, icd_code):
    diagnosis = Diagnosis(patient_id=patient_id, code=icd_code)
    db.session.add(diagnosis)
    db.session.commit()
    # No consent verification for medical data processing

# ✅ Verify consent and legal basis before processing
def record_diagnosis(patient_id, icd_code):
    patient = Patient.query.get(patient_id)

    # Medical data processing: legal basis is typically GDPR Art. 9(2)(h)
    # "processing is necessary for [...] provision of health care"
    # But additional consent may be required for specific uses (research, etc.)
    if not patient.has_treatment_relationship(current_user):
        raise ForbiddenError("No active treatment relationship")

    diagnosis = Diagnosis(patient_id=patient_id, code=icd_code)
    db.session.add(diagnosis)
    db.session.commit()

    audit_log.emit(AuditEvent(
        actor=current_user.id,
        action="diagnosis.create",
        target=f"patient:{patient_id}",
        legal_basis="GDPR_9_2_H",
    ))
```

---

## Session & Access Management

### Healthcare-Specific Session Requirements

```
NEN 7510 §9.4.2 requirements for session management:

✅ Automatic timeout: 15 minutes inactivity for PHI-accessing sessions
✅ Re-authentication: required before viewing BSN or critical medical data
✅ Concurrent session limit: max 1-2 active sessions per user
✅ Session termination: logout must invalidate server-side session
✅ Forced logout: privacy officer can terminate any session remotely
```

```python
# ❌ No re-authentication for sensitive operations [important]
@require_auth
def view_patient_bsn(patient_id):
    return {"bsn": patient.bsn}

# ✅ Step-up authentication for sensitive data
@require_auth
@require_step_up_auth(max_age_seconds=300)  # Must have authenticated within 5 min
def view_patient_bsn(patient_id):
    audit_log.emit(AuditEvent(
        actor=current_user.id,
        action="patient.view_bsn",
        target=f"patient:{patient_id}",
    ))
    return {"bsn": mask_bsn(patient.bsn)}  # Show last 3 digits only
```

---

## Encryption & Key Management

### Data at Rest

```
❌ PHI stored in plaintext database columns [blocking for NEN 7510]
❌ Encryption keys stored alongside encrypted data [blocking]
❌ Encryption keys in source code or environment variables [important]

✅ Column-level encryption for BSN, diagnosis codes, notes
✅ Keys in HSM, Vault, or managed KMS (AWS KMS, Azure Key Vault, Infisical)
✅ Key rotation policy documented and automated
✅ Separate keys per tenant in multi-tenant systems
```

### Data in Transit

```
❌ Internal service-to-service communication over HTTP [important]
❌ TLS < 1.2 [blocking]
❌ Self-signed certificates in production [important]

✅ TLS 1.2+ for all connections (internal and external)
✅ HSTS header with includeSubdomains
✅ Certificate pinning for mobile apps accessing healthcare APIs
```

---

## Third-Party Integration Security

### Healthcare API Integration

```python
# ❌ Logging full request/response of external healthcare API [blocking]
logger.info(f"HL7 FHIR response: {response.json()}")
# May contain full patient records

# ✅ Log metadata only
logger.info(f"HL7 FHIR response: status={response.status_code}, "
            f"resource_type={response.json().get('resourceType')}, "
            f"count={len(response.json().get('entry', []))}")
```

### Webhook Security

```python
# ❌ Webhook endpoint without signature verification [blocking]
@app.route("/webhook/lab-results", methods=["POST"])
def receive_lab_results():
    data = request.json
    process_results(data)  # No verification that request is from legitimate source

# ✅ Verify webhook signature
@app.route("/webhook/lab-results", methods=["POST"])
def receive_lab_results():
    signature = request.headers.get("X-Signature-256")
    if not verify_webhook_signature(request.data, signature, WEBHOOK_SECRET):
        abort(403)
    data = request.json
    process_results(data)
```

---

## Logging Discipline

### What to Log vs What NOT to Log

```
MUST log (NEN 7510 §12.4):
✅ Authentication events (login, logout, failed attempts)
✅ Authorization failures (access denied)
✅ PHI access events (read, create, update, delete)
✅ Configuration changes
✅ Privilege escalation events
✅ Data export/print events

MUST NOT log:
❌ Passwords (including failed password attempts)
❌ BSN / patient identifiers (use internal IDs)
❌ Session tokens / API keys
❌ Medical diagnoses / notes content
❌ Credit card or banking details
❌ Full request/response bodies containing PHI
```

```python
# ❌ Logging sensitive data [blocking]
logger.info(f"Login attempt: user={username}, password={password}")
logger.info(f"Patient accessed: BSN={patient.bsn}, diagnosis={patient.diagnosis}")

# ✅ Logging with PII sanitization
logger.info(f"Login attempt: user={username}, result=failed, ip={ip}")
logger.info(f"Patient accessed: patient_id={patient.id}, action=read, actor={user.id}")
```

---

## Review Checklist

### NEN 7510 Compliance (Severity: blocking)
- [ ] Three-layer authorization (auth + role + data) on all PHI endpoints
- [ ] Individual user accounts — no shared credentials
- [ ] Session timeout <= 15 minutes for PHI access
- [ ] All PHI access events logged (read AND write)
- [ ] Audit log is append-only (no UPDATE/DELETE)
- [ ] TLS 1.2+ on all connections (internal + external)
- [ ] PHI encrypted at rest (column-level for BSN, diagnosis codes)
- [ ] Encryption keys not in source code

### OWASP Top 10 (Severity: blocking / important)
- [ ] No SQL/LDAP/OS injection vectors
- [ ] No XSS (output encoding on all user/DB content)
- [ ] No insecure deserialization
- [ ] No SSRF (server-side URL validation)
- [ ] CORS properly configured (not `*` on auth endpoints)
- [ ] Dependencies checked for known CVEs
- [ ] Debug mode disabled in production

### PII/PHI (Severity: blocking)
- [ ] BSN never in URLs, logs, client-side storage, or JavaScript bundles
- [ ] Patient names not in application logs
- [ ] Medical codes (DBC/ICD-10) not in client-side code
- [ ] PII transmitted only via POST over TLS
- [ ] BSN masked in UI (show last 3 digits only)

### Audit Trail (Severity: blocking)
- [ ] Every data mutation emits audit event
- [ ] Every PHI read emits audit event
- [ ] Audit events contain: actor, action, target, timestamp
- [ ] Mutation events contain before/after state
- [ ] Break-glass access requires mandatory justification
- [ ] Audit events are immutable (INSERT-only table)

### Evidence Tiers (Severity: important)
- [ ] Deterministic findings tagged as EV1 or EV2
- [ ] LLM-derived findings tagged as EV3 (default)
- [ ] Cross-LLM Gate-validated findings tagged as EV4
- [ ] Evidence tier noted in review comments

### AVG/GDPR (Severity: blocking / important)
- [ ] Data minimization — only necessary fields collected
- [ ] Soft-delete with retention policy (not hard delete for medical records)
- [ ] Valid verwerkingsovereenkomst for third-party PII sharing
- [ ] Consent/legal basis verified before processing special category data
- [ ] BSN never shared with third parties without explicit legal basis
- [ ] Anonymization mechanism available for erasure requests

### Logging (Severity: blocking)
- [ ] No passwords, tokens, or BSNs in log output
- [ ] No PHI content (diagnosis, notes) in application logs
- [ ] Authentication events logged
- [ ] Authorization failures logged with actor + target
