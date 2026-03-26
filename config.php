<?php
ini_set('display_errors', '1');
ini_set('display_startup_errors', '1');
error_reporting(E_ALL);

session_start();

/* =========================
   DEBUG / PROFILING
   - misura tempi pagina, DB e memoria
   - mostra pannello debug lato UI (app.php / login.php)
========================= */

class DebugMetrics {
  public static array $data = [
    'start_time'      => 0.0,
    'db_connect_ms'   => 0.0,
    'db_connected'    => false,
    'queries'         => [],
    'queries_count'   => 0,
    'queries_time_ms' => 0.0,
    'init_db_ms'      => 0.0,
    'migrate_db_ms'   => 0.0,
    'notes'           => [],
  ];

  public static function init(): void {
    if (!self::$data['start_time']) {
      self::$data['start_time'] = isset($_SERVER['REQUEST_TIME_FLOAT'])
        ? (float)$_SERVER['REQUEST_TIME_FLOAT']
        : microtime(true);
    }
  }

  public static function logDbConnect(float $ms): void {
    self::$data['db_connected'] = true;
    self::$data['db_connect_ms'] = $ms;
  }

  public static function logQuery(string $sql, ?array $params, float $ms): void {
    self::$data['queries_count']++;
    self::$data['queries_time_ms'] += $ms;

    // memorizza solo le prime N query per non appesantire
    if (count(self::$data['queries']) < 25) {
      $clean = preg_replace('/\s+/', ' ', trim($sql));
      if (strlen($clean) > 160) {
        $clean = substr($clean, 0, 157) . '...';
      }
      self::$data['queries'][] = [
        'sql' => $clean,
        'ms'  => $ms,
      ];
    }
  }

  public static function setSectionTime(string $key, float $ms): void {
    self::$data[$key] = $ms;
  }

  public static function addNote(string $note): void {
    self::$data['notes'][] = $note;
  }

  public static function summary(array $extra = []): array {
    $now = microtime(true);
    $total_ms = ($now - self::$data['start_time']) * 1000.0;
    $memory_peak = memory_get_peak_usage(true);

    $php_ms = max(0.0, $total_ms - self::$data['queries_time_ms']);

    $warnings = [];

    if (self::$data['migrate_db_ms'] > 10.0) {
      $ms = round(self::$data['migrate_db_ms']);
      $warnings[] = "La funzione migrate_db() viene eseguita in questa richiesta ({$ms} ms). Spostala in uno script di migrazione separato per evitare lentezza ad ogni pagina.";
    }

    if (self::$data['queries_count'] > 10 && self::$data['queries_time_ms'] > $total_ms * 0.5) {
      $warnings[] = "Molte query al DB (" . self::$data['queries_count'] . ") e tempo DB elevato (" . round(self::$data['queries_time_ms']) . " ms): possibile collo di bottiglia MySQL.";
    }

    if ($total_ms > 800 && self::$data['queries_time_ms'] < $total_ms * 0.4) {
      $warnings[] = "Tempo totale pagina alto (" . round($total_ms) . " ms) ma DB relativamente veloce: probabile lentezza lato PHP o server (CPU lenta / troppi processi).";
    }

    if ($memory_peak > 64 * 1024 * 1024) {
      $warnings[] = "Uso memoria elevato (~" . round($memory_peak / 1024 / 1024) . " MB).";
    }

    $summary = [
      'total_ms'        => $total_ms,
      'php_ms'          => $php_ms,
      'queries_count'   => self::$data['queries_count'],
      'queries_time_ms' => self::$data['queries_time_ms'],
      'db_connect_ms'   => self::$data['db_connect_ms'],
      'db_connected'    => self::$data['db_connected'],
      'init_db_ms'      => self::$data['init_db_ms'],
      'migrate_db_ms'   => self::$data['migrate_db_ms'],
      'memory_peak_mb'  => $memory_peak / 1024 / 1024,
      'notes'           => self::$data['notes'],
      'warnings'        => $warnings,
      'queries'         => self::$data['queries'],
    ];

    return array_merge($summary, $extra);
  }
}

class DebugPDOStatement extends PDOStatement {
  protected string $q;

  protected function __construct() {
    $this->q = $this->queryString;
  }

  public function execute($params = null): bool {
    $t0 = microtime(true);
    $ok = parent::execute($params);
    $dt = (microtime(true) - $t0) * 1000.0;
    DebugMetrics::logQuery($this->q, is_array($params) ? $params : [], $dt);
    return $ok;
  }
}

class DebugPDO extends PDO {
  public function __construct($dsn, $username = null, $passwd = null, $options = []) {
    $t0 = microtime(true);
    parent::__construct($dsn, $username, $passwd, $options);
    $dt = (microtime(true) - $t0) * 1000.0;
    DebugMetrics::logDbConnect($dt);

    $this->setAttribute(PDO::ATTR_STATEMENT_CLASS, [DebugPDOStatement::class, []]);
  }

  public function query(string $statement, ?int $mode = null, ...$fetchModeArgs) {
    $t0 = microtime(true);
    if ($mode === null) {
      $stmt = parent::query($statement);
    } else {
      $stmt = parent::query($statement, $mode, ...$fetchModeArgs);
    }
    $dt = (microtime(true) - $t0) * 1000.0;
    DebugMetrics::logQuery($statement, null, $dt);
    return $stmt;
  }

  public function exec($statement) {
    $t0 = microtime(true);
    $res = parent::exec($statement);
    $dt = (microtime(true) - $t0) * 1000.0;
    DebugMetrics::logQuery($statement, null, $dt);
    return $res;
  }
}

DebugMetrics::init();

/* =========================
   CONFIG UPLOADS
========================= */
$upload_dir = __DIR__ . '/uploadslist/';
$upload_url = 'uploadslist/';
if (!is_dir($upload_dir)) @mkdir($upload_dir, 0777, true);

/** Bootstrap admin (solo prima installazione) */
$bootstrap_admin_user = "admin";
$bootstrap_admin_pass = "lunabella";

/** DB config */
define('DB_HOST', 'localhost');
define('DB_NAME', 'rubrica');
define('DB_USER', 'root');
define('DB_PASS', 'homecasaluna'); // <-- metti la tua password DB

if (!function_exists('str_starts_with')) {
  function str_starts_with(string $haystack, string $needle): bool {
    return $needle === '' || strpos($haystack, $needle) === 0;
  }
}

function db(): PDO {
  static $pdo = null;
  if ($pdo) return $pdo;

  try {
    $dsn = "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=utf8mb4";
    $pdo = new PDO($dsn, DB_USER, DB_PASS, [
      PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
      PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
      PDO::ATTR_EMULATE_PREPARES => false,
    ]);
    return $pdo;
  } catch (Throwable $e) {
    http_response_code(500);
    echo "<pre style='padding:14px;background:#111;color:#fff;border-radius:12px;white-space:pre-wrap'>";
    echo "ERRORE CONNESSIONE DB\n\n";
    echo "Host: ".DB_HOST."\nDB: ".DB_NAME."\nUser: ".DB_USER."\n\n";
    echo "Dettaglio:\n".$e->getMessage();
    echo "</pre>";
    exit;
  }
}

function h($s) { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }

/* =========================
   LOCALIZATION (IT, EN, FR, ES)
========================= */
$AVAILABLE_LANGS = ['it' => 'Italiano', 'en' => 'English', 'fr' => 'Français', 'es' => 'Español'];

if (isset($_GET['lang']) && isset($AVAILABLE_LANGS[(string)$_GET['lang']])) {
  $_SESSION['lang'] = (string)$_GET['lang'];
  $redirect = strtok($_SERVER['REQUEST_URI'], '?');
  if (isset($_GET['view_user_id']) && (int)$_GET['view_user_id'] > 0) {
    $redirect .= (strpos($redirect, '?') !== false ? '&' : '?') . 'view_user_id=' . (int)$_GET['view_user_id'];
  }
  header("Location: " . $redirect);
  exit;
}

$CURRENT_LANG = $_SESSION['lang'] ?? 'it';
if (!isset($AVAILABLE_LANGS[$CURRENT_LANG])) {
  $CURRENT_LANG = 'it';
}
$_SESSION['lang'] = $CURRENT_LANG;

$LOCALE = [];
$locale_file = __DIR__ . '/localizable/' . $CURRENT_LANG . '.php';
if (file_exists($locale_file)) {
  $LOCALE = require $locale_file;
}

function t(string $key): string {
  global $LOCALE;
  return $LOCALE[$key] ?? $key;
}

function safe_path_inside_uploads($path, $upload_url) {
  if (!$path) return "";
  $path = str_replace("\\", "/", (string)$path);
  if (strpos($path, $upload_url) !== 0) return "";
  if (strpos($path, "..") !== false) return "";
  return $path;
}

/* =========================
   DB INIT + MIGRATION
========================= */
function init_db(string $admin_user, string $admin_pass): void {
  $t0 = microtime(true);

  $pdo = db();

  $pdo->exec("
    CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      username VARCHAR(50) NOT NULL UNIQUE,
      pass_hash VARCHAR(255) NOT NULL,
      role ENUM('admin','user') NOT NULL DEFAULT 'user',
      is_active TINYINT(1) NOT NULL DEFAULT 1,
      avatar VARCHAR(255) NOT NULL DEFAULT '',
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    ) ENGINE=InnoDB;
  ");

  $pdo->exec("
    CREATE TABLE IF NOT EXISTS contacts (
      id VARCHAR(64) PRIMARY KEY,
      user_id INT NOT NULL,
      nome VARCHAR(120) NOT NULL,
      cognome VARCHAR(120) NOT NULL DEFAULT '',
      telefono VARCHAR(60) NOT NULL,
      email VARCHAR(190) NOT NULL DEFAULT '',
      avatar VARCHAR(255) NOT NULL DEFAULT '',
      preferito TINYINT(1) NOT NULL DEFAULT 0,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      KEY idx_user_id (user_id),
      KEY idx_preferito_nome (preferito, nome),
      KEY idx_tel (telefono),
      KEY idx_email (email)
    ) ENGINE=InnoDB;
  ");

  // Bootstrap admin se non esiste
  $st = $pdo->prepare("SELECT id FROM users WHERE username=? LIMIT 1");
  $st->execute([$admin_user]);
  if (!$st->fetchColumn()) {
    $hash = password_hash($admin_pass, PASSWORD_DEFAULT);
    $ins = $pdo->prepare("INSERT INTO users (username, pass_hash, role, is_active) VALUES (?, ?, 'admin', 1)");
    $ins->execute([$admin_user, $hash]);
  }

  $dt = (microtime(true) - $t0) * 1000.0;
  DebugMetrics::setSectionTime('init_db_ms', $dt);
}

function table_exists(string $table): bool {
  $pdo = db();
  $st = $pdo->prepare("SELECT 1 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name=? LIMIT 1");
  $st->execute([$table]);
  return (bool)$st->fetchColumn();
}

function column_exists(string $table, string $column): bool {
  $pdo = db();
  $st = $pdo->prepare("SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name=? AND column_name=? LIMIT 1");
  $st->execute([$table, $column]);
  return (bool)$st->fetchColumn();
}

/**
 * Ritorna metadati colonna (column_type, is_nullable) oppure null se non esiste.
 */
function column_meta(string $table, string $column): ?array {
  $pdo = db();
  $st = $pdo->prepare("
    SELECT column_type, is_nullable
    FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name=? AND column_name=?
    LIMIT 1
  ");
  $st->execute([$table, $column]);
  $row = $st->fetch();
  return $row ?: null;
}

function migrate_db(): void {
  $t0 = microtime(true);

  $pdo = db();

  // USERS.role fix (esegui solo se davvero necessario)
  if (table_exists('users') && column_exists('users', 'role')) {
    $meta = column_meta('users', 'role');
    $type = strtolower((string)($meta['column_type'] ?? ''));
    // se non è già enum('admin','user'), esegui la migrazione una sola volta
    if (strpos($type, "enum('admin','user'") === false) {
      $pdo->exec("ALTER TABLE users MODIFY role VARCHAR(20) NOT NULL DEFAULT 'user'");
      $pdo->exec("UPDATE users SET role = LOWER(role)");
      // rimuovi ruoli legacy (es. moderator)
      $pdo->exec("UPDATE users SET role='user' WHERE role='moderator'");
      $pdo->exec("UPDATE users SET role='user' WHERE role IS NULL OR role='' OR role NOT IN ('admin','user')");
      $pdo->exec("ALTER TABLE users MODIFY role ENUM('admin','user') NOT NULL DEFAULT 'user'");
    }
  }

  // USERS.avatar (foto profilo utente)
  if (table_exists('users') && !column_exists('users', 'avatar')) {
    $pdo->exec("ALTER TABLE users ADD COLUMN avatar VARCHAR(255) NOT NULL DEFAULT '' AFTER is_active");
  }

  // CONTACTS.user_id migrazione (solo se colonna manca o è nullable)
  if (table_exists('contacts')) {
    $metaUserId = column_meta('contacts', 'user_id');
    $needsMigration = false;

    if ($metaUserId === null) {
      $needsMigration = true;
    } else {
      $isNullable = strtoupper((string)($metaUserId['is_nullable'] ?? 'YES'));
      if ($isNullable === 'YES') {
        $needsMigration = true;
      }
    }

    if ($needsMigration) {
      if ($metaUserId === null) {
        $pdo->exec("ALTER TABLE contacts ADD COLUMN user_id INT NULL AFTER id");
      }

      $adminId = (int)$pdo->query("SELECT id FROM users WHERE role='admin' ORDER BY id ASC LIMIT 1")->fetchColumn();
      if ($adminId <= 0) {
        $adminId = (int)$pdo->query("SELECT id FROM users ORDER BY id ASC LIMIT 1")->fetchColumn();
      }

      if ($adminId > 0) {
        $st = $pdo->prepare("UPDATE contacts SET user_id=? WHERE user_id IS NULL OR user_id=0");
        $st->execute([$adminId]);
      }

      $pdo->exec("ALTER TABLE contacts MODIFY user_id INT NOT NULL");

      // Indice
      try { $pdo->exec("ALTER TABLE contacts ADD KEY idx_user_id (user_id)"); } catch (Throwable $e) {}

      // FK (non blocca se già esiste o se non si può creare)
      try {
        $pdo->exec("ALTER TABLE contacts
          ADD CONSTRAINT fk_contacts_user
          FOREIGN KEY (user_id) REFERENCES users(id)
          ON DELETE CASCADE
        ");
      } catch (Throwable $e) {}
    }
  }

  $dt = (microtime(true) - $t0) * 1000.0;
  DebugMetrics::setSectionTime('migrate_db_ms', $dt);
  DebugMetrics::addNote('migrate_db eseguita in questa richiesta.');
}

init_db($bootstrap_admin_user, $bootstrap_admin_pass);

/* =========================
   CSRF
========================= */
if (empty($_SESSION['csrf'])) {
  $_SESSION['csrf'] = bin2hex(random_bytes(16));
}
$CSRF = $_SESSION['csrf'];

/* =========================
   AUTH HELPERS
========================= */
function current_user(): ?array {
  if (empty($_SESSION['uid'])) return null;
  $pdo = db();
  $cols = column_exists('users', 'avatar') ? 'id, username, role, is_active, avatar' : 'id, username, role, is_active';
  $st = $pdo->prepare("SELECT {$cols} FROM users WHERE id=? LIMIT 1");
  $st->execute([(int)$_SESSION['uid']]);
  $u = $st->fetch();
  if (!$u || (int)$u['is_active'] !== 1) return null;
  if (!isset($u['avatar'])) $u['avatar'] = '';
  return $u;
}

function require_auth(bool $json_on_fail = false): array {
  $u = current_user();
  if (!$u) {
    session_destroy();
    if ($json_on_fail) {
      header('Content-Type: application/json; charset=utf-8');
      http_response_code(401);
      echo json_encode(['ok' => false, 'error' => 'Sessione scaduta. Effettua nuovamente il login.'], JSON_UNESCAPED_UNICODE);
      exit();
    }
    header("Location: login.php");
    exit();
  }
  return $u;
}

function is_admin(array $u): bool { return ($u['role'] ?? '') === 'admin'; }

function can_manage_contacts(array $u): bool {
  $r = (string)($u['role'] ?? '');
  return in_array($r, ['admin','user'], true);
}

function require_admin(array $u): void {
  if (!is_admin($u)) { http_response_code(403); echo "Permesso negato."; exit; }
}

/* =========================
   USERS (ADMIN)
========================= */
function count_admins_active(): int {
  $pdo = db();
  return (int)$pdo->query("SELECT COUNT(*) FROM users WHERE role='admin' AND is_active=1")->fetchColumn();
}

function fetch_users(): array {
  $pdo = db();
  $cols = column_exists('users', 'avatar') ? 'id, username, role, is_active, avatar, created_at, updated_at' : 'id, username, role, is_active, created_at, updated_at';
  $rows = $pdo->query("SELECT {$cols} FROM users ORDER BY role='admin' DESC, username ASC")->fetchAll() ?: [];
  foreach ($rows as &$r) { if (!isset($r['avatar'])) $r['avatar'] = ''; }
  return $rows;
}

function fetch_users_for_select(): array {
  $pdo = db();
  $cols = column_exists('users', 'avatar') ? 'id, username, role, is_active, avatar' : 'id, username, role, is_active';
  $rows = $pdo->query("SELECT {$cols} FROM users WHERE is_active=1 ORDER BY username ASC")->fetchAll() ?: [];
  foreach ($rows as &$r) { if (!isset($r['avatar'])) $r['avatar'] = ''; }
  return $rows;
}

function set_user_avatar(int $uid, string $path): void {
  $pdo = db();
  $st = $pdo->prepare("UPDATE users SET avatar=? WHERE id=?");
  $st->execute([$path, $uid]);
}

function create_user_admin(string $username, string $plain_pass, string $role): void {
  $pdo = db();
  $hash = password_hash($plain_pass, PASSWORD_DEFAULT);
  $st = $pdo->prepare("INSERT INTO users (username, pass_hash, role, is_active) VALUES (?, ?, ?, 1)");
  $st->execute([$username, $hash, $role]);
}

function set_user_role(int $uid, string $role): void {
  $pdo = db();
  $st = $pdo->prepare("UPDATE users SET role=? WHERE id=?");
  $st->execute([$role, $uid]);
}

function set_user_active(int $uid, int $active): void {
  $pdo = db();
  $st = $pdo->prepare("UPDATE users SET is_active=? WHERE id=?");
  $st->execute([$active, $uid]);
}

function set_user_password(int $uid, string $plain_pass): void {
  $pdo = db();
  $hash = password_hash($plain_pass, PASSWORD_DEFAULT);
  $st = $pdo->prepare("UPDATE users SET pass_hash=? WHERE id=?");
  $st->execute([$hash, $uid]);
}

function delete_user(int $uid): void {
  $pdo = db();
  $st = $pdo->prepare("DELETE FROM users WHERE id=?");
  $st->execute([$uid]);
}

/* =========================
   CONTACTS CRUD (multi-tenant)
========================= */
function contact_belongs_to_user(string $id, int $uid): bool {
  $pdo = db();
  $st = $pdo->prepare("SELECT 1 FROM contacts WHERE id=? AND user_id=? LIMIT 1");
  $st->execute([$id, $uid]);
  return (bool)$st->fetchColumn();
}

function require_contact_access(array $user, string $contact_id, ?int $view_user_id = null): void {
  $uid = (int)$user['id'];
  $is_admin = ($user['role'] ?? '') === 'admin';

  if ($is_admin) {
    // Admin: può accedere solo ai propri contatti O ai contatti dell'utente che sta visualizzando
    if ($view_user_id !== null) {
      if (!contact_belongs_to_user($contact_id, $view_user_id)) {
        http_response_code(403);
        echo "Permesso negato.";
        exit;
      }
    } else {
      if (!contact_belongs_to_user($contact_id, $uid)) {
        http_response_code(403);
        echo "Permesso negato.";
        exit;
      }
    }
    return;
  }

  if (!contact_belongs_to_user($contact_id, $uid)) {
    http_response_code(403);
    echo "Permesso negato.";
    exit;
  }
}

/** Restituisce i contatti: per tutti gli utenti (incluso admin) solo i propri; se admin passa view_user_id vede quelli di quel utente */
function fetch_contacts(array $user, ?int $view_user_id = null): array {
  $pdo = db();
  $target_uid = (int)$user['id'];

  if (($user['role'] ?? '') === 'admin' && $view_user_id !== null && $view_user_id > 0) {
    $target_uid = $view_user_id;
  }

  $st = $pdo->prepare("SELECT * FROM contacts WHERE user_id=? ORDER BY preferito DESC, nome ASC");
  $st->execute([$target_uid]);
  $rows = $st->fetchAll();
  foreach ($rows as &$r) $r['preferito'] = (bool)((int)($r['preferito'] ?? 0));
  return $rows ?: [];
}

function upsert_contact(array $c): void {
  $pdo = db();
  $sql = "
    INSERT INTO contacts (id, user_id, nome, cognome, telefono, email, avatar, preferito)
    VALUES (:id, :user_id, :nome, :cognome, :telefono, :email, :avatar, :preferito)
    ON DUPLICATE KEY UPDATE
      nome=VALUES(nome),
      cognome=VALUES(cognome),
      telefono=VALUES(telefono),
      email=VALUES(email),
      avatar=VALUES(avatar),
      preferito=VALUES(preferito),
      user_id=VALUES(user_id)
  ";
  $st = $pdo->prepare($sql);
  $st->execute([
    ':id' => $c['id'],
    ':user_id' => (int)$c['user_id'],
    ':nome' => $c['nome'],
    ':cognome' => $c['cognome'],
    ':telefono' => $c['telefono'],
    ':email' => $c['email'],
    ':avatar' => $c['avatar'],
    ':preferito' => $c['preferito'] ? 1 : 0,
  ]);
}

function delete_contact(string $id): ?string {
  $pdo = db();
  $st = $pdo->prepare("SELECT avatar FROM contacts WHERE id=? LIMIT 1");
  $st->execute([$id]);
  $avatar = $st->fetchColumn();
  $del = $pdo->prepare("DELETE FROM contacts WHERE id=?");
  $del->execute([$id]);
  return is_string($avatar) ? $avatar : null;
}

function toggle_fav(string $id): void {
  $pdo = db();
  $st = $pdo->prepare("UPDATE contacts SET preferito = IF(preferito=1,0,1) WHERE id=?");
  $st->execute([$id]);
}

/* =========================
   DEBUG PANEL RENDER
   - chiamare debug_render_panel(...) a fine pagina
========================= */

function debug_render_panel(array $extra = []): void {
  $s = DebugMetrics::summary($extra);

  $total_ms        = round($s['total_ms']);
  $php_ms          = round($s['php_ms']);
  $queries_count   = (int)$s['queries_count'];
  $queries_time_ms = round($s['queries_time_ms']);
  $db_connect_ms   = round($s['db_connect_ms']);
  $init_db_ms      = round($s['init_db_ms']);
  $migrate_db_ms   = round($s['migrate_db_ms']);
  $memory_mb       = round($s['memory_peak_mb'], 1);

  $script   = $extra['script']   ?? ($_SERVER['SCRIPT_NAME'] ?? '');
  $username = $extra['username'] ?? null;
  $role     = $extra['role']     ?? null;
  $contacts = isset($extra['contacts_count']) ? (int)$extra['contacts_count'] : null;
  $users    = isset($extra['users_count']) ? (int)$extra['users_count'] : null;

  $warnings = $s['warnings'];
  $queries  = $s['queries'];
  ?>
  <div id="debug-panel" style="
    position:fixed;
    right:10px;
    bottom:10px;
    z-index:9999;
    font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;
    font-size:11px;
    color:#f9fafb;
  ">
    <div style="
      background:rgba(15,23,42,.92);
      border-radius:10px;
      border:1px solid rgba(148,163,184,.6);
      box-shadow:0 16px 40px rgba(0,0,0,.55);
      min-width:220px;
      max-width:320px;
      overflow:hidden;
      backdrop-filter:blur(14px);
      -webkit-backdrop-filter:blur(14px);
    ">
      <div style="display:flex;align-items:center;justify-content:space-between;padding:6px 8px 5px 8px;background:linear-gradient(135deg,rgba(56,189,248,.9),rgba(129,140,248,.9));color:#020617;">
        <div style="font-weight:700;letter-spacing:.04em;text-transform:uppercase;font-size:10px;">Debug performance</div>
        <button type="button" onclick="var b=document.getElementById('debug-body');if(!b)return;var h=b.style.display==='none';b.style.display=h?'block':'none';this.textContent=h?'–':'+';" style="
          border:none;
          background:rgba(15,23,42,.06);
          width:18px;height:18px;
          border-radius:999px;
          cursor:pointer;
          font-size:12px;
        ">–</button>
      </div>
      <div id="debug-body" style="padding:7px 8px 7px 8px;max-height:260px;overflow:auto;">
        <div style="margin-bottom:4px;">
          <div><strong>Pagina</strong>: <?= h(basename((string)$script)) ?></div>
          <?php if ($username): ?>
            <div><strong>Utente</strong>: <?= h($username) ?><?= $role ? " (".h($role).")" : "" ?></div>
          <?php endif; ?>
          <?php if ($contacts !== null): ?>
            <div><strong>Contatti</strong>: <?= $contacts ?></div>
          <?php endif; ?>
          <?php if ($users !== null): ?>
            <div><strong>Utenti</strong>: <?= $users ?></div>
          <?php endif; ?>
        </div>

        <div style="margin-top:4px;">
          <div><strong>Tempo totale</strong>: <?= $total_ms ?> ms</div>
          <div><strong>Tempo PHP</strong>: <?= $php_ms ?> ms</div>
          <div><strong>Query DB</strong>: <?= $queries_count ?> (<?= $queries_time_ms ?> ms)</div>
          <div><strong>Connessione DB</strong>: <?= $db_connect_ms ?> ms</div>
          <div><strong>init_db()</strong>: <?= $init_db_ms ?> ms</div>
          <div><strong>migrate_db()</strong>: <?= $migrate_db_ms ?> ms</div>
          <div><strong>Memoria picco</strong>: <?= $memory_mb ?> MB</div>
        </div>

        <?php if (!empty($warnings)): ?>
          <div style="margin-top:6px;padding:4px 5px;border-radius:7px;background:rgba(248,113,113,.16);border:1px solid rgba(248,113,113,.45);color:#fecaca;">
            <div style="font-weight:600;font-size:10px;margin-bottom:2px;text-transform:uppercase;letter-spacing:.08em;">Possibili cause lentezza</div>
            <ul style="padding-left:16px;margin:0;font-size:11px;">
              <?php foreach ($warnings as $w): ?>
                <li><?= h($w) ?></li>
              <?php endforeach; ?>
            </ul>
          </div>
        <?php endif; ?>

        <?php if (!empty($queries)): ?>
          <div style="margin-top:6px;">
            <div style="font-weight:600;font-size:10px;margin-bottom:2px;text-transform:uppercase;letter-spacing:.08em;">Ultime query (ms)</div>
            <ul style="padding-left:16px;margin:0;font-size:10px;max-height:120px;overflow:auto;">
              <?php foreach ($queries as $q): ?>
                <li><span style="color:#a5b4fc;"><?= round($q['ms']) ?></span> · <?= h($q['sql']) ?></li>
              <?php endforeach; ?>
            </ul>
          </div>
        <?php endif; ?>
      </div>
    </div>
  </div>
  <?php
}

