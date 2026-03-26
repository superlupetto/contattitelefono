<?php
require __DIR__ . '/config.php';

/* =========================
   AUTH OK
========================= */
$user = require_auth();

/* =========================
   LOGOUT
========================= */
if (isset($_GET['logout'])) {
  session_destroy();
  header("Location: login.php");
  exit();
}

/* =========================
   TOAST
========================= */
$toast_msg = $_SESSION['toast_msg'] ?? null;
$toast_err = $_SESSION['toast_err'] ?? null;
unset($_SESSION['toast_msg'], $_SESSION['toast_err']);

/* =========================
   ADMIN ACTIONS (users)
========================= */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['azione']) && str_starts_with((string)$_POST['azione'], 'admin_')) {
  if (!hash_equals($_SESSION['csrf'] ?? '', (string)($_POST['csrf'] ?? ''))) {
    $_SESSION['toast_err'] = t('error_csrf_req');
    header("Location: app.php");
    exit();
  }
  require_admin($user);

  try {
    $azione = (string)$_POST['azione'];

    if ($azione === 'admin_create_user') {
      $new_user = trim((string)($_POST['new_user'] ?? ''));
      $new_pass = (string)($_POST['new_pass'] ?? '');
      $new_pass2 = (string)($_POST['new_pass2'] ?? '');
      $role_in = (string)($_POST['new_role'] ?? 'user');
      $role = in_array($role_in, ['admin','user'], true) ? $role_in : 'user';

      if ($new_user === '' || !preg_match('/^[a-zA-Z0-9._-]{3,50}$/', $new_user)) {
        $_SESSION['toast_err'] = t('error_username_invalid');
      } elseif (strlen($new_pass) < 6) {
        $_SESSION['toast_err'] = t('error_password_short');
      } elseif ($new_pass !== $new_pass2) {
        $_SESSION['toast_err'] = t('error_password_mismatch');
      } else {
        create_user_admin($new_user, $new_pass, $role);
        $_SESSION['toast_msg'] = t('msg_user_created') . $new_user . ")";
      }

    } elseif ($azione === 'admin_set_role') {
      $uid = (int)($_POST['uid'] ?? 0);
      $role_in = (string)($_POST['role'] ?? 'user');
      $role = in_array($role_in, ['admin','user'], true) ? $role_in : 'user';

      if ($uid <= 0) {
        $_SESSION['toast_err'] = t('error_invalid_user');
      } else {
        $pdo = db();
        $st = $pdo->prepare("SELECT username FROM users WHERE id=? LIMIT 1");
        $st->execute([$uid]);
        $uname = (string)$st->fetchColumn();

        if ($uname === 'admin') {
          $_SESSION['toast_err'] = t('error_admin_no_role');
        } elseif ($uid === (int)$user['id']) {
          $_SESSION['toast_err'] = t('error_cant_change_self_role');
        } else {
          set_user_role($uid, $role);
          $_SESSION['toast_msg'] = t('msg_role_updated');
        }
      }

    } elseif ($azione === 'admin_toggle_active') {
      $uid = (int)($_POST['uid'] ?? 0);
      $active = (int)($_POST['active'] ?? 1);

      if ($uid === (int)$user['id']) {
        $_SESSION['toast_err'] = t('error_cant_deactivate_self');
      } else {
        if ($active === 0) {
          $pdo = db();
          $st = $pdo->prepare("SELECT username, role, is_active FROM users WHERE id=? LIMIT 1");
          $st->execute([$uid]);
          $t = $st->fetch();
          if ($t && ($t['username'] ?? '') === 'admin') {
            $_SESSION['toast_err'] = t('error_admin_no_deactivate');
            header("Location: app.php");
            exit();
          }
          if ($t && ($t['role'] ?? '') === 'admin' && (int)($t['is_active'] ?? 1) === 1) {
            if (count_admins_active() <= 1) {
              $_SESSION['toast_err'] = t('error_min_one_admin');
              header("Location: app.php");
              exit();
            }
          }
        }
        set_user_active($uid, $active);
        $_SESSION['toast_msg'] = $active ? t('msg_user_reactivated') : t('msg_user_deactivated');
      }

    } elseif ($azione === 'admin_delete_user') {
      $uid = (int)($_POST['uid'] ?? 0);

      if ($uid === (int)$user['id']) {
        $_SESSION['toast_err'] = t('error_cant_delete_self');
      } else {
        $pdo = db();
        $st = $pdo->prepare("SELECT username, role, is_active FROM users WHERE id=? LIMIT 1");
        $st->execute([$uid]);
        $t = $st->fetch();
        if ($t && ($t['username'] ?? '') === 'admin') {
          $_SESSION['toast_err'] = t('error_admin_no_delete');
          header("Location: app.php");
          exit();
        }
        if ($t && ($t['role'] ?? '') === 'admin' && (int)($t['is_active'] ?? 1) === 1) {
          if (count_admins_active() <= 1) {
            $_SESSION['toast_err'] = t('error_min_one_admin');
            header("Location: app.php");
            exit();
          }
        }
        delete_user($uid);
        $_SESSION['toast_msg'] = t('msg_user_deleted');
      }

    } elseif ($azione === 'admin_set_password') {
      $uid = (int)($_POST['uid'] ?? 0);
      $p1 = (string)($_POST['new_pass'] ?? '');
      $p2 = (string)($_POST['new_pass2'] ?? '');

      if ($uid <= 0) {
        $_SESSION['toast_err'] = t('error_invalid_user');
      } elseif ($uid === (int)$user['id']) {
        $_SESSION['toast_err'] = t('error_use_change_pass');
      } elseif (strlen($p1) < 6) {
        $_SESSION['toast_err'] = t('error_password_short');
      } elseif ($p1 !== $p2) {
        $_SESSION['toast_err'] = t('error_password_mismatch');
      } else {
        set_user_password($uid, $p1);
        $_SESSION['toast_msg'] = t('msg_password_updated');
      }
    }

  } catch (Throwable $e) {
    $_SESSION['toast_err'] = "Errore DB: " . $e->getMessage();
  }

  header("Location: app.php");
  exit();
}

/* =========================
   CHANGE PASSWORD (utente loggato)
========================= */
if ($_SERVER["REQUEST_METHOD"] === "POST" && (string)($_POST['azione'] ?? '') === 'change_pass') {
  if (!hash_equals($_SESSION['csrf'] ?? '', (string)($_POST['csrf'] ?? ''))) {
    $_SESSION['toast_err'] = t('error_csrf_req');
    header("Location: app.php");
    exit();
  }

  $old = (string)($_POST['old_pass'] ?? '');
  $new = (string)($_POST['new_pass'] ?? '');
  $new2 = (string)($_POST['new_pass2'] ?? '');

  $pdo = db();
  $st = $pdo->prepare("SELECT pass_hash FROM users WHERE id=? LIMIT 1");
  $st->execute([(int)$user['id']]);
  $hash = $st->fetchColumn();

  if (!$hash || !password_verify($old, (string)$hash)) {
    $_SESSION['toast_err'] = t('error_wrong_password');
  } elseif (strlen($new) < 6) {
    $_SESSION['toast_err'] = t('error_new_password_short');
  } elseif ($new !== $new2) {
    $_SESSION['toast_err'] = t('error_new_password_mismatch');
  } else {
    $new_hash = password_hash($new, PASSWORD_DEFAULT);
    $up = $pdo->prepare("UPDATE users SET pass_hash=? WHERE id=?");
    $up->execute([$new_hash, (int)$user['id']]);
    $_SESSION['toast_msg'] = t('msg_password_updated');
  }

  header("Location: app.php");
  exit();
}

/* =========================
   VIEW USER ID (solo admin dal pannello utenti)
========================= */
$view_user_id = null;
$view_user_info = null;
if (is_admin($user) && isset($_GET['view_user_id'])) {
  $vid = (int)$_GET['view_user_id'];
  if ($vid > 0) {
    $pdo = db();
    $st = $pdo->prepare("SELECT id, username FROM users WHERE id=? AND is_active=1 LIMIT 1");
    $st->execute([$vid]);
    $view_user_info = $st->fetch();
    if ($view_user_info) {
      $view_user_id = $vid;
    }
  }
}

/* =========================
   CRUD CONTATTI
========================= */
if ($_SERVER["REQUEST_METHOD"] === "POST" && (string)($_POST['azione'] ?? '') === 'salva') {
  if (!hash_equals($_SESSION['csrf'] ?? '', (string)($_POST['csrf'] ?? ''))) {
    $_SESSION['toast_err'] = t('error_csrf_req');
    header("Location: app.php");
    exit();
  }

  if (!can_manage_contacts($user)) {
    http_response_code(403);
    echo "Permesso negato.";
    exit;
  }

  $id = !empty($_POST['id']) ? (string)$_POST['id'] : uniqid("c_", true);

  // verifica ownership del contatto
  if (!empty($_POST['id'])) {
    require_contact_access($user, (string)$_POST['id'], $view_user_id);
  }

  $old_avatar = safe_path_inside_uploads($_POST['old_avatar'] ?? "", $upload_url);
  $avatar_path = $old_avatar;

  if (isset($_FILES['avatar']) && isset($_FILES['avatar']['error']) && $_FILES['avatar']['error'] === 0) {
    $orig = (string)($_FILES["avatar"]["name"] ?? "avatar");
    $ext = strtolower(pathinfo($orig, PATHINFO_EXTENSION));
    $allowed = ["jpg","jpeg","png","webp","gif"];

    if (in_array($ext, $allowed, true)) {
      $base = preg_replace("/[^a-zA-Z0-9._-]/", "_", pathinfo($orig, PATHINFO_FILENAME));
      $avatar_name = time() . "_" . $base . "." . $ext;

      if (move_uploaded_file($_FILES["avatar"]["tmp_name"], $upload_dir . $avatar_name)) {
        if (!empty($old_avatar) && file_exists(__DIR__ . "/" . $old_avatar)) {
          @unlink(__DIR__ . "/" . $old_avatar);
        }
        $avatar_path = $upload_url . $avatar_name;
      }
    }
  }

  $preferito = (isset($_POST['preferito']) && (string)$_POST['preferito'] === '1');

  // owner: se admin in modalità "visualizza utente X" usa X, altrimenti usa proprio id
  $owner_id = (int)$user['id'];
  if ($view_user_id !== null) {
    $owner_id = $view_user_id;
  }

  $contact_data = [
    'id' => $id,
    'user_id' => $owner_id,
    'nome' => trim((string)($_POST['nome'] ?? "")),
    'cognome' => trim((string)($_POST['cognome'] ?? "")),
    'telefono' => trim((string)($_POST['telefono'] ?? "")),
    'email' => trim((string)($_POST['email'] ?? "")),
    'avatar' => $avatar_path,
    'preferito' => $preferito
  ];

  upsert_contact($contact_data);
  $redirect = $view_user_id ? "app.php?view_user_id=" . $view_user_id : "app.php";
  header("Location: " . $redirect);
  exit();
}

/* =========================
   IMPORT DA SIM (VCF / CSV)
========================= */
if ($_SERVER["REQUEST_METHOD"] === "POST" && (string)($_POST['azione'] ?? '') === 'import_sim') {
  if (!hash_equals($_SESSION['csrf'] ?? '', (string)($_POST['csrf'] ?? ''))) {
    $_SESSION['toast_err'] = t('error_csrf_req');
    header("Location: app.php" . ($view_user_id ? "?view_user_id=" . $view_user_id : ""));
    exit();
  }
  if (!can_manage_contacts($user)) {
    $_SESSION['toast_err'] = t('error_csrf_req');
    header("Location: app.php" . ($view_user_id ? "?view_user_id=" . $view_user_id : ""));
    exit();
  }

  $owner_id = (int)$user['id'];
  if ($view_user_id !== null) $owner_id = $view_user_id;

  $imported = 0;
  $err_msg = null;

  if (!empty($_FILES['sim_file']['tmp_name']) && is_uploaded_file($_FILES['sim_file']['tmp_name'])) {
    $tmp = $_FILES['sim_file']['tmp_name'];
    $name = strtolower((string)($_FILES['sim_file']['name'] ?? ''));
    $content = @file_get_contents($tmp);
    if ($content === false) $content = '';

    $contacts_to_import = [];
    if (substr($name, -4) === '.vcf' || strpos($content, 'BEGIN:VCARD') !== false) {
      // Parse VCF (vCard)
      $blocks = preg_split('/\nBEGIN:VCARD\n/i', "\n" . $content);
      foreach ($blocks as $card) {
        $card = trim($card);
        if ($card === '') continue;
        if (!preg_match('/^BEGIN:VCARD/i', $card)) $card = "BEGIN:VCARD\r\n" . $card;
        $card = preg_replace('/\r\n\s/', '', $card);
        $n = $fn = $tel = $email = '';
        if (preg_match('/N:([^\r\n]*)/i', $card, $m)) $n = trim($m[1]);
        if (preg_match('/FN:([^\r\n]*)/i', $card, $m)) $fn = trim($m[1]);
        if (preg_match('/TEL[^:]*:([^\r\n]*)/i', $card, $m)) $tel = preg_replace('/[^\d+]/', '', $m[1]);
        if (preg_match('/EMAIL[^:]*:([^\r\n]*)/i', $card, $m)) $email = trim($m[1]);
        if ($tel !== '' || $fn !== '' || $n !== '') {
          $nome = $cognome = '';
          if ($n) {
            $parts = array_map('trim', explode(';', $n));
            $cognome = $parts[0] ?? '';
            $nome = $parts[1] ?? '';
            if ($nome === '' && $cognome !== '') { $nome = $cognome; $cognome = ''; }
          }
          if ($nome === '') $nome = $fn;
          $nome = $nome ?: t('no_name');
          $contacts_to_import[] = [
            'nome' => $nome,
            'cognome' => $cognome,
            'telefono' => $tel ?: ' ',
            'email' => '',
          ];
        }
      }
    } elseif (substr($name, -4) === '.csv' || strpos($content, ',') !== false || strpos($content, ';') !== false) {
      // Parse CSV (supporta virgola e punto e virgola) - formato Google Contacts
      $lines = preg_split('/\r?\n/', $content);
      if (count($lines) < 2) $lines = [];
      $delim = (substr_count($lines[0] ?? '', ';') >= substr_count($lines[0] ?? '', ',')) ? ';' : ',';
      $header = array_map('trim', str_getcsv($lines[0] ?? '', $delim, '"'));
      $header_lower = array_map('strtolower', $header);
      $idx_first = $idx_middle = $idx_last = $idx_name = $idx_nome = $idx_cognome = $idx_tel = $idx_phone = $idx_phone_value = -1;
      foreach ($header_lower as $i => $h) {
        $h = trim($h);
        if (in_array($h, ['first name', 'first', 'given'], true)) $idx_first = $i;
        elseif (in_array($h, ['middle name', 'middle'], true)) $idx_middle = $i;
        elseif (in_array($h, ['last name', 'last', 'family', 'cognome'], true)) $idx_last = $i;
        elseif (in_array($h, ['name', 'nome', 'display name', 'display name 1'], true)) $idx_name = $i;
        elseif (in_array($h, ['tel', 'telefono', 'phone', 'mobile', 'cell'], true)) { $idx_tel = $i; if ($idx_phone < 0) $idx_phone = $i; }
        elseif ($h === 'phone 1 - value' || strpos($h, 'phone') !== false && strpos($h, 'value') !== false) $idx_phone_value = $i;
      }
      if ($idx_tel < 0 && $idx_phone_value < 0) {
        foreach ($header_lower as $i => $h) {
          if (strpos($h, 'phone') !== false || strpos($h, 'tel') !== false) {
            if (strpos($h, 'value') !== false) $idx_phone_value = $i;
            else { $idx_tel = $i; if ($idx_phone < 0) $idx_phone = $i; }
            break;
          }
        }
      }
      if ($idx_phone_value >= 0) $idx_tel = $idx_phone_value;
      if ($idx_tel < 0 && $idx_phone >= 0) $idx_tel = $idx_phone;
      for ($i = 1; $i < count($lines); $i++) {
        $row = str_getcsv($lines[$i], $delim, '"');
        $first = trim($row[$idx_first] ?? '');
        $middle = trim($row[$idx_middle] ?? '');
        $last = trim($row[$idx_last] ?? '');
        $nome = trim($row[$idx_name] ?? $row[$idx_nome] ?? '');
        $cognome = trim($row[$idx_cognome] ?? '');
        $tel_raw = trim($row[$idx_tel] ?? $row[$idx_phone] ?? '');
        $tel = preg_replace('/[^\d+]/', '', $tel_raw);
        if ($idx_first >= 0 || $idx_last >= 0) {
          $nome = trim($first . ' ' . $middle) ?: $nome;
          $cognome = $last ?: $cognome;
        }
        if ($nome === '' && $cognome === '') $nome = trim($row[0] ?? '');
        if ($tel === '' && isset($row[1])) $tel = preg_replace('/[^\d+]/', '', (string)$row[1]);
        if ($tel !== '' || $nome !== '' || $cognome !== '') {
          $contacts_to_import[] = [
            'nome' => $nome ?: t('no_name'),
            'cognome' => $cognome,
            'telefono' => $tel ?: ' ',
            'email' => '',
          ];
        }
      }
    } else {
      $err_msg = t('import_sim_invalid_format');
    }

    foreach ($contacts_to_import as $c) {
      $id = 'c_' . uniqid('', true);
      $contact_data = [
        'id' => $id,
        'user_id' => $owner_id,
        'nome' => $c['nome'],
        'cognome' => $c['cognome'],
        'telefono' => $c['telefono'],
        'email' => $c['email'],
        'avatar' => '',
        'preferito' => false,
      ];
      upsert_contact($contact_data);
      $imported++;
    }
  } else {
    $err_msg = t('import_sim_no_file');
  }

  $redirect = $view_user_id ? "app.php?view_user_id=" . $view_user_id : "app.php";
  if ($err_msg) {
    $_SESSION['toast_err'] = $err_msg;
  } elseif ($imported > 0) {
    $_SESSION['toast_msg'] = str_replace('{n}', (string)$imported, t('import_sim_success'));
  }
  header("Location: " . $redirect);
  exit();
}

/* =========================
   DELETE MULTIPLE CONTACTS
========================= */
if ($_SERVER["REQUEST_METHOD"] === "POST" && (string)($_POST['azione'] ?? '') === 'delete_multiple') {
  if (!hash_equals($_SESSION['csrf'] ?? '', (string)($_POST['csrf'] ?? ''))) {
    $_SESSION['toast_err'] = t('error_csrf_req');
    header("Location: app.php" . ($view_user_id ? "?view_user_id=" . $view_user_id : ""));
    exit();
  }
  if (!can_manage_contacts($user)) {
    $_SESSION['toast_err'] = t('error_csrf_req');
    header("Location: app.php" . ($view_user_id ? "?view_user_id=" . $view_user_id : ""));
    exit();
  }

  $ids = isset($_POST['ids']) && is_array($_POST['ids']) ? $_POST['ids'] : [];
  $deleted = 0;
  foreach ($ids as $id) {
    $id = trim((string)$id);
    if ($id === '') continue;
    require_contact_access($user, $id, $view_user_id);
    $avatar = delete_contact($id);
    $av = safe_path_inside_uploads($avatar ?? "", $upload_url);
    if (!empty($av) && file_exists(__DIR__ . "/" . $av)) @unlink(__DIR__ . "/" . $av);
    $deleted++;
  }

  $redirect = $view_user_id ? "app.php?view_user_id=" . $view_user_id : "app.php";
  if ($deleted > 0) {
    $_SESSION['toast_msg'] = str_replace('{n}', (string)$deleted, t('delete_multiple_success'));
  }
  header("Location: " . $redirect);
  exit();
}

if (isset($_GET['action'], $_GET['id'])) {
  $action = (string)$_GET['action'];
  $id = (string)$_GET['id'];

  if (!can_manage_contacts($user)) {
    http_response_code(403);
    echo "Permesso negato.";
    exit;
  }

  require_contact_access($user, $id, $view_user_id);

  if ($action === 'delete') {
    $avatar = delete_contact($id);
    $av = safe_path_inside_uploads($avatar ?? "", $upload_url);
    if (!empty($av) && file_exists(__DIR__ . "/" . $av)) @unlink(__DIR__ . "/" . $av);
  } elseif ($action === 'toggle_fav') {
    toggle_fav($id);
  }

  $redirect = $view_user_id ? "app.php?view_user_id=" . $view_user_id : "app.php";
  header("Location: " . $redirect);
  exit();
}

/* =========================
   DATA FOR UI
========================= */
$contacts = fetch_contacts($user, $view_user_id);
$contacts_json = json_encode($contacts, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

$users = is_admin($user) ? fetch_users() : [];
$users_json = json_encode($users, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
?>
<!doctype html>
<html lang="<?= htmlspecialchars($CURRENT_LANG) ?>">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover" />
  <title><?= t('page_contacts') ?></title>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/cropperjs/1.6.2/cropper.min.css" crossorigin="anonymous" />
  <style>
    :root, [data-theme="default"]{
      --bg0:#070b16;
      --bg1:#0b1630;
      --bg-gradient: radial-gradient(ellipse 140vw 100vh at 15% 5%, rgba(125,211,252,.22), transparent 55%),
        radial-gradient(ellipse 100vw 80vh at 88% 10%, rgba(167,139,250,.20), transparent 50%),
        radial-gradient(ellipse 100vw 90vh at 55% 98%, rgba(52,211,153,.12), transparent 55%),
        linear-gradient(180deg, var(--bg0), var(--bg1));
      --glass: rgba(255,255,255,.10);
      --glass2: rgba(255,255,255,.14);
      --stroke: rgba(255,255,255,.18);
      --text: rgba(255,255,255,.92);
      --muted: rgba(255,255,255,.68);
      --muted2: rgba(255,255,255,.50);
      --shadow: 0 24px 70px rgba(0,0,0,.48);
      --radius: 22px;
      --radius2: 18px;
      --danger:#fb7185;
      --accent1: rgba(125,211,252,.95);
      --accent2: rgba(167,139,250,.90);
      --accent-gradient: linear-gradient(135deg, var(--accent1), var(--accent2));
      --topbar-bg: linear-gradient(180deg, rgba(10,15,30,.72), rgba(10,15,30,.35));
      --card-bg: linear-gradient(180deg, rgba(255,255,255,.10), rgba(255,255,255,.05));
      --input-bg: rgba(0,0,0,.14);
      --focus-ring: rgba(125,211,252,.14);
      --focus-border: rgba(125,211,252,.55);
      --success-bg: rgba(52,211,153,.12);
      --success-border: rgba(52,211,153,.35);
      --menu-bg: rgba(12,20,40,.95);
    }
    [data-theme="ocean"]{
      --bg0:#05101a;
      --bg1:#0a1e2e;
      --bg-gradient: radial-gradient(ellipse 140vw 100vh at 20% 0%, rgba(6,182,212,.25), transparent 50%),
        radial-gradient(ellipse 100vw 80vh at 80% 20%, rgba(14,165,233,.18), transparent 50%),
        radial-gradient(ellipse 100vw 90vh at 50% 100%, rgba(34,211,238,.10), transparent 55%),
        linear-gradient(180deg, var(--bg0), var(--bg1));
      --accent1: rgba(6,182,212,.95);
      --accent2: rgba(14,165,233,.90);
      --topbar-bg: linear-gradient(180deg, rgba(5,16,26,.78), rgba(10,30,46,.38));
      --focus-ring: rgba(6,182,212,.18);
      --focus-border: rgba(6,182,212,.55);
    }
    [data-theme="sunset"]{
      --bg0:#1a0a0f;
      --bg1:#2e1520;
      --bg-gradient: radial-gradient(ellipse 140vw 100vh at 10% 5%, rgba(251,146,60,.22), transparent 55%),
        radial-gradient(ellipse 100vw 80vh at 90% 15%, rgba(244,63,94,.20), transparent 50%),
        radial-gradient(ellipse 100vw 90vh at 50% 95%, rgba(251,113,133,.12), transparent 55%),
        linear-gradient(180deg, var(--bg0), var(--bg1));
      --accent1: rgba(251,146,60,.95);
      --accent2: rgba(244,63,94,.90);
      --topbar-bg: linear-gradient(180deg, rgba(26,10,15,.78), rgba(46,21,32,.38));
      --focus-ring: rgba(251,146,60,.18);
      --focus-border: rgba(251,146,60,.55);
    }
    [data-theme="forest"]{
      --bg0:#051508;
      --bg1:#0a1f0e;
      --bg-gradient: radial-gradient(ellipse 140vw 100vh at 25% 0%, rgba(34,197,94,.20), transparent 55%),
        radial-gradient(ellipse 100vw 80vh at 75% 15%, rgba(22,163,74,.18), transparent 50%),
        radial-gradient(ellipse 100vw 90vh at 50% 100%, rgba(74,222,128,.10), transparent 55%),
        linear-gradient(180deg, var(--bg0), var(--bg1));
      --accent1: rgba(34,197,94,.95);
      --accent2: rgba(22,163,74,.90);
      --topbar-bg: linear-gradient(180deg, rgba(5,21,8,.78), rgba(10,31,14,.38));
      --focus-ring: rgba(34,197,94,.18);
      --focus-border: rgba(34,197,94,.55);
    }
    [data-theme="midnight"]{
      --bg0:#030712;
      --bg1:#0f172a;
      --bg-gradient: radial-gradient(ellipse 140vw 100vh at 30% 0%, rgba(99,102,241,.15), transparent 55%),
        radial-gradient(ellipse 100vw 80vh at 70% 20%, rgba(79,70,229,.12), transparent 50%),
        radial-gradient(ellipse 100vw 90vh at 50% 98%, rgba(129,140,248,.08), transparent 55%),
        linear-gradient(180deg, var(--bg0), var(--bg1));
      --accent1: rgba(99,102,241,.95);
      --accent2: rgba(129,140,248,.90);
      --topbar-bg: linear-gradient(180deg, rgba(3,7,18,.85), rgba(15,23,42,.45));
      --focus-ring: rgba(99,102,241,.18);
      --focus-border: rgba(99,102,241,.55);
    }
    [data-theme="rose"]{
      --bg0:#1c0a12;
      --bg1:#2d1520;
      --bg-gradient: radial-gradient(ellipse 140vw 100vh at 15% 5%, rgba(244,114,182,.22), transparent 55%),
        radial-gradient(ellipse 100vw 80vh at 85% 15%, rgba(236,72,153,.18), transparent 50%),
        radial-gradient(ellipse 100vw 90vh at 55% 98%, rgba(251,113,133,.12), transparent 55%),
        linear-gradient(180deg, var(--bg0), var(--bg1));
      --accent1: rgba(244,114,182,.95);
      --accent2: rgba(236,72,153,.90);
      --topbar-bg: linear-gradient(180deg, rgba(28,10,18,.78), rgba(45,21,32,.38));
      --focus-ring: rgba(244,114,182,.18);
      --focus-border: rgba(244,114,182,.55);
    }
    [data-theme="amber"]{
      --bg0:#1a1205;
      --bg1:#2d1f0a;
      --bg-gradient: radial-gradient(ellipse 140vw 100vh at 20% 0%, rgba(245,158,11,.22), transparent 55%),
        radial-gradient(ellipse 100vw 80vh at 80% 10%, rgba(217,119,6,.18), transparent 50%),
        radial-gradient(ellipse 100vw 90vh at 50% 98%, rgba(251,191,36,.12), transparent 55%),
        linear-gradient(180deg, var(--bg0), var(--bg1));
      --accent1: rgba(245,158,11,.95);
      --accent2: rgba(217,119,6,.90);
      --topbar-bg: linear-gradient(180deg, rgba(26,18,5,.78), rgba(45,31,10,.38));
      --focus-ring: rgba(245,158,11,.18);
      --focus-border: rgba(245,158,11,.55);
    }
    *{box-sizing:border-box}
    html,body{min-height:100%; height:100%}
    body{
      margin:0;
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial, "Apple Color Emoji","Segoe UI Emoji";
      color: var(--text);
      background: var(--bg-gradient);
      background-attachment: fixed;
      background-size: cover;
      background-position: center;
      padding-bottom: 40px;
    }
    .topbar{
      position: sticky; top: 0;
      z-index: 50;
      padding: max(14px, env(safe-area-inset-top)) 16px 12px 16px;
      backdrop-filter: blur(18px);
      -webkit-backdrop-filter: blur(18px);
      background: var(--topbar-bg);
      border-bottom: 1px solid rgba(255,255,255,.10);
    }
    .topbar-inner{
      width:min(980px, 100%);
      margin:0 auto;
      display:flex;
      align-items:center;
      justify-content:space-between;
      gap:12px;
    }
    .title{
      display:flex; align-items:center; gap:12px;
      min-width: 0;
    }
    .appdot{
      width:38px; height:38px;
      border-radius: 14px;
      background: var(--accent-gradient);
      box-shadow: 0 16px 40px rgba(0,0,0,.30);
      flex:0 0 auto;
    }
    h1{
      margin:0;
      font-size: 18px;
      font-weight: 780;
      letter-spacing:.2px;
      line-height:1.1;
    }
    .subtitle{
      margin: 2px 0 0;
      color: var(--muted);
      font-size: 12.5px;
      white-space: nowrap;
      overflow:hidden;
      text-overflow: ellipsis;
      max-width: 56vw;
    }
    .actions{
      display:flex;
      align-items:center;
      gap:10px;
      flex:0 0 auto;
    }
    .iconbtn{
      width: 40px; height: 40px;
      border-radius: 16px;
      border: 1px solid rgba(255,255,255,.16);
      background: rgba(255,255,255,.08);
      color: var(--text);
      cursor:pointer;
      display:grid;
      place-items:center;
      transition:.18s ease;
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      box-shadow: 0 12px 30px rgba(0,0,0,.22);
      user-select:none;
    }
    .iconbtn:hover{ transform: translateY(-1px); background: rgba(255,255,255,.10) }
    .iconbtn:active{ transform: translateY(1px); background: rgba(255,255,255,.07) }
    .logout{
      color: var(--muted);
      text-decoration:none;
      font-size: 13px;
      padding: 10px 12px;
      border-radius: 16px;
      border: 1px solid rgba(255,255,255,.12);
      background: rgba(255,255,255,.06);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      transition:.18s ease;
      white-space:nowrap;
    }
    .logout:hover{ color: var(--text); background: rgba(255,255,255,.08) }
    .profileDropdown{ position:relative; }
    .profileBtn{
      width: 42px; height: 42px;
      border-radius: 50%;
      border: 1px solid rgba(255,255,255,.2);
      background: linear-gradient(135deg, color-mix(in srgb, var(--accent1) 50%, transparent), color-mix(in srgb, var(--accent2) 50%, transparent));
      color: var(--text);
      font-size: 20px;
      cursor: pointer;
      display: grid; place-items: center;
      transition: .18s ease;
      backdrop-filter: blur(12px);
      box-shadow: 0 12px 30px rgba(0,0,0,.22);
    }
    .profileBtn:hover{ transform: scale(1.05); background: linear-gradient(135deg, color-mix(in srgb, var(--accent1) 70%, transparent), color-mix(in srgb, var(--accent2) 70%, transparent)); }
    .profileBtnImg{ width:100%; height:100%; object-fit:cover; border-radius:50%; }
    .profileMenu{
      position: absolute;
      top: calc(100% + 8px);
      right: 0;
      min-width: 200px;
      border-radius: 18px;
      border: 1px solid rgba(255,255,255,.18);
      background: var(--menu-bg);
      backdrop-filter: blur(20px);
      box-shadow: 0 24px 60px rgba(0,0,0,.5);
      padding: 8px;
      display: none;
      z-index: 100;
    }
    .profileMenu.open{ display: block; animation: dropdownPop .2s ease; }
    @keyframes dropdownPop{ from{ opacity:0; transform: translateY(-8px); } to{ opacity:1; transform: translateY(0); } }
    .profileMenu a, .profileMenu button{
      display: flex; align-items: center; gap: 12px;
      width: 100%;
      padding: 12px 14px;
      border: none;
      border-radius: 14px;
      background: transparent;
      color: var(--text);
      font-size: 14px;
      text-align: left;
      cursor: pointer;
      text-decoration: none;
      transition: .15s ease;
    }
    .profileMenu a:hover, .profileMenu button:hover{
      background: rgba(255,255,255,.1);
    }
    .profileMenu .ico{ font-size: 18px; opacity: .9; }
    .langItem{display:flex;align-items:center;padding:12px 14px;border-radius:14px;text-decoration:none;color:rgba(255,255,255,.9);font-weight:600;transition:.15s ease;margin-bottom:6px;}
    .langItem:hover{background:rgba(255,255,255,.1)}
    .langItem.active{background: color-mix(in srgb, var(--accent1) 25%, transparent); border:1px solid color-mix(in srgb, var(--accent1) 45%, transparent);}
    .toolbar{
      width:min(980px, 100%);
      margin: 14px auto 0;
      padding: 0 16px;
      display:flex;
      flex-wrap:wrap;
      gap:10px;
      align-items:center;
    }
    .search{
      flex:1 1 240px;
      display:flex;
      align-items:center;
      gap:10px;
      padding: 12px 14px;
      border-radius: 18px;
      border: 1px solid rgba(255,255,255,.14);
      background: rgba(255,255,255,.07);
      backdrop-filter: blur(14px);
      -webkit-backdrop-filter: blur(14px);
      box-shadow: 0 18px 45px rgba(0,0,0,.20);
    }
    .search span{ opacity:.9 }
    .search input{
      width:100%;
      border:none;
      outline:none;
      background: transparent;
      color: var(--text);
      font-size: 14px;
    }
    .search input::placeholder{ color: rgba(255,255,255,.55) }
    .tabs{
      flex:0 0 auto;
      display:flex;
      gap:8px;
      padding: 6px;
      border-radius: 18px;
      border: 1px solid rgba(255,255,255,.12);
      background: rgba(255,255,255,.06);
      backdrop-filter: blur(14px);
      -webkit-backdrop-filter: blur(14px);
    }
    .tab{
      border:none;
      cursor:pointer;
      padding: 10px 12px;
      border-radius: 14px;
      background: transparent;
      color: var(--muted);
      font-weight: 650;
      font-size: 13px;
      transition:.18s ease;
      user-select:none;
      white-space:nowrap;
    }
    .tab.active{
      color: rgba(0,0,0,.85);
      background: var(--accent-gradient);
      box-shadow: 0 12px 26px rgba(0,0,0,.22);
    }

    .content{
      width:min(980px, 100%);
      margin: 16px auto 0;
      padding: 0 16px;
    }
    .section-label{
      margin: 16px 0 10px;
      font-size: 12px;
      letter-spacing:.18em;
      text-transform: uppercase;
      color: rgba(255,255,255,.62);
      padding-left: 2px;
    }
    .list{ display:flex; flex-direction:column; gap:10px; }
    .item{
      display:flex; align-items:center; gap:12px;
      padding: 12px 12px;
      border-radius: 20px;
      border: 1px solid rgba(255,255,255,.14);
      background: var(--card-bg);
      backdrop-filter: blur(14px);
      -webkit-backdrop-filter: blur(14px);
      box-shadow: 0 18px 50px rgba(0,0,0,.22);
      cursor:pointer;
      transition: .18s ease;
      user-select:none;
    }
    .item:hover{ transform: translateY(-1px); background: linear-gradient(180deg, rgba(255,255,255,.12), rgba(255,255,255,.05)); }
    .item:active{ transform: translateY(1px) }
    .avatar{
      width: 44px; height: 44px;
      border-radius: 18px;
      display:grid; place-items:center;
      color: rgba(255,255,255,.95);
      font-weight: 800;
      overflow:hidden;
      flex:0 0 auto;
      border: 1px solid rgba(255,255,255,.14);
      box-shadow: inset 0 0 0 1px rgba(0,0,0,.18);
    }
    .avatar img{ width:100%; height:100%; object-fit:cover }
    .meta{
      min-width:0; flex:1 1 auto;
      display:flex; flex-direction:column; gap:2px;
    }
    .name{
      font-weight: 780;
      letter-spacing:.1px;
      white-space:nowrap; overflow:hidden; text-overflow: ellipsis;
    }
    .mini{
      color: var(--muted);
      font-size: 13px;
      white-space:nowrap; overflow:hidden; text-overflow: ellipsis;
    }
    .phone{
      flex:0 0 auto;
      color: rgba(255,255,255,.80);
      font-weight: 650;
      font-size: 13px;
      padding: 8px 10px;
      border-radius: 14px;
      border: 1px solid rgba(255,255,255,.12);
      background: rgba(0,0,0,.12);
    }
    .badgeStar{ margin-left: 6px; opacity:.9; font-size: 14px; }
    .empty{
      margin-top: 16px;
      padding: 18px;
      border-radius: 22px;
      border: 1px solid rgba(255,255,255,.12);
      background: rgba(255,255,255,.06);
      color: rgba(255,255,255,.75);
      text-align:center;
    }

    .toast{
      width:min(980px, 100%);
      margin: 10px auto 0;
      padding: 0 16px;
    }
    .msg{
      padding: 10px 12px;
      border-radius: 16px;
      border: 1px solid var(--success-border);
      background: var(--success-bg);
      color: rgba(255,255,255,.92);
      font-size: 13px;
    }
    .err{
      padding: 10px 12px;
      border-radius: 16px;
      border: 1px solid rgba(251,113,133,.35);
      background: rgba(251,113,133,.12);
      color: rgba(255,255,255,.92);
      font-size: 13px;
    }

    .overlay{ position:fixed; inset:0; z-index:200; display:none; flex-direction:column; background: rgba(0,0,0,.7); backdrop-filter: blur(18px); -webkit-backdrop-filter: blur(18px); }
    .overlayTop{ position:sticky; top:0; z-index:5; padding:max(14px, env(safe-area-inset-top)) 16px 12px 16px; border-bottom:1px solid rgba(255,255,255,.10); background: rgba(12,18,36,.55); backdrop-filter: blur(16px); -webkit-backdrop-filter: blur(16px); }
    .overlayTopInner{ width:min(980px, 100%); margin:0 auto; display:flex; align-items:center; justify-content:space-between; gap:10px; }
    .overlayBtns{ display:flex; gap:10px; align-items:center; }
    .detail{ width:min(980px, 100%); margin:0 auto; padding:18px 16px 28px; }
    .hero{ margin-top:6px; display:grid; place-items:center; gap:10px; padding:16px 0 10px; }
    .bigAvatar{ width:110px; height:110px; border-radius:36px; display:grid; place-items:center; overflow:hidden; border:1px solid rgba(255,255,255,.18); box-shadow: 0 26px 70px rgba(0,0,0,.35); font-size:42px; font-weight:900; color: rgba(255,255,255,.95); }
    .bigAvatar img{ width:100%; height:100%; object-fit:cover }
    .bigName{ font-size: 26px; font-weight: 900; letter-spacing:.2px; text-align:center; margin:0; }
    .card{ margin-top:14px; border-radius:26px; border:1px solid rgba(255,255,255,.14); background: var(--card-bg); backdrop-filter: blur(16px); -webkit-backdrop-filter: blur(16px); box-shadow: 0 24px 70px rgba(0,0,0,.28); overflow:hidden; }
    .cardHeader{ padding:16px 16px 10px; color: rgba(255,255,255,.75); font-size:12px; letter-spacing:.18em; text-transform: uppercase; }
    .row{ display:flex; gap:12px; align-items:flex-start; padding:14px 16px; border-top:1px solid rgba(255,255,255,.08); }
    .row:first-of-type{ border-top:none; }
    .ico{ width:34px; height:34px; border-radius:14px; display:grid; place-items:center; border:1px solid rgba(255,255,255,.12); background: rgba(0,0,0,.14); flex:0 0 auto; }
    .rowMain{ min-width:0; flex:1 1 auto; }
    .rowLabel{ font-size:12px; color: rgba(255,255,255,.58); margin-bottom:2px; }
    .rowValue{ font-size:14px; color: rgba(255,255,255,.90); white-space:nowrap; overflow:hidden; text-overflow: ellipsis; }
    .quick{ display:flex; gap:10px; padding:14px 16px 16px; border-top:1px solid rgba(255,255,255,.08); }
    .pill{ flex:1 1 0; text-decoration:none; display:flex; align-items:center; justify-content:center; gap:10px; padding:12px 12px; border-radius:18px; border:1px solid rgba(255,255,255,.14); background: rgba(255,255,255,.07); color: rgba(255,255,255,.92); font-weight: 780; transition:.18s ease; }
    .pill:hover{ transform: translateY(-1px); background: rgba(255,255,255,.09) }

    .sheetWrap{ position:fixed; inset:0; z-index:300; display:none; align-items:flex-end; justify-content:center; background: rgba(0,0,0,.48); backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px); padding:16px; }
    .sheet{ width:min(560px, 100%); border-radius:28px; border:1px solid rgba(255,255,255,.16); background: linear-gradient(180deg, rgba(255,255,255,.12), rgba(255,255,255,.06)); backdrop-filter: blur(18px); -webkit-backdrop-filter: blur(18px); box-shadow: var(--shadow); overflow:hidden; transform: translateY(10px); animation: pop .22s ease forwards; }
    @keyframes pop { to { transform: translateY(0); } }
    .handle{ width:54px; height:5px; border-radius:999px; background: rgba(255,255,255,.22); margin:10px auto 0; }
    .sheetTop{ padding:14px 16px 10px; display:flex; align-items:center; justify-content:space-between; gap:10px; border-bottom:1px solid rgba(255,255,255,.10); }
    .sheetTitle{ margin:0; font-size: 16px; font-weight: 850; letter-spacing:.2px; }
    .sheetBody{ padding: 12px 16px 16px; }
    .grid{ display:grid; grid-template-columns: 1fr; gap:10px; }
    .f{ display:flex; flex-direction:column; gap:7px; }
    .f label{ font-size:12px; color: rgba(255,255,255,.60); }
    .f input, .f select{
      width:100%; padding:13px 14px; border-radius:18px; border:1px solid rgba(255,255,255,.14);
      background: var(--input-bg); color: var(--text); outline:none; transition:.18s ease;
    }
    .f input:focus, .f select:focus{ border-color: var(--focus-border); box-shadow: 0 0 0 4px var(--focus-ring); transform: translateY(-1px); }
    .sheetActions{ display:flex; gap:10px; justify-content:flex-end; padding:12px 16px 16px; border-top:1px solid rgba(255,255,255,.10); }
    .btn{ border:none; cursor:pointer; border-radius:18px; padding:12px 14px; font-weight: 850; transition:.18s ease; user-select:none; }
    .btnGhost{ background: rgba(255,255,255,.08); border:1px solid rgba(255,255,255,.14); color: rgba(255,255,255,.85); }
    .btnPrimary{ color: rgba(0,0,0,.85); background: var(--accent-gradient); border:1px solid rgba(255,255,255,.18); box-shadow: 0 18px 40px rgba(0,0,0,.28); }
    .btnDanger{ background: rgba(251,113,133,.14); border:1px solid rgba(251,113,133,.32); color: rgba(255,255,255,.92); }
    .usersToolbar{
      display:flex;
      flex-wrap:wrap;
      gap:8px;
      margin-bottom:10px;
    }
    .usersSearch{
      flex:1 1 200px;
      display:flex;
      align-items:center;
      gap:8px;
      padding:9px 11px;
      border-radius:14px;
      border:1px solid rgba(255,255,255,.14);
      background:rgba(0,0,0,.16);
    }
    .usersSearch span{ opacity:.9; }
    .usersSearch input{
      width:100%;
      border:none;
      outline:none;
      background:transparent;
      color:var(--text);
      font-size:13px;
    }
    .usersSearch input::placeholder{ color:rgba(255,255,255,.55); }
    .usersFilter{
      min-width:140px;
      padding:9px 11px;
      border-radius:14px;
      border:1px solid rgba(255,255,255,.14);
      background:rgba(0,0,0,.16);
      color:var(--text);
      font-size:13px;
      outline:none;
    }
    .userFilterChip{
      display:inline-flex;
      align-items:center;
      gap:6px;
      padding:8px 10px;
      border-radius:14px;
      border:1px solid rgba(255,255,255,.16);
      background:rgba(255,255,255,.06);
      color:var(--muted);
      font-size:12px;
    }
    /* Tooltip hover per icone gestione utenti */
    #usersList [data-tooltip]{
      position: relative;
    }
    #usersList [data-tooltip]:hover::after{
      content: attr(data-tooltip);
      position: absolute;
      bottom: 100%;
      left: 50%;
      transform: translateX(-50%);
      padding: 6px 10px;
      background: rgba(0,0,0,.92);
      color: white;
      font-size: 12px;
      white-space: nowrap;
      border-radius: 8px;
      margin-bottom: 6px;
      z-index: 100;
      pointer-events: none;
      animation: tooltipFade 0.15s ease;
    }
    @keyframes tooltipFade{ from{ opacity:0; transform: translateX(-50%) translateY(4px); } to{ opacity:1; transform: translateX(-50%) translateY(0); } }
    .fab{
      position: fixed;
      bottom: max(24px, env(safe-area-inset-bottom));
      right: max(20px, env(safe-area-inset-right));
      width: min(72px, 18vw);
      height: min(72px, 18vw);
      min-width: 60px;
      min-height: 60px;
      border-radius: 50%;
      border: none;
      background: var(--accent-gradient);
      color: rgba(0,0,0,.88);
      font-size: 32px;
      cursor: pointer;
      display: grid;
      place-items: center;
      box-shadow: 0 12px 40px rgba(0,0,0,.4), 0 0 0 1px rgba(255,255,255,.15);
      transition: .2s ease;
      z-index: 90;
    }
    .fab:hover{
      transform: scale(1.08);
      box-shadow: 0 16px 50px rgba(0,0,0,.45);
    }
    .fab:active{ transform: scale(0.98); }
    .fab.hidden{ opacity: 0; pointer-events: none; transform: scale(0.8); }
    .selectionBar{
      position: fixed;
      bottom: max(24px, env(safe-area-inset-bottom));
      left: 50%;
      transform: translateX(-50%);
      z-index: 95;
      min-width: min(400px, 90vw);
      padding: 14px 18px;
      border-radius: 22px;
      border: 1px solid rgba(255,255,255,.18);
      background: var(--menu-bg);
      backdrop-filter: blur(20px);
      box-shadow: 0 24px 60px rgba(0,0,0,.5);
    }
    .selectionBarInner{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
    }
    .selectionCount{ font-weight: 780; font-size: 15px; color: var(--text); }
    .itemSelect{ width: 24px; height: 24px; flex-shrink: 0; cursor: pointer; accent-color: var(--accent1); }
    .item.selectMode{ cursor: default; }
    .item.selectMode:hover{ transform: none; }
    .item.selectMode .meta{ cursor: pointer; }
    .btnGhost.active{ background: color-mix(in srgb, var(--accent1) 25%, transparent); border-color: color-mix(in srgb, var(--accent1) 45%, transparent); color: var(--text); }

    /* Crop modal */
    #cropModalWrap{
      position:fixed; inset:0; z-index:300; display:none; flex-direction:column;
      background: rgba(0,0,0,.92); backdrop-filter: blur(24px); -webkit-backdrop-filter: blur(24px);
      padding: max(14px, env(safe-area-inset-top)) 16px max(24px, env(safe-area-inset-bottom));
    }
    #cropModalWrap.open{ display:flex; }
    .cropModalHeader{
      display:flex; align-items:center; justify-content:space-between; margin-bottom:16px;
      padding-bottom:12px; border-bottom: 1px solid rgba(255,255,255,.12);
    }
    .cropModalTitle{ font-size:18px; font-weight:780; color: var(--text); }
    .cropModalBody{
      flex:1; min-height:0; display:flex; flex-direction:column; align-items:center; justify-content:center;
    }
    .cropContainer{
      width:100%; max-width:min(90vw, 400px); height:min(70vh, 400px);
      background: #1a1a2e; border-radius: 20px; overflow: hidden;
      border: 1px solid rgba(255,255,255,.14);
    }
    .cropContainer img{ max-width:100%; max-height:100%; display:block; }
    .cropToolbar{
      display:flex; align-items:center; justify-content:center; gap:12px; margin-top:16px;
      flex-wrap:wrap;
    }
    .cropToolbar .iconbtn{ width:44px; height:44px; font-size:20px; }
    .cropToolbar .iconbtn.rotate{ font-size:18px; }
    .cropActions{
      display:flex; gap:12px; margin-top:20px; justify-content:center;
    }
    .cropActions .btn{ min-width:120px; }

    .themeGrid{ display:grid; grid-template-columns: repeat(auto-fill, minmax(120px, 1fr)); gap:12px; }
    .themeItem{ display:flex; flex-direction:column; align-items:center; gap:8px; padding:12px; border-radius:18px; border:2px solid rgba(255,255,255,.14); background: rgba(0,0,0,.12); color: var(--text); cursor:pointer; transition:.18s ease; }
    .themeItem:hover{ border-color: rgba(255,255,255,.25); background: rgba(255,255,255,.06); transform: translateY(-2px); }
    .themeItem.active{ border-color: var(--accent1); background: color-mix(in srgb, var(--accent1) 15%, transparent); box-shadow: 0 0 0 1px var(--accent1); }
    .themePreview{ width:48px; height:48px; border-radius:14px; display:block; }
    .theme-default{ background: linear-gradient(135deg, rgba(125,211,252,.9), rgba(167,139,250,.85)); }
    .theme-ocean{ background: linear-gradient(135deg, rgba(6,182,212,.9), rgba(14,165,233,.85)); }
    .theme-sunset{ background: linear-gradient(135deg, rgba(251,146,60,.9), rgba(244,63,94,.85)); }
    .theme-forest{ background: linear-gradient(135deg, rgba(34,197,94,.9), rgba(22,163,74,.85)); }
    .theme-midnight{ background: linear-gradient(135deg, rgba(99,102,241,.9), rgba(129,140,248,.85)); }
    .theme-rose{ background: linear-gradient(135deg, rgba(244,114,182,.9), rgba(236,72,153,.85)); }
    .theme-amber{ background: linear-gradient(135deg, rgba(245,158,11,.9), rgba(217,119,6,.85)); }
    .themeLabel{ font-size:12px; font-weight:650; text-align:center; }

    /* Chat FAB + popup */
    .fabStack{ position:fixed; bottom:max(24px, env(safe-area-inset-bottom)); right:max(20px, env(safe-area-inset-right)); z-index:90; display:flex; flex-direction:column; align-items:center; gap:10px; }
    .fabChat{
      position:relative;
      width:52px; height:52px; min-width:52px; min-height:52px;
      border-radius:50%; border:none; cursor:pointer;
      background:linear-gradient(135deg, rgba(99,102,241,.9), rgba(129,140,248,.85));
      color:#fff; font-size:22px; display:grid; place-items:center;
      box-shadow:0 10px 30px rgba(0,0,0,.35);
      transition:.2s ease;
    }
    .fabChat:hover{ transform:scale(1.08); }
    .fabStack .fab{ position:relative; bottom:auto; right:auto; width:min(72px,18vw); height:min(72px,18vw); min-width:60px; min-height:60px; }
    #chatPopupWrap{
      position:fixed; inset:0; z-index:350; display:none; align-items:center; justify-content:center;
      background:rgba(0,0,0,.6); backdrop-filter:blur(12px); padding:16px;
    }
    #chatPopupWrap.open{ display:flex; }
    .chatPopup{
      width:min(480px,100%); max-height:85vh; border-radius:24px;
      border:1px solid rgba(255,255,255,.18); background:linear-gradient(180deg,rgba(255,255,255,.14),rgba(255,255,255,.06));
      backdrop-filter:blur(20px); box-shadow:0 24px 60px rgba(0,0,0,.5); overflow:hidden; display:flex; flex-direction:column;
    }
    .chatPopupHeader{ padding:14px 16px; border-bottom:1px solid rgba(255,255,255,.12); display:flex; align-items:center; justify-content:space-between; gap:10px; }
    .chatPopupTitle{ font-size:17px; font-weight:800; margin:0; }
    .chatPopupBody{ flex:1; min-height:0; overflow-y:auto; padding:12px; }
    .chatTabs{ display:flex; gap:8px; margin-bottom:12px; }
    .chatTab{ padding:10px 14px; border-radius:14px; border:none; background:rgba(255,255,255,.08); color:var(--muted); font-weight:650; cursor:pointer; transition:.18s; }
    .chatTab.active{ background:var(--accent-gradient); color:rgba(0,0,0,.88); }
    .chatList{ display:flex; flex-direction:column; gap:8px; }
    .chatItem{ display:flex; align-items:center; gap:12px; padding:12px 14px; border-radius:18px; border:1px solid rgba(255,255,255,.12); background:rgba(255,255,255,.06); cursor:pointer; transition:.18s; }
    .chatItem:hover{ background:rgba(255,255,255,.1); transform:translateY(-1px); }
    .chatItemAvatar{ width:44px; height:44px; border-radius:50%; background:var(--accent-gradient); display:grid; place-items:center; font-size:18px; font-weight:800; flex:0 0 auto; overflow:hidden; }
    .chatItemAvatar img{ width:100%; height:100%; object-fit:cover; }
    .chatItemName{ position:relative; }
    .chatItemBadge{ display:inline-block; min-width:18px; height:18px; padding:0 5px; margin-left:6px; border-radius:9px; background:#ef4444; color:#fff; font-size:11px; font-weight:700; line-height:18px; text-align:center; vertical-align:middle; }
    .fabChatBadge{ position:absolute; top:-4px; right:-4px; min-width:18px; height:18px; padding:0 4px; border-radius:9px; background:#ef4444; color:#fff; font-size:11px; font-weight:700; line-height:18px; text-align:center; }
    .chatItemMeta{ min-width:0; flex:1; }
    .chatItemName{ font-weight:780; font-size:15px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
    .chatItemLast{ font-size:12px; color:var(--muted); white-space:nowrap; overflow:hidden; text-overflow:ellipsis; margin-top:2px; }
    .chatEmpty{ padding:24px; text-align:center; color:var(--muted); font-size:14px; }
    .chatTtlNotice{ padding:10px 14px; border-radius:14px; background:rgba(245,158,11,.15); border:1px solid rgba(245,158,11,.35); color:rgba(255,255,255,.9); font-size:12px; margin-bottom:12px; }
    #chatRoomWrap{ display:none; flex-direction:column; height:100%; min-height:400px; }
    #chatRoomWrap.open{ display:flex; }
    .chatRoomHeader{ padding:12px 16px; border-bottom:1px solid rgba(255,255,255,.12); display:flex; align-items:center; gap:12px; }
    .chatRoomBack{ width:40px; height:40px; border-radius:14px; border:1px solid rgba(255,255,255,.14); background:rgba(255,255,255,.08); color:var(--text); cursor:pointer; display:grid; place-items:center; font-size:18px; }
    .chatRoomTitle{ font-weight:800; font-size:16px; flex:1; }
    .chatRoomHeaderActions{ position:relative; display:flex; align-items:center; }
    .chatGroupMenu{ position:absolute; top:100%; right:0; margin-top:6px; padding:8px; border-radius:14px; background:var(--card-bg); border:1px solid rgba(255,255,255,.14); box-shadow:0 12px 30px rgba(0,0,0,.3); z-index:10; }
    .chatGroupMenu button{ display:block; width:100%; padding:10px 14px; border:none; border-radius:10px; background:transparent; color:var(--text); cursor:pointer; text-align:left; font-size:14px; }
    .chatGroupMenu button:hover{ background:rgba(255,255,255,.1); }
    .chatMessages{ flex:1; overflow-y:auto; padding:16px; display:flex; flex-direction:column; gap:10px; min-height:200px; }
    .chatMsg{ max-width:85%; padding:12px 14px; border-radius:18px; font-size:14px; line-height:1.4; }
    .chatMsg.mine{ align-self:flex-end; background:var(--accent-gradient); color:rgba(0,0,0,.88); }
    .chatMsg.other{ align-self:flex-start; background:rgba(255,255,255,.12); border:1px solid rgba(255,255,255,.14); }
    .chatMsgMeta{ font-size:11px; color:rgba(255,255,255,.6); margin-top:4px; }
    .chatMsgAudio{ display:flex; align-items:center; gap:10px; margin-top:6px; }
    .chatMsgAudio audio{ max-width:200px; height:36px; }
    .chatInputRow{ padding:12px 16px; border-top:1px solid rgba(255,255,255,.12); display:flex; gap:10px; align-items:flex-end; }
    .chatInputRow input{ flex:1; padding:12px 14px; border-radius:18px; border:1px solid rgba(255,255,255,.14); background:rgba(0,0,0,.14); color:var(--text); font-size:14px; outline:none; }
    .chatInputRow .btnMic{ width:48px; height:48px; border-radius:50%; border:none; background:var(--accent-gradient); color:rgba(0,0,0,.88); cursor:pointer; font-size:22px; display:grid; place-items:center; transition:.2s; }
    .chatInputRow .btnMic.recording{ animation:pulse 1s infinite; }
    @keyframes pulse{ 0%,100%{ opacity:1; transform:scale(1); } 50%{ opacity:.85; transform:scale(1.05); } }
    .voiceSpectrum{ display:flex; align-items:center; justify-content:center; gap:4px; height:40px; padding:8px 16px; }
    .voiceSpectrum span{ width:4px; min-height:8px; background:var(--accent1); border-radius:2px; animation:spectrum 0.5s ease-in-out infinite alternate; }
    .voiceSpectrum span:nth-child(1){ animation-delay:0s; }
    .voiceSpectrum span:nth-child(2){ animation-delay:.05s; }
    .voiceSpectrum span:nth-child(3){ animation-delay:.1s; }
    .voiceSpectrum span:nth-child(4){ animation-delay:.15s; }
    .voiceSpectrum span:nth-child(5){ animation-delay:.2s; }
    .voiceSpectrum span:nth-child(6){ animation-delay:.25s; }
    .voiceSpectrum span:nth-child(7){ animation-delay:.3s; }
    .voiceSpectrum span:nth-child(8){ animation-delay:.35s; }
    .voiceSpectrum span:nth-child(9){ animation-delay:.4s; }
    .voiceSpectrum span:nth-child(10){ animation-delay:.45s; }
    @keyframes spectrum{ from{ height:8px; } to{ height:32px; } }
    .chatNewContact{ padding:12px; border-radius:18px; border:1px dashed rgba(255,255,255,.3); background:rgba(255,255,255,.05); margin-bottom:12px; }
    .chatNewContact input{ width:100%; padding:10px 12px; border-radius:14px; border:1px solid rgba(255,255,255,.14); background:rgba(0,0,0,.14); color:var(--text); font-size:14px; margin-bottom:8px; }
    .chatNewContact .userSearchResult{ padding:10px 12px; border-radius:14px; background:rgba(255,255,255,.08); margin:4px 0; cursor:pointer; display:flex; align-items:center; gap:10px; }
    .chatNewContact .userSearchResult:hover{ background:rgba(255,255,255,.12); }
    .userSearchAvatar{ width:32px; height:32px; border-radius:50%; background:var(--accent-gradient); display:grid; place-items:center; font-size:14px; font-weight:700; flex:0 0 auto; overflow:hidden; }
    .userSearchAvatar img{ width:100%; height:100%; object-fit:cover; }
    .chatCreateGroup{ margin-top:12px; }
    .adminChatsList{ max-height:400px; overflow-y:auto; }
    .adminChatItem{ padding:14px; border-radius:18px; border:1px solid rgba(255,255,255,.12); margin-bottom:10px; background:rgba(255,255,255,.06); }
    .adminChatItem .interlocutors{ font-weight:780; font-size:15px; margin-bottom:6px; }
    .adminChatItem .msgPreview{ font-size:13px; color:var(--muted); max-height:80px; overflow-y:auto; }
  </style>
  <script>
  (function(){var t=localStorage.getItem("app_theme")||"default";document.documentElement.setAttribute("data-theme",t);})();
  </script>
</head>
<body>

  <div class="topbar">
    <div class="topbar-inner">
      <div class="title">
        <div class="appdot"></div>
        <div style="min-width:0">
          <h1><?= t('page_contacts') ?></h1>
          <div class="subtitle">
            <?php if ($view_user_id && $view_user_info): ?>
              <?= t('viewing_contacts_of') ?> <strong><?= h($view_user_info['username']) ?></strong>
              <a href="app.php" style="margin-left:8px;color:var(--accent1);"><?= t('back_to_my_contacts') ?></a>
            <?php else: ?>
              <?= h($user['username']) ?><?php if (is_admin($user)): ?> (<?= h($user['role']) ?>)<?php endif; ?> · <?= count($contacts) ?> <?= t('contacts_subtitle') ?>
              · <?= t('contacts_yours_only') ?>
            <?php endif; ?>
          </div>
        </div>
      </div>

      <div class="actions">
        <div class="profileDropdown">
          <button type="button" class="profileBtn" onclick="toggleProfileMenu()" aria-label="Menu profilo" aria-expanded="false" aria-haspopup="true" id="profileBtn"><?php if (!empty($user['avatar'])): ?><img src="<?= h($user['avatar']) ?>" alt="" class="profileBtnImg"><?php else: ?>👤<?php endif; ?></button>
          <div class="profileMenu" id="profileMenu" role="menu">
            <button type="button" role="menuitem" onclick="closeProfileMenu(); openAvatarSheet();">
              <span class="ico">📷</span><?= t('label_photo_profile') ?>
            </button>
            <button type="button" role="menuitem" onclick="closeProfileMenu(); openTheme();">
              <span class="ico">🎨</span><?= t('label_change_background') ?>
            </button>
            <button type="button" role="menuitem" onclick="closeProfileMenu(); openLanguage();">
              <span class="ico">🌐</span><?= t('label_language') ?>
            </button>
            <button type="button" role="menuitem" onclick="closeProfileMenu(); openImportSIM();">
              <span class="ico">📲</span><?= t('btn_import_from_sim') ?>
            </button>
            <button type="button" role="menuitem" onclick="closeProfileMenu(); openExport();">
              <span class="ico">📤</span><?= t('btn_export') ?>
            </button>
            <button type="button" role="menuitem" onclick="closeProfileMenu(); openPass();">
              <span class="ico">🔒</span><?= t('btn_change_password') ?>
            </button>
            <?php if (is_admin($user)): ?>
              <button type="button" role="menuitem" onclick="closeProfileMenu(); openUsersAdmin();">
                <span class="ico">👥</span><?= t('btn_users_admin') ?>
              </button>
              <button type="button" role="menuitem" onclick="closeProfileMenu(); openChatPopup(); openAdminChatsTab();">
                <span class="ico">💬</span><?= t('chat_admin_chats') ?>
              </button>
            <?php endif; ?>
            <a href="app.php?logout=1" role="menuitem">
              <span class="ico">🚪</span><?= t('btn_logout') ?>
            </a>
          </div>
        </div>
      </div>
    </div>

    <div class="toolbar">
      <div class="search">
        <span>🔎</span>
        <input id="q" type="search" placeholder="<?= t('search_placeholder') ?>" autocomplete="off" />
      </div>

      <div style="display:flex;align-items:center;gap:10px;flex:0 0 auto;">
        <div class="tabs" role="tablist" aria-label="Filtro contatti">
          <button class="tab active" id="tabAll" onclick="setTab('all')" type="button" data-t="tab_all"><?= t('tab_all') ?></button>
          <button class="tab" id="tabFav" onclick="setTab('fav')" type="button" data-t="tab_favorites"><?= t('tab_favorites') ?></button>
        </div>
        <button class="btn btnGhost" id="btnSelectMode" type="button" onclick="toggleSelectMode()" style="padding:10px 12px;font-size:13px;"><?= t('btn_select_contacts') ?></button>
      </div>
    </div>
  </div>

  <?php if ($toast_msg || $toast_err): ?>
    <div class="toast">
      <?php if ($toast_msg): ?><div class="msg"><?= h($toast_msg) ?></div><?php endif; ?>
      <?php if ($toast_err): ?><div class="err"><?= h($toast_err) ?></div><?php endif; ?>
    </div>
  <?php endif; ?>

  <div class="content">
    <div id="list" class="list"></div>
    <div id="empty" class="empty" style="display:none;">
      <?= t('empty_contacts') ?>
    </div>
  </div>

  <!-- SELECTION BAR (multi-delete) -->
  <div id="selectionBar" class="selectionBar" style="display:none;">
    <div class="selectionBarInner">
      <span id="selectionCount" class="selectionCount">0</span>
      <form id="formDeleteMultiple" method="POST" action="app.php<?= $view_user_id ? '?view_user_id='.$view_user_id : '' ?>" style="display:flex;gap:10px;align-items:center;">
        <input type="hidden" name="azione" value="delete_multiple">
        <input type="hidden" name="csrf" value="<?= h($CSRF) ?>">
        <button type="button" class="btn btnGhost" onclick="toggleSelectMode()"><?= t('btn_cancel_selection') ?></button>
        <button type="submit" class="btn btnDanger" id="btnDeleteSelected"><?= t('btn_delete_selected') ?></button>
      </form>
    </div>
  </div>

  <!-- DETAIL OVERLAY -->
  <div id="viewOverlay" class="overlay" aria-hidden="true">
    <div class="overlayTop">
      <div class="overlayTopInner">
        <button class="iconbtn" onclick="closeView()" aria-label="<?= t('btn_back') ?>">←</button>
        <div class="overlayBtns">
          <button class="iconbtn" id="btnEdit" aria-label="<?= t('btn_edit') ?>" title="<?= t('btn_edit') ?>">✎</button>
          <button class="iconbtn" id="btnStar" aria-label="<?= t('btn_favorite') ?>" title="<?= t('btn_favorite') ?>">☆</button>
          <button class="iconbtn" id="btnDelete" aria-label="<?= t('btn_delete') ?>" title="<?= t('btn_delete') ?>">🗑️</button>
          <button class="iconbtn" onclick="closeView()" aria-label="<?= t('btn_close') ?>" title="<?= t('btn_close') ?>">✕</button>
        </div>
      </div>
    </div>

    <div class="detail">
      <div class="hero">
        <div id="v_avatar" class="bigAvatar"></div>
        <p id="v_nome" class="bigName"></p>
      </div>

      <div class="card">
        <div class="cardHeader"><?= t('details_contact') ?></div>

        <div class="row">
          <div class="ico">📞</div>
          <div class="rowMain">
            <div class="rowLabel"><?= t('label_phone') ?></div>
            <div id="v_tel" class="rowValue"></div>
          </div>
        </div>

        <div class="row">
          <div class="ico">📧</div>
          <div class="rowMain">
            <div class="rowLabel"><?= t('label_email') ?></div>
            <div id="v_email" class="rowValue"></div>
          </div>
        </div>

        <div class="quick">
          <a id="callBtn" class="pill" href="#" onclick="return false;">📞 <?= t('btn_call') ?></a>
          <a id="mailBtn" class="pill" href="#" onclick="return false;">✉️ <?= t('btn_email') ?></a>
        </div>
      </div>
    </div>
  </div>

  <!-- EDIT SHEET -->
  <div id="editSheetWrap" class="sheetWrap" onclick="sheetBackdropClose(event)">
    <div class="sheet" role="dialog" aria-modal="true" aria-label="Modifica contatto">
      <div class="handle"></div>
      <div class="sheetTop">
        <div>
          <p id="etitle" class="sheetTitle"><?= t('sheet_create_contact') ?></p>
          <div style="color:rgba(255,255,255,.55); font-size:12px; margin-top:4px;">
            <?= t('sheet_save_info') ?><?= ($view_user_id && $view_user_info) ? h($view_user_info['username']) : t('sheet_your_contacts') ?>
          </div>
        </div>
        <button class="iconbtn" onclick="closeEdit()" aria-label="<?= t('btn_close') ?>">✕</button>
      </div>

      <form action="app.php<?= $view_user_id ? '?view_user_id='.$view_user_id : '' ?>" method="POST" enctype="multipart/form-data">
        <div class="sheetBody">
          <input type="hidden" name="azione" value="salva">
          <input type="hidden" name="csrf" value="<?= h($CSRF) ?>">
          <input type="hidden" name="id" id="e_id">
          <input type="hidden" name="old_avatar" id="e_old_avatar">
          <input type="hidden" name="preferito" id="e_preferito">

          <div class="grid">
            <div class="f">
              <label for="e_nome"><?= t('label_name') ?> *</label>
              <input type="text" name="nome" id="e_nome" placeholder="<?= t('placeholder_name') ?>" autocomplete="given-name" required>
            </div>
            <div class="f">
              <label for="e_cognome"><?= t('label_surname') ?></label>
              <input type="text" name="cognome" id="e_cognome" placeholder="<?= t('placeholder_surname') ?>" autocomplete="family-name">
            </div>
            <div class="f">
              <label for="e_tel"><?= t('label_phone') ?> *</label>
              <input type="tel" name="telefono" id="e_tel" placeholder="<?= t('placeholder_phone') ?>" autocomplete="tel" required>
            </div>
            <div class="f">
              <label for="e_email"><?= t('label_email') ?></label>
              <input type="email" name="email" id="e_email" placeholder="<?= t('placeholder_email') ?>" autocomplete="email">
            </div>
            <div class="f">
              <label for="e_avatar"><?= t('label_avatar') ?></label>
              <input id="e_avatar" type="file" name="avatar" accept="image/*">
            </div>
          </div>
        </div>

        <div class="sheetActions">
          <button type="button" class="btn btnGhost" onclick="closeEdit()"><?= t('btn_cancel') ?></button>
          <button type="submit" class="btn btnPrimary"><?= t('btn_save') ?></button>
        </div>
      </form>
    </div>
  </div>

  <!-- CROP AVATAR MODAL -->
  <div id="cropModalWrap" class="cropModalWrap" role="dialog" aria-modal="true" aria-label="<?= t('crop_title') ?>" onclick="if(event.target===this)closeCropModal()">
    <div class="cropModalHeader">
      <span class="cropModalTitle"><?= t('crop_title') ?></span>
      <button type="button" class="iconbtn" onclick="closeCropModal()" aria-label="<?= t('btn_close') ?>">✕</button>
    </div>
    <div class="cropModalBody">
      <div class="cropContainer">
        <img id="cropImage" src="" alt="">
      </div>
      <div class="cropToolbar">
        <button type="button" class="iconbtn" onclick="cropZoomOut()" title="<?= t('crop_zoom_out') ?>" aria-label="<?= t('crop_zoom_out') ?>">−</button>
        <button type="button" class="iconbtn" onclick="cropZoomIn()" title="<?= t('crop_zoom_in') ?>" aria-label="<?= t('crop_zoom_in') ?>">+</button>
        <button type="button" class="iconbtn rotate" onclick="cropRotateLeft()" title="<?= t('crop_rotate_left') ?>" aria-label="<?= t('crop_rotate_left') ?>">↺</button>
        <button type="button" class="iconbtn rotate" onclick="cropRotateRight()" title="<?= t('crop_rotate_right') ?>" aria-label="<?= t('crop_rotate_right') ?>">↻</button>
      </div>
      <div class="cropActions">
        <button type="button" class="btn btnGhost" onclick="closeCropModal()"><?= t('btn_cancel') ?></button>
        <button type="button" class="btn btnPrimary" onclick="cropSave()"><?= t('btn_crop_save') ?></button>
      </div>
    </div>
  </div>

  <!-- CHANGE PASSWORD SHEET -->
  <div id="passSheetWrap" class="sheetWrap" onclick="passBackdropClose(event)">
    <div class="sheet" role="dialog" aria-modal="true" aria-label="Cambia password">
      <div class="handle"></div>
      <div class="sheetTop">
        <div>
          <p class="sheetTitle"><?= t('sheet_change_password') ?></p>
          <div style="color:rgba(255,255,255,.55); font-size:12px; margin-top:4px;">
            <?= t('label_user') ?>: <b><?= h($user['username']) ?></b>
          </div>
        </div>
        <button class="iconbtn" onclick="closePass()" aria-label="Chiudi">✕</button>
      </div>

      <form action="app.php" method="POST" autocomplete="off">
        <div class="sheetBody">
          <input type="hidden" name="azione" value="change_pass">
          <input type="hidden" name="csrf" value="<?= h($CSRF) ?>">
          <input type="text" name="username" value="" autocomplete="username" tabindex="-1" aria-hidden="true" style="position:absolute;left:-9999px;width:1px;height:1px;opacity:0;" />

          <div class="grid">
            <div class="f">
              <label for="old_pass"><?= t('label_current_password') ?></label>
              <input id="old_pass" type="password" name="old_pass" autocomplete="current-password" required>
            </div>

            <div class="f">
              <label for="new_pass"><?= t('label_new_password') ?></label>
              <input id="new_pass" type="password" name="new_pass" autocomplete="new-password" required>
            </div>

            <div class="f">
              <label for="new_pass2"><?= t('label_repeat_new_password') ?></label>
              <input id="new_pass2" type="password" name="new_pass2" autocomplete="new-password" required>
            </div>
          </div>
        </div>

        <div class="sheetActions">
          <button type="button" class="btn btnGhost" onclick="closePass()"><?= t('btn_cancel') ?></button>
          <button type="submit" class="btn btnPrimary"><?= t('btn_update') ?></button>
        </div>
      </form>
    </div>
  </div>

  <!-- FOTO PROFILO SHEET -->
  <div id="avatarSheetWrap" class="sheetWrap" onclick="avatarSheetBackdropClose(event)">
    <div class="sheet" role="dialog" aria-modal="true" aria-label="<?= t('label_photo_profile') ?>">
      <div class="handle"></div>
      <div class="sheetTop">
        <p class="sheetTitle"><?= t('label_photo_profile') ?></p>
        <button class="iconbtn" onclick="closeAvatarSheet()" aria-label="<?= t('btn_close') ?>">✕</button>
      </div>
      <div class="sheetBody">
        <form id="avatarForm" onsubmit="return uploadAvatar(event)">
          <div class="f">
            <label><?= t('label_avatar') ?></label>
            <input type="file" id="avatarFile" name="avatar" accept="image/jpeg,image/png,image/webp,image/gif" required>
          </div>
          <div class="sheetActions" style="margin-top:14px;">
            <button type="button" class="btn btnGhost" onclick="closeAvatarSheet()"><?= t('btn_cancel') ?></button>
            <button type="submit" class="btn btnPrimary"><?= t('btn_save') ?></button>
          </div>
        </form>
      </div>
    </div>
  </div>

  <!-- THEME / CAMBIA SFONDO SHEET -->
  <div id="themeSheetWrap" class="sheetWrap" onclick="themeSheetBackdropClose(event)">
    <div class="sheet" role="dialog" aria-modal="true" aria-label="<?= t('sheet_change_background') ?>">
      <div class="handle"></div>
      <div class="sheetTop">
        <p class="sheetTitle"><?= t('sheet_change_background') ?></p>
        <button class="iconbtn" onclick="closeTheme()" aria-label="<?= t('btn_close') ?>">✕</button>
      </div>
      <div class="sheetBody">
        <div class="themeGrid" id="themeGrid">
          <button type="button" class="themeItem" data-theme="default" onclick="applyTheme('default')">
            <span class="themePreview theme-default"></span>
            <span class="themeLabel"><?= t('theme_default') ?></span>
          </button>
          <button type="button" class="themeItem" data-theme="ocean" onclick="applyTheme('ocean')">
            <span class="themePreview theme-ocean"></span>
            <span class="themeLabel"><?= t('theme_ocean') ?></span>
          </button>
          <button type="button" class="themeItem" data-theme="sunset" onclick="applyTheme('sunset')">
            <span class="themePreview theme-sunset"></span>
            <span class="themeLabel"><?= t('theme_sunset') ?></span>
          </button>
          <button type="button" class="themeItem" data-theme="forest" onclick="applyTheme('forest')">
            <span class="themePreview theme-forest"></span>
            <span class="themeLabel"><?= t('theme_forest') ?></span>
          </button>
          <button type="button" class="themeItem" data-theme="midnight" onclick="applyTheme('midnight')">
            <span class="themePreview theme-midnight"></span>
            <span class="themeLabel"><?= t('theme_midnight') ?></span>
          </button>
          <button type="button" class="themeItem" data-theme="rose" onclick="applyTheme('rose')">
            <span class="themePreview theme-rose"></span>
            <span class="themeLabel"><?= t('theme_rose') ?></span>
          </button>
          <button type="button" class="themeItem" data-theme="amber" onclick="applyTheme('amber')">
            <span class="themePreview theme-amber"></span>
            <span class="themeLabel"><?= t('theme_amber') ?></span>
          </button>
        </div>
      </div>
    </div>
  </div>

  <!-- LINGUA SHEET -->
  <div id="langSheetWrap" class="sheetWrap" onclick="langSheetBackdropClose(event)">
    <div class="sheet" role="dialog" aria-modal="true" aria-label="<?= t('sheet_language') ?>">
      <div class="handle"></div>
      <div class="sheetTop">
        <p class="sheetTitle"><?= t('sheet_language') ?></p>
        <button class="iconbtn" onclick="closeLanguage()" aria-label="<?= t('btn_close') ?>">✕</button>
      </div>
      <div class="sheetBody">
        <?php foreach ($AVAILABLE_LANGS as $code => $label): ?>
          <a href="app.php?lang=<?= $code ?><?= $view_user_id ? '&view_user_id='.$view_user_id : '' ?>" class="langItem <?= $code === $CURRENT_LANG ? 'active' : '' ?>" hreflang="<?= $code ?>"><?= h($label) ?></a>
        <?php endforeach; ?>
      </div>
    </div>
  </div>

  <!-- IMPORT DA SIM SHEET -->
  <div id="importSIMSheetWrap" class="sheetWrap" onclick="importSIMBackdropClose(event)">
    <div class="sheet" role="dialog" aria-modal="true" aria-label="<?= t('sheet_import_sim') ?>">
      <div class="handle"></div>
      <div class="sheetTop">
        <div>
          <p class="sheetTitle"><?= t('sheet_import_sim') ?></p>
          <div style="color:rgba(255,255,255,.55); font-size:12px; margin-top:4px;">
            <?= t('import_sim_formats') ?>
            <ul style="margin:6px 0 0 14px; padding:0;">
              <li><strong>.VCF</strong> (vCard) — <?= t('format_vcf_desc') ?></li>
              <li><strong>.CSV</strong> — <?= t('format_csv_desc') ?></li>
            </ul>
          </div>
        </div>
        <button class="iconbtn" onclick="closeImportSIM()" aria-label="<?= t('btn_close') ?>">✕</button>
      </div>

      <form action="app.php<?= $view_user_id ? '?view_user_id='.$view_user_id : '' ?>" method="POST" enctype="multipart/form-data">
        <div class="sheetBody">
          <input type="hidden" name="azione" value="import_sim">
          <input type="hidden" name="csrf" value="<?= h($CSRF) ?>">

          <div class="f">
            <label for="import_sim_file"><?= t('import_sim_select_file') ?></label>
            <input id="import_sim_file" type="file" name="sim_file" accept=".vcf,.csv,text/vcard,text/csv,text/x-vcard,application/vnd.ms-excel" required>
          </div>
        </div>

        <div class="sheetActions">
          <button type="button" class="btn btnGhost" onclick="closeImportSIM()"><?= t('btn_cancel') ?></button>
          <button type="submit" class="btn btnPrimary"><?= t('btn_import') ?></button>
        </div>
      </form>
    </div>
  </div>

  <!-- EXPORT SHEET -->
  <div id="exportSheetWrap" class="sheetWrap" onclick="exportBackdropClose(event)">
    <div class="sheet" role="dialog" aria-modal="true" aria-label="<?= t('sheet_export') ?>">
      <div class="handle"></div>
      <div class="sheetTop">
        <div>
          <p class="sheetTitle"><?= t('sheet_export') ?></p>
          <div style="color:rgba(255,255,255,.55); font-size:12px; margin-top:4px;">
            <?= t('export_formats_desc') ?>
            <ul style="margin:6px 0 0 14px; padding:0;">
              <li><strong>.VCF</strong> (vCard) — <?= t('format_vcf_desc') ?></li>
              <li><strong>.CSV</strong> — <?= t('format_csv_desc') ?></li>
            </ul>
          </div>
        </div>
        <button class="iconbtn" onclick="closeExport()" aria-label="<?= t('btn_close') ?>">✕</button>
      </div>
      <div class="sheetBody">
        <div class="grid" style="gap:12px;">
          <button type="button" class="btn btnPrimary" style="width:100%;display:flex;align-items:center;justify-content:center;gap:10px;" onclick="downloadExport('vcf')">
            <span>📇</span><?= t('btn_export_vcf') ?>
          </button>
          <button type="button" class="btn btnPrimary" style="width:100%;display:flex;align-items:center;justify-content:center;gap:10px;" onclick="downloadExport('csv')">
            <span>📊</span><?= t('btn_export_csv') ?>
          </button>
        </div>
      </div>
      <div class="sheetActions">
        <button type="button" class="btn btnGhost" onclick="closeExport()"><?= t('btn_cancel') ?></button>
      </div>
    </div>
  </div>

  <!-- USERS ADMIN SHEET -->
  <?php if (is_admin($user)): ?>
  <div id="usersSheetWrap" class="sheetWrap" onclick="usersBackdropClose(event)">
    <div class="sheet" role="dialog" aria-modal="true" aria-label="Gestione utenti">
      <div class="handle"></div>
      <div class="sheetTop">
        <div>
          <p class="sheetTitle"><?= t('sheet_users_admin') ?></p>
          <div style="color:rgba(255,255,255,.55); font-size:12px; margin-top:4px;">
            <?= t('sheet_users_admin_sub') ?>
          </div>
        </div>
        <button class="iconbtn" onclick="closeUsersAdmin()" aria-label="Chiudi">✕</button>
      </div>

      <div class="sheetBody">
        <div class="usersToolbar">
          <div class="usersSearch">
            <span>🔎</span>
            <input id="usersSearch" type="search" placeholder="<?= t('search_users_placeholder') ?>" autocomplete="off" />
          </div>
          <select id="usersFilterRole" class="usersFilter">
            <option value="all"><?= t('filter_all_roles') ?></option>
            <option value="admin"><?= t('filter_admin_only') ?></option>
            <option value="user"><?= t('filter_user_only') ?></option>
          </select>
          <select id="usersFilterActive" class="usersFilter">
            <option value="all"><?= t('filter_active_inactive') ?></option>
            <option value="active"><?= t('filter_active_only') ?></option>
            <option value="inactive"><?= t('filter_inactive_only') ?></option>
          </select>
        </div>

        <div class="card">
          <div class="cardHeader"><?= t('card_all_users') ?></div>
          <div id="usersList" style="padding:10px 10px 14px;"></div>
        </div>
      </div>
    </div>
  </div>

  <!-- Cambia password (admin per altro utente) -->
  <div id="adminPassSheetWrap" class="sheetWrap" style="display:none" onclick="adminPassBackdropClose(event)">
    <div class="sheet" role="dialog" aria-modal="true" aria-label="Cambia password utente">
      <div class="sheetTop">
        <div>
          <p class="sheetTitle">Cambia password</p>
          <div style="color:rgba(255,255,255,.55); font-size:12px; margin-top:4px;" id="adminPassSubtitle"></div>
        </div>
        <button class="iconbtn" onclick="closeAdminPass()" aria-label="Chiudi">✕</button>
      </div>

      <div class="sheetBody">
        <form action="app.php" method="POST" autocomplete="off" class="card" style="margin-top:0; padding:14px 16px 16px;">
          <input type="hidden" name="azione" value="admin_set_password">
          <input type="hidden" name="csrf" value="<?= h($CSRF) ?>">
          <input type="hidden" name="uid" id="adminPassUid" value="">
          <input type="text" name="username" value="" autocomplete="username" tabindex="-1" aria-hidden="true" style="position:absolute;left:-9999px;width:1px;height:1px;opacity:0;" />

          <div class="grid">
            <div class="f">
              <label>Nuova password *</label>
              <input type="password" name="new_pass" id="adminNewPass" required minlength="6" placeholder="Min 6 caratteri" autocomplete="new-password">
            </div>
            <div class="f">
              <label>Ripeti password *</label>
              <input type="password" name="new_pass2" id="adminNewPass2" required minlength="6" autocomplete="new-password">
            </div>
          </div>

          <div class="sheetActions" style="padding:12px 0 0;border-top:none;">
            <button type="button" class="btn btnGhost" onclick="closeAdminPass()">Annulla</button>
            <button type="submit" class="btn btnPrimary">Salva</button>
          </div>
        </form>
      </div>
    </div>
  </div>
  <?php endif; ?>

  <!-- FAB Stack: Chat icon sopra, + contatto sotto -->
  <div class="fabStack">
    <button type="button" class="fabChat" id="fabChat" onclick="openChatPopup()" aria-label="<?= t('chat_title') ?>" title="<?= t('chat_title') ?>">💬</button>
    <button type="button" class="fab" id="fabAdd" onclick="openEdit(null)" aria-label="<?= t('btn_new_contact') ?>" title="<?= t('btn_new_contact') ?>">➕</button>
  </div>

  <!-- CHAT POPUP -->
  <div id="chatPopupWrap" onclick="if(event.target===this)closeChatPopup()">
    <div class="chatPopup">
      <div class="chatPopupHeader">
        <h2 class="chatPopupTitle"><?= t('chat_title') ?></h2>
        <button type="button" class="iconbtn" onclick="closeChatPopup()" aria-label="<?= t('btn_close') ?>">✕</button>
      </div>
      <div class="chatPopupBody">
        <div class="chatTtlNotice"><?= t('chat_temporary_notice') ?></div>
        <div class="chatTabs">
          <button type="button" class="chatTab active" data-tab="list" onclick="setChatTab('list')"><?= t('chat_tab_list') ?></button>
          <button type="button" class="chatTab" data-tab="new" onclick="setChatTab('new')"><?= t('chat_tab_new') ?></button>
          <button type="button" class="chatTab" data-tab="group" onclick="setChatTab('group')"><?= t('chat_tab_group') ?></button>
          <?php if (is_admin($user)): ?>
          <button type="button" class="chatTab" data-tab="admin" onclick="setChatTab('admin')"><?= t('chat_admin_chats') ?></button>
          <?php endif; ?>
        </div>

        <div id="chatListPanel" class="chatListPanel">
          <div id="chatList" class="chatList"></div>
          <div id="chatListEmpty" class="chatEmpty" style="display:none;"><?= t('chat_empty') ?></div>
        </div>

        <div id="chatNewPanel" style="display:none;">
          <div class="chatNewContact">
            <input type="search" id="chatUserSearch" placeholder="<?= t('chat_search_users') ?>" autocomplete="off">
            <div id="chatUserResults"></div>
          </div>
        </div>

        <div id="chatGroupPanel" style="display:none;">
          <div class="chatNewContact chatCreateGroup">
            <input type="text" id="chatGroupName" placeholder="<?= t('chat_group_name') ?>">
            <div class="f" style="margin-top:10px;">
              <label><?= t('chat_group_photo') ?> (opzionale)</label>
              <input type="file" id="chatGroupPhoto" accept="image/jpeg,image/png,image/webp,image/gif">
            </div>
            <input type="search" id="chatGroupUserSearch" placeholder="<?= t('chat_search_users') ?>" autocomplete="off" style="margin-top:10px;">
            <div id="chatGroupUserResults"></div>
            <div id="chatGroupMembers" style="margin-top:10px;"></div>
            <button type="button" class="btn btnPrimary" id="btnCreateGroup" style="margin-top:10px;"><?= t('chat_create_group') ?></button>
          </div>
        </div>

        <div id="chatAdminPanel" style="display:none;">
          <div class="chatTtlNotice"><?= t('chat_temporary_notice') ?></div>
          <div id="adminChatsList" class="adminChatsList"></div>
        </div>

        <div id="chatRoomWrap">
          <div class="chatRoomHeader">
            <button type="button" class="chatRoomBack" onclick="chatRoomBack()">←</button>
            <span class="chatRoomTitle" id="chatRoomTitle"></span>
            <div class="chatRoomHeaderActions" id="chatRoomHeaderActions">
              <button type="button" class="iconbtn" onclick="exportChatHtml()" title="<?= t('chat_export_html') ?>">📥</button>
              <div id="chatGroupAdminActions" style="display:none;">
                <button type="button" class="iconbtn" id="chatGroupMenuBtn" onclick="toggleChatGroupMenu()" title="<?= t('chat_transfer_admin') ?>">⋮</button>
                <div id="chatGroupMenu" class="chatGroupMenu" style="display:none;">
                  <button type="button" onclick="openTransferAdminModal()"><?= t('chat_transfer_admin') ?></button>
                </div>
              </div>
            </div>
          </div>
          <div class="chatMessages" id="chatMessages"></div>
          <div class="chatInputRow">
            <input type="text" id="chatMsgInput" placeholder="<?= t('chat_type_message') ?>" onkeydown="if(event.key==='Enter')sendChatMsg()">
            <div id="chatVoiceRec" style="display:none;" class="voiceSpectrum">
              <span></span><span></span><span></span><span></span><span></span><span></span><span></span><span></span><span></span><span></span>
            </div>
            <button type="button" class="btnMic" id="chatBtnMic" onclick="toggleVoiceRecord()" title="<?= t('chat_voice_msg') ?>">🎤</button>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- MODAL TRASFERIMENTO ADMIN GRUPPO -->
  <div id="transferAdminModal" class="sheetWrap" style="display:none;" onclick="if(event.target===this)closeTransferAdminModal()">
    <div class="sheet" style="max-height:70vh;">
      <div class="sheetTop">
        <p class="sheetTitle"><?= t('chat_transfer_admin') ?></p>
        <button class="iconbtn" onclick="closeTransferAdminModal()">✕</button>
      </div>
      <div class="sheetBody" id="transferAdminMembers"></div>
    </div>
  </div>

<script>
  const ALL_CONTACTS = <?= $contacts_json ?: "[]" ?>;
  const IS_ADMIN = <?= is_admin($user) ? 'true' : 'false' ?>;
  const VIEW_USER_ID = <?= $view_user_id ? (int)$view_user_id : 'null' ?>;
  const MY_UID = <?= (int)$user['id'] ?>;
  const T = <?= json_encode([
    'no_name' => t('no_name'),
    'export_empty' => t('export_empty'),
    'section_favorites' => t('section_favorites'),
    'section_contacts' => t('section_contacts'),
    'sheet_create_contact' => t('sheet_create_contact'),
    'sheet_edit_contact' => t('sheet_edit_contact'),
    'confirm_delete_contact' => t('confirm_delete_contact'),
    'confirm_delete_user' => t('confirm_delete_user'),
    'empty_users' => t('empty_users'),
    'status_active' => t('status_active'),
    'status_inactive' => t('status_inactive'),
    'btn_select_contacts' => t('btn_select_contacts'),
    'btn_cancel_selection' => t('btn_cancel_selection'),
    'btn_delete_selected' => t('btn_delete_selected'),
    'confirm_delete_selected' => t('confirm_delete_selected'),
    'selected_count' => t('selected_count'),
    'chat_empty' => t('chat_empty'),
    'chat_temporary_notice' => t('chat_temporary_notice'),
  ], JSON_UNESCAPED_UNICODE) ?>;
  const CSRF = <?= json_encode($CSRF) ?>;
  const MY_USERNAME = <?= json_encode($user['username']) ?>;

  let currentTab = "all";
  let currentQuery = "";
  let viewing = null;
  let selectionMode = false;
  let selectedIds = new Set();

  const $ = (id) => document.getElementById(id);
  function normalize(s){ return (s||"").toString().toLowerCase().trim(); }

  (function initTheme(){
    const saved = localStorage.getItem("app_theme") || "default";
    document.documentElement.setAttribute("data-theme", saved);
    const grid = $("themeGrid");
    if (grid) {
      grid.querySelectorAll(".themeItem").forEach(el => {
        el.classList.toggle("active", el.getAttribute("data-theme") === saved);
      });
    }
  })();

  function toggleProfileMenu(){
    const m = $("profileMenu");
    const b = $("profileBtn");
    if (!m || !b) return;
    m.classList.toggle("open");
    b.setAttribute("aria-expanded", m.classList.contains("open"));
  }
  function closeProfileMenu(){
    const m = $("profileMenu");
    const b = $("profileBtn");
    if (m) m.classList.remove("open");
    if (b) b.setAttribute("aria-expanded", "false");
  }
  document.addEventListener("click", (e) => {
    if ($("profileMenu")?.classList.contains("open") && !e.target.closest(".profileDropdown")) {
      closeProfileMenu();
    }
  });

  function contactMatches(c, q){
    if (!q) return true;
    const hay = [c.nome, c.cognome, c.telefono, c.email].map(normalize).join(" ");
    return hay.includes(q);
  }

  function baseUrl(){ return VIEW_USER_ID ? "app.php?view_user_id=" + VIEW_USER_ID : "app.php"; }

  // ========== CHAT ==========
  let chatCurrentTab = 'list';
  let chatCurrentRoom = null;
  let chatMediaRecorder = null;
  let chatAudioChunks = [];
  let chatStream = null;
  let chatAnalyser = null;
  let chatGroupMembers = [];
  let chatGroupMemberNames = {};

  function openChatPopup(){
    $("chatPopupWrap").classList.add("open");
    document.body.style.overflow = "hidden";
    setChatTab(chatCurrentTab);
    if (chatCurrentTab === 'list') loadChatList();
    if (chatCurrentTab === 'admin' && IS_ADMIN) loadAdminChats();
  }
  function closeChatPopup(){
    $("chatPopupWrap").classList.remove("open");
    document.body.style.overflow = "";
    if (chatCurrentRoom) chatRoomBack();
  }
  function openAdminChatsTab(){
    chatCurrentTab = 'admin';
    setChatTab('admin');
    loadAdminChats();
  }
  function setChatTab(tab){
    chatCurrentTab = tab;
    document.querySelectorAll(".chatTab").forEach(t => t.classList.toggle("active", t.dataset.tab === tab));
    $("chatListPanel").style.display = (tab === 'list') ? "block" : "none";
    $("chatNewPanel").style.display = (tab === 'new') ? "block" : "none";
    $("chatGroupPanel").style.display = (tab === 'group') ? "block" : "none";
    $("chatAdminPanel").style.display = (tab === 'admin') ? "block" : "none";
    $("chatRoomWrap").classList.remove("open");
    if (tab === 'list') loadChatList();
    if (tab === 'admin' && IS_ADMIN) loadAdminChats();
  }
  async function loadChatList(){
    try {
      const r = await fetch("api_chat.php?action=my_chats");
      const d = await r.json();
      if (!d.ok) return;
      renderChatList(d.chats || []);
    } catch (e) { console.error(e); }
  }
  function renderChatList(chats){
    const list = $("chatList");
    const empty = $("chatListEmpty");
    list.innerHTML = "";
    if (!chats.length) {
      empty.style.display = "block";
      updateChatBadge(0);
      return;
    }
    empty.style.display = "none";
    let unreadTotal = 0;
    const lastRead = JSON.parse(localStorage.getItem("chat_last_read") || "{}");
    chats.forEach(c => {
      const el = document.createElement("div");
      el.className = "chatItem";
      const name = c.type === 'private' ? (c.other_username || '?') : (c.name || c.chat_id);
      const last = c.last_msg ? (c.last_msg.text || '[ vocale ]') : '';
      const lastTs = c.last_msg ? (c.last_msg.ts || 0) : 0;
      const readTs = lastRead[c.chat_id] || 0;
      const t = typeof lastTs === 'number' ? lastTs : (new Date(lastTs)).getTime();
      const r = typeof readTs === 'number' ? readTs : (new Date(readTs)).getTime();
      const unread = t > r && c.last_msg && c.last_msg.uid !== MY_UID;
      if (unread) unreadTotal++;
      let avatarHtml = (name||'?').charAt(0).toUpperCase();
      if (c.type === 'private' && c.other_avatar) {
        avatarHtml = `<img src="${escapeHtml(c.other_avatar)}" alt="">`;
      } else if (c.type === 'group' && c.avatar) {
        avatarHtml = `<img src="${escapeHtml(c.avatar)}" alt="">`;
      }
      const badgeHtml = unread ? `<span class="chatItemBadge">${(c.count || 0)}</span>` : '';
      el.innerHTML = `<div class="chatItemAvatar">${avatarHtml}</div><div class="chatItemMeta"><div class="chatItemName">${escapeHtml(name)}${badgeHtml}</div><div class="chatItemLast">${escapeHtml(last)}</div></div>`;
      el.onclick = () => { markChatRead(c.chat_id, lastTs); openChatRoom(c); };
      list.appendChild(el);
    });
    updateChatBadge(unreadTotal);
  }
  function markChatRead(chatId, ts){
    const lastRead = JSON.parse(localStorage.getItem("chat_last_read") || "{}");
    lastRead[chatId] = ts;
    localStorage.setItem("chat_last_read", JSON.stringify(lastRead));
  }
  function updateChatBadge(n){
    const fab = $("fabChat");
    if (!fab) return;
    let badge = fab.querySelector(".fabChatBadge");
    if (n > 0) {
      if (!badge) { badge = document.createElement("span"); badge.className = "fabChatBadge"; fab.appendChild(badge); }
      badge.textContent = n > 99 ? "99+" : n;
      badge.style.display = "";
    } else if (badge) badge.style.display = "none";
  }
  function escapeHtml(s){ const d=document.createElement("div"); d.textContent=s||""; return d.innerHTML; }
  function openChatRoom(chat){
    chatCurrentRoom = chat;
    if (chat.type === 'group' && chat.admin_id) chatCurrentRoom.admin_id = chat.admin_id;
    if (chat.type === 'group' && chat.members) chatCurrentRoom.members = chat.members;
    $("chatListPanel").style.display = "none";
    $("chatNewPanel").style.display = "none";
    $("chatGroupPanel").style.display = "none";
    $("chatAdminPanel").style.display = "none";
    $("chatRoomWrap").classList.add("open");
    $("chatRoomTitle").textContent = chat.type === 'private' ? (chat.other_username || '?') : (chat.name || chat.chat_id);
    loadChatHistory();
  }
  function chatRoomBack(){
    chatCurrentRoom = null;
    $("chatRoomWrap").classList.remove("open");
    $("chatListPanel").style.display = "block";
    loadChatList();
  }
  async function loadChatHistory(){
    if (!chatCurrentRoom) return;
    try {
      const r = await fetch(`api_chat.php?action=history&type=${chatCurrentRoom.type}&chat_id=${encodeURIComponent(chatCurrentRoom.chat_id)}`);
      const d = await r.json();
      if (!d.ok) return;
      const msgs = d.history.messages || [];
      if (chatCurrentRoom.type === 'group' && d.history.meta) {
        chatCurrentRoom.meta = d.history.meta;
        chatCurrentRoom.members = d.history.meta.members || [];
        chatCurrentRoom.member_names = d.history.meta.member_names || {};
        chatCurrentRoom.admin_id = parseInt(d.history.meta.admin_id || 0);
      }
      renderChatMessages(msgs);
      const last = msgs[msgs.length - 1];
      if (last) markChatRead(chatCurrentRoom.chat_id, last.ts);
      const groupActions = $("chatGroupAdminActions");
      if (groupActions) {
        const isGroupAdmin = chatCurrentRoom.type === 'group' && chatCurrentRoom.admin_id === MY_UID;
        groupActions.style.display = isGroupAdmin ? "block" : "none";
      }
    } catch (e) { console.error(e); }
  }
  function renderChatMessages(msgs){
    const cont = $("chatMessages");
    cont.innerHTML = "";
    msgs.forEach(m => {
      const div = document.createElement("div");
      div.className = "chatMsg " + (m.uid === MY_UID ? "mine" : "other");
      let body = escapeHtml(m.text || '');
      if (m.audio) {
        const url = `api_chat.php?action=audio&type=${chatCurrentRoom.type}&chat_id=${encodeURIComponent(chatCurrentRoom.chat_id)}&file=${encodeURIComponent(m.audio.replace('audio/',''))}`;
        body += `<div class="chatMsgAudio"><audio controls src="${url}"></audio></div>`;
      }
      div.innerHTML = `<div>${body}</div><div class="chatMsgMeta">${escapeHtml(m.username)} · ${formatChatTime(m.ts)}</div>`;
      cont.appendChild(div);
    });
    cont.scrollTop = cont.scrollHeight;
  }
  function formatChatTime(ts){
    if (!ts) return '';
    const t = typeof ts === 'number' ? ts : (new Date(ts)).getTime();
    const d = new Date(t);
    const now = new Date();
    if (d.toDateString() === now.toDateString()) return d.toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'});
    return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'});
  }
  async function sendChatMsg(){
    const input = $("chatMsgInput");
    const text = (input.value || "").trim();
    if (!text || !chatCurrentRoom) return;
    input.value = "";
    try {
      const fd = new FormData();
      fd.append("action", "send");
      fd.append("type", chatCurrentRoom.type);
      fd.append("chat_id", chatCurrentRoom.chat_id);
      fd.append("text", text);
      const r = await fetch("api_chat.php", { method: "POST", body: fd });
      const txt = await r.text();
      if (r.status === 401) { location.href = "login.php"; return; }
      const trimmed = txt.trim();
      if (trimmed.charAt(0) !== '{' && trimmed.charAt(0) !== '[') {
        console.error("API non-JSON:", txt.slice(0, 300));
        return;
      }
      const d = JSON.parse(txt);
      if (d.ok) loadChatHistory();
      else if (d.error && r.status === 401) location.href = "login.php";
    } catch (e) { console.error(e); }
  }
  function toggleVoiceRecord(){
    if (chatMediaRecorder && chatMediaRecorder.state === "recording") {
      chatMediaRecorder.stop();
      return;
    }
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      alert("<?= h(t('chat_voice_unavailable')) ?>");
      return;
    }
    navigator.mediaDevices.getUserMedia({ audio: true }).then(stream => {
      chatStream = stream;
      const ac = new AudioContext();
      const src = ac.createMediaStreamSource(stream);
      chatAnalyser = ac.createAnalyser();
      chatAnalyser.fftSize = 256;
      src.connect(chatAnalyser);
      const chunks = [];
      chatMediaRecorder = new MediaRecorder(stream);
      chatMediaRecorder.ondataavailable = e => { if (e.data.size) chunks.push(e.data); };
      chatMediaRecorder.onstop = async () => {
        stream.getTracks().forEach(t => t.stop());
        const blob = new Blob(chunks, { type: "audio/webm" });
        const fd = new FormData();
        fd.append("action", "send");
        fd.append("type", chatCurrentRoom.type);
        fd.append("chat_id", chatCurrentRoom.chat_id);
        fd.append("text", "[ messaggio vocale ]");
        fd.append("audio", blob, "voice.webm");
        try {
          const r = await fetch("api_chat.php", { method: "POST", body: fd });
          const txt = await r.text();
          if (r.status === 401) { location.href = "login.php"; return; }
          const t = txt.trim();
          if (t.charAt(0) === '{' || t.charAt(0) === '[') {
            const d = JSON.parse(txt);
            if (d.ok) loadChatHistory();
          }
        } catch (e) { console.error(e); }
        $("chatVoiceRec").style.display = "none";
        $("chatBtnMic").classList.remove("recording");
      };
      chatMediaRecorder.start();
      $("chatVoiceRec").style.display = "flex";
      $("chatBtnMic").classList.add("recording");
      updateVoiceSpectrum();
    }).catch(e => alert("Microfono non disponibile: " + e.message));
  }
  function updateVoiceSpectrum(){
    if (!chatAnalyser || !$("chatVoiceRec").style.display || $("chatVoiceRec").style.display === "none") return;
    const data = new Uint8Array(chatAnalyser.frequencyBinCount);
    chatAnalyser.getByteFrequencyData(data);
    const bars = $("chatVoiceRec").querySelectorAll("span");
    for (let i = 0; i < bars.length; i++) {
      const v = data[Math.floor((i / bars.length) * data.length)] || 0;
      bars[i].style.height = (8 + (v / 255) * 24) + "px";
    }
    requestAnimationFrame(updateVoiceSpectrum);
  }
  let chatUserSearchT = null;
  $("chatUserSearch")?.addEventListener("input", function(){
    clearTimeout(chatUserSearchT);
    const q = this.value.trim();
    if (q.length < 2) { $("chatUserResults").innerHTML = ""; return; }
    chatUserSearchT = setTimeout(async () => {
      try {
        const r = await fetch(`api_chat.php?action=search_users&q=${encodeURIComponent(q)}`);
        const d = await r.json();
        if (!d.ok) return;
        const users = (d.users || []).filter(u => u.id != MY_UID);
        let html = "";
        users.forEach(u => {
          const av = u.avatar ? `<img src="${escapeHtml(u.avatar)}" alt="">` : (u.username||'?').charAt(0).toUpperCase();
          html += `<div class="userSearchResult" data-id="${u.id}" data-name="${escapeHtml(u.username)}"><span class="userSearchAvatar">${av}</span>${escapeHtml(u.username)}</div>`;
        });
        $("chatUserResults").innerHTML = html;
        $("chatUserResults").querySelectorAll(".userSearchResult").forEach(el => {
          el.onclick = () => startPrivateChat(parseInt(el.dataset.id), el.dataset.name);
        });
      } catch (e) { console.error(e); }
    }, 300);
  });
  async function startPrivateChat(otherId, otherName){
    try {
      const fd = new FormData();
      fd.append("action", "start_private");
      fd.append("other_user_id", otherId);
      const r = await fetch("api_chat.php", { method: "POST", body: fd });
      const d = await r.json();
      if (!d.ok) { alert(d.error || "Errore"); return; }
      openChatRoom({ chat_id: d.chat_id, type: "private", other_username: otherName });
    } catch (e) { alert(e.message); }
  }
  $("chatGroupUserSearch")?.addEventListener("input", function(){
    clearTimeout(chatUserSearchT);
    const q = this.value.trim();
    if (q.length < 2) { $("chatGroupUserResults").innerHTML = ""; return; }
    chatUserSearchT = setTimeout(async () => {
      try {
        const r = await fetch(`api_chat.php?action=search_users&q=${encodeURIComponent(q)}`);
        const d = await r.json();
        if (!d.ok) return;
        const users = (d.users || []).filter(u => u.id != MY_UID && !chatGroupMembers.includes(u.id));
        let html = "";
        users.forEach(u => {
          const av = u.avatar ? `<img src="${escapeHtml(u.avatar)}" alt="">` : (u.username||'?').charAt(0).toUpperCase();
          html += `<div class="userSearchResult" data-id="${u.id}" data-name="${escapeHtml(u.username)}"><span class="userSearchAvatar">${av}</span>+ ${escapeHtml(u.username)}</div>`;
        });
        $("chatGroupUserResults").innerHTML = html;
        $("chatGroupUserResults").querySelectorAll(".userSearchResult").forEach(el => {
          el.onclick = () => {
            const id = parseInt(el.dataset.id);
            const name = el.dataset.name || ('User '+id);
            if (!chatGroupMembers.includes(id)) {
              chatGroupMembers.push(id);
              chatGroupMemberNames[id] = name;
              renderGroupMembers();
            }
          };
        });
      } catch (e) { console.error(e); }
    }, 300);
  });
  function renderGroupMembers(){
    const cont = $("chatGroupMembers");
    if (!cont) return;
    cont.innerHTML = chatGroupMembers.map(id => {
      const name = chatGroupMemberNames[id] || ('User '+id);
      return `<span style="display:inline-block;padding:6px 10px;margin:4px;border-radius:12px;background:rgba(255,255,255,.1);cursor:pointer;" onclick="chatGroupMembers=chatGroupMembers.filter(x=>x!==${id});renderGroupMembers();">${escapeHtml(name)} ✕</span>`;
    }).join("");
  }
  $("btnCreateGroup")?.addEventListener("click", async function(){
    const name = ($("chatGroupName").value || "Gruppo").trim();
    if (chatGroupMembers.length === 0) { alert("Aggiungi almeno un membro"); return; }
    if (chatGroupMembers.length >= 50) { alert("Max 50 membri"); return; }
    try {
      const fd = new FormData();
      fd.append("action", "create_group");
      fd.append("name", name);
      chatGroupMembers.forEach(m => fd.append("members[]", m));
      const photoInput = $("chatGroupPhoto");
      if (photoInput?.files?.length) fd.append("avatar", photoInput.files[0]);
      const r = await fetch("api_chat.php", { method: "POST", body: fd });
      const d = await r.json();
      if (!d.ok) { alert(d.error || "Errore"); return; }
      chatGroupMembers = [];
      chatGroupMemberNames = {};
      const gn = $("chatGroupName");
      if (gn) gn.value = "";
      if (photoInput) photoInput.value = "";
      setChatTab("list");
      loadChatList();
    } catch (e) { alert(e.message); }
  });
  async function exportChatHtml(){
    if (!chatCurrentRoom) return;
    try {
      const r = await fetch(`api_chat.php?action=history&type=${chatCurrentRoom.type}&chat_id=${encodeURIComponent(chatCurrentRoom.chat_id)}`);
      const d = await r.json();
      if (!d.ok) return;
      const msgs = d.history.messages || [];
      const title = chatCurrentRoom.type === 'private' ? (chatCurrentRoom.other_username || 'Chat') : (chatCurrentRoom.name || 'Gruppo');
      let rows = msgs.map(m => {
        const isMine = m.uid === MY_UID;
        const text = (m.text || '').replace(/</g,'&lt;').replace(/>/g,'&gt;');
        const time = formatChatTime(m.ts);
        return `<tr><td class="${isMine?'mine':'other'}"><strong>${(m.username||'?').replace(/</g,'&lt;')}</strong> · ${time}<br>${text}${m.audio?'<br><em>[ messaggio vocale ]</em>':''}</td></tr>`;
      }).join('');
      const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Chat - ${title.replace(/</g,'&lt;')}</title><style>body{font-family:system-ui;max-width:600px;margin:20px auto;padding:16px;background:#1a1a2e;color:#eee;}table{width:100%;}td{margin:8px 0;padding:12px;border-radius:12px;}td.mine{background:rgba(59,130,246,.3);margin-left:20px;}td.other{background:rgba(100,100,100,.3);margin-right:20px;}small{color:#888;font-size:11px;}p{margin:8px 0 0;font-size:13px;}</style></head><body><h1>Chat - ${title.replace(/</g,'&lt;')}</h1><p><small>Esportata il ${new Date().toLocaleString('it-IT')} · Chat temporanee (7 giorni dall'ultimo messaggio)</small></p><table>${rows}</table></body></html>`;
      const blob = new Blob([html], {type:'text/html;charset=utf-8'});
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = `chat_${chatCurrentRoom.chat_id}_${Date.now()}.html`;
      a.click();
      URL.revokeObjectURL(a.href);
    } catch (e) { console.error(e); }
  }

  function toggleChatGroupMenu(){
    const m = $("chatGroupMenu");
    if (m) m.style.display = m.style.display === "none" ? "block" : "none";
  }
  document.addEventListener("click", function(e){
    const m = $("chatGroupMenu");
    if (m && m.style.display !== "none" && !e.target.closest("#chatGroupAdminActions")) m.style.display = "none";
  });
  function openTransferAdminModal(){
    $("chatGroupMenu").style.display = "none";
    const members = chatCurrentRoom?.members || [];
    const names = chatCurrentRoom?.member_names || {};
    const adminId = chatCurrentRoom?.admin_id || 0;
    const cont = $("transferAdminMembers");
    cont.innerHTML = "";
    members.forEach(uid => {
      if (parseInt(uid) === adminId) return;
      const name = names[uid] || names[parseInt(uid)] || ('User ' + uid);
      const btn = document.createElement("button");
      btn.className = "btn btnGhost";
      btn.style.width = "100%";
      btn.style.marginBottom = "8px";
      btn.textContent = name;
      btn.onclick = async () => {
        try {
          const fd = new FormData();
          fd.append("action", "transfer_admin");
          fd.append("chat_id", chatCurrentRoom.chat_id);
          fd.append("new_admin_id", uid);
          const r = await fetch("api_chat.php", { method: "POST", body: fd });
          const d = await r.json();
          if (d.ok) {
            chatCurrentRoom.admin_id = parseInt(uid);
            closeTransferAdminModal();
            $("chatGroupAdminActions").style.display = "none";
          } else alert(d.error || "Errore");
        } catch (e) { alert(e.message); }
      };
      cont.appendChild(btn);
    });
    if (cont.children.length === 0) cont.innerHTML = "<p style='color:var(--muted)'>Nessun altro membro</p>";
    $("transferAdminModal").style.display = "flex";
  }
  function closeTransferAdminModal(){
    $("transferAdminModal").style.display = "none";
  }

  async function loadAdminChats(){
    if (!IS_ADMIN) return;
    try {
      const r = await fetch("api_chat.php?action=admin_all_chats");
      const text = await r.text();
      let d;
      try {
        d = text ? JSON.parse(text) : {};
      } catch (_) {
        console.error('loadAdminChats: risposta non JSON', text?.slice(0, 200));
        $("adminChatsList").innerHTML = "<p style='color:var(--muted)'>Errore caricamento chat</p>";
        return;
      }
      if (!d.ok) return;
      const cont = $("adminChatsList");
      cont.innerHTML = "";
      (d.chats || []).forEach(c => {
        const el = document.createElement("div");
        el.className = "adminChatItem";
        const interlocutors = c.interlocutors || (c.type === 'private' ? `${c.user1_name} ↔ ${c.user2_name}` : c.member_names?.join(", ")) || c.chat_id;
        let prev = "";
        (c.messages || []).slice(-5).forEach(m => {
          prev += (m.username || '?') + ": " + (m.text || '[vocale]') + "\n";
        });
        el.innerHTML = `<div class="interlocutors">${escapeHtml(interlocutors)}</div><div class="msgPreview">${escapeHtml(prev || 'Nessun messaggio')}</div>`;
        el.style.cursor = "pointer";
        el.onclick = () => {
          const members = c.members || [];
          const names = c.member_names || [];
          const member_names = {};
          members.forEach((id, i) => { member_names[id] = names[i] || ('User '+id); });
          const chat = { chat_id: c.chat_id, type: c.type, name: c.name || interlocutors, other_username: interlocutors, members, admin_id: c.admin_id, member_names };
          openChatRoom(chat);
        };
        cont.appendChild(el);
      });
    } catch (e) { console.error(e); }
  }

  function filteredContacts(){
    return ALL_CONTACTS.filter(c => {
      if (currentTab === "fav" && !c.preferito) return false;
      return contactMatches(c, currentQuery);
    });
  }

  function groupContacts(list){
    const fav = list.filter(c => c.preferito);
    const oth = list.filter(c => !c.preferito);
    return { fav, oth };
  }

  function render(){
    const list = filteredContacts();
    const grouped = groupContacts(list);
    const container = $("list");
    container.innerHTML = "";

    const showEmpty = (list.length === 0);
    $("empty").style.display = showEmpty ? "block" : "none";
    if (showEmpty) return;

    const sections = [];
    if (currentTab === "all") {
      if (grouped.fav.length) sections.push({ label: T.section_favorites, items: grouped.fav });
      if (grouped.oth.length) sections.push({ label: T.section_contacts, items: grouped.oth });
    } else {
      sections.push({ label: T.section_favorites, items: grouped.fav });
    }

    for (const s of sections) {
      const lab = document.createElement("div");
      lab.className = "section-label";
      lab.textContent = s.label;
      container.appendChild(lab);

      for (const c of s.items) {
        const item = document.createElement("div");
        item.className = "item" + (selectionMode ? " selectMode" : "");
        if (selectionMode) {
          item.onclick = (e) => {
            if (e.target.type === "checkbox") return;
            toggleSelectContact(c.id);
          };
        } else {
          item.onclick = () => openView(c);
        }

        if (selectionMode) {
          const cb = document.createElement("input");
          cb.type = "checkbox";
          cb.className = "itemSelect";
          cb.checked = selectedIds.has(c.id);
          cb.onclick = (e) => { e.stopPropagation(); toggleSelectContact(c.id); };
          item.appendChild(cb);
        }

        const av = document.createElement("div");
        av.className = "avatar";
        av.style.background = `linear-gradient(135deg, ${avatarColor(c.id, 0.95)}, ${avatarColor2(c.id, 0.9)})`;

        if (c.avatar) {
          const img = document.createElement("img");
          img.src = c.avatar;
          img.alt = "avatar";
          av.appendChild(img);
        } else {
          av.textContent = (c.nome || "?").charAt(0).toUpperCase();
        }

        const meta = document.createElement("div");
        meta.className = "meta";

        const nm = document.createElement("div");
        nm.className = "name";
        nm.textContent = `${c.nome || ""} ${c.cognome || ""}`.trim() || T.no_name;

        if (c.preferito) {
          const star = document.createElement("span");
          star.className = "badgeStar";
          star.textContent = "★";
          nm.appendChild(star);
        }

        const mini = document.createElement("div");
        mini.className = "mini";
        mini.textContent = (c.email || "—");

        meta.appendChild(nm);
        meta.appendChild(mini);

        const phone = document.createElement("div");
        phone.className = "phone";
        phone.textContent = c.telefono || "";

        item.appendChild(av);
        item.appendChild(meta);
        item.appendChild(phone);

        container.appendChild(item);
      }
    }
  }

  function hexFromId(id){
    let h = 0;
    const s = (id || "").toString();
    for (let i=0;i<s.length;i++) h = ((h<<5)-h) + s.charCodeAt(i), h |= 0;
    const hex = (h >>> 0).toString(16).padStart(8,'0');
    return hex;
  }
  function avatarColor(id, a=1){
    const hex = hexFromId(id);
    const r = parseInt(hex.slice(0,2),16);
    const g = parseInt(hex.slice(2,4),16);
    const b = parseInt(hex.slice(4,6),16);
    return `rgba(${r},${g},${b},${a})`;
  }
  function avatarColor2(id, a=1){
    const hex = hexFromId(id + "_x");
    const r = parseInt(hex.slice(0,2),16);
    const g = parseInt(hex.slice(2,4),16);
    const b = parseInt(hex.slice(4,6),16);
    return `rgba(${r},${g},${b},${a})`;
  }

  function setTab(t){
    currentTab = t;
    $("tabAll").classList.toggle("active", t === "all");
    $("tabFav").classList.toggle("active", t === "fav");
    render();
  }

  function toggleSelectMode(){
    selectionMode = !selectionMode;
    if (!selectionMode) selectedIds.clear();
    $("btnSelectMode").textContent = selectionMode ? T.btn_cancel_selection : T.btn_select_contacts;
    $("btnSelectMode").classList.toggle("active", selectionMode);
    $("selectionBar").style.display = selectionMode ? "block" : "none";
    $("fabAdd")?.classList.toggle("hidden", selectionMode);
    updateSelectionCount();
    render();
  }

  function toggleSelectContact(id){
    if (selectedIds.has(id)) selectedIds.delete(id);
    else selectedIds.add(id);
    updateSelectionCount();
    render();
  }

  function updateSelectionCount(){
    const n = selectedIds.size;
    $("selectionCount").textContent = (T.selected_count || "{n} selezionati").replace("{n}", n);
    $("btnDeleteSelected").disabled = n === 0;
  }

  $("q").addEventListener("input", (e) => {
    currentQuery = normalize(e.target.value);
    render();
  });

  $("formDeleteMultiple")?.addEventListener("submit", (e) => {
    if (selectedIds.size === 0) { e.preventDefault(); return; }
    if (!confirm(T.confirm_delete_selected.replace("{n}", selectedIds.size))) {
      e.preventDefault();
      return;
    }
    const form = e.target;
    form.querySelectorAll("input[name='ids[]']").forEach(el => el.remove());
    for (const id of selectedIds) {
      const inp = document.createElement("input");
      inp.type = "hidden";
      inp.name = "ids[]";
      inp.value = id;
      form.appendChild(inp);
    }
  });

  function openView(c){
    viewing = c;

    $("v_nome").textContent = `${c.nome || ""} ${c.cognome || ""}`.trim() || T.no_name;
    $("v_tel").textContent = c.telefono || "—";
    $("v_email").textContent = c.email || "—";

    const av = $("v_avatar");
    av.style.background = `linear-gradient(135deg, ${avatarColor(c.id, 0.95)}, ${avatarColor2(c.id, 0.9)})`;
    av.innerHTML = c.avatar ? `<img src="${c.avatar}" alt="avatar">` : (c.nome||"?").charAt(0).toUpperCase();

    $("btnEdit").onclick = () => openEdit(c);
    $("btnStar").textContent = c.preferito ? "★" : "☆";
    $("btnStar").onclick = () => window.location.href = baseUrl() + (VIEW_USER_ID ? "&" : "?") + "action=toggle_fav&id=" + encodeURIComponent(c.id);
    $("btnDelete").onclick = () => {
      if (confirm(T.confirm_delete_contact)) {
        window.location.href = baseUrl() + (VIEW_USER_ID ? "&" : "?") + "action=delete&id=" + encodeURIComponent(c.id);
      }
    };

    const tel = (c.telefono||"").replace(/\s+/g,'');
    const email = (c.email||"").trim();

    const callBtn = $("callBtn");
    callBtn.href = tel ? `tel:${tel}` : "#";
    callBtn.style.opacity = tel ? "1" : ".45";
    callBtn.onclick = () => !!tel;

    const mailBtn = $("mailBtn");
    mailBtn.href = email ? `mailto:${email}` : "#";
    mailBtn.style.opacity = email ? "1" : ".45";
    mailBtn.onclick = () => !!email;

    $("viewOverlay").style.display = "flex";
    $("viewOverlay").setAttribute("aria-hidden", "false");
    document.body.style.overflow = "hidden";
    $("fabAdd")?.classList.add("hidden");
  }
  function closeView(){
    $("viewOverlay").style.display = "none";
    $("viewOverlay").setAttribute("aria-hidden", "true");
    document.body.style.overflow = "";
    $("fabAdd")?.classList.remove("hidden");
  }

  // ====== EDIT SHEET ======
  function openEdit(c=null){
    closeView();
    $("fabAdd")?.classList.add("hidden");

    if (c) {
      $("etitle").textContent = T.sheet_edit_contact;
      $("e_id").value = c.id || "";
      $("e_nome").value = c.nome || "";
      $("e_cognome").value = c.cognome || "";
      $("e_tel").value = c.telefono || "";
      $("e_email").value = c.email || "";
      $("e_old_avatar").value = c.avatar || "";
      $("e_preferito").value = c.preferito ? "1" : "0";
    } else {
      $("etitle").textContent = T.sheet_create_contact;
      document.querySelector("#editSheetWrap form").reset();
      $("e_id").value = "";
      $("e_old_avatar").value = "";
      $("e_preferito").value = "0";
    }

    $("editSheetWrap").style.display = "flex";
    document.body.style.overflow = "hidden";
    setTimeout(() => $("e_nome").focus(), 50);
  }

  function closeEdit(){
    $("editSheetWrap").style.display = "none";
    document.body.style.overflow = "";
    $("fabAdd")?.classList.remove("hidden");
    if ($("cropModalWrap")?.classList.contains("open")) closeCropModal();
  }

  function sheetBackdropClose(e){
    if (e.target && e.target.id === "editSheetWrap") closeEdit();
  }

  // ====== CROP AVATAR MODAL ======
  let cropCropper = null;
  let cropObjectUrl = null;
  let cropPendingFile = null;

  function openCropModal(file){
    if (!file || !file.type.startsWith("image/")) return;
    cropPendingFile = file;
    const url = URL.createObjectURL(file);
    cropObjectUrl = url;
    const img = $("cropImage");
    img.src = url;
    $("cropModalWrap").classList.add("open");
    $("cropModalWrap").style.display = "flex";
    document.body.style.overflow = "hidden";
    img.onload = () => {
      if (cropCropper) cropCropper.destroy();
      cropCropper = new Cropper(img, {
        aspectRatio: 1,
        viewMode: 1,
        dragMode: "move",
        autoCropArea: 0.8,
        restore: false,
        guides: true,
        center: true,
        highlight: false,
        cropBoxMovable: true,
        cropBoxResizable: true,
        toggleDragModeOnDblclick: false,
      });
    };
  }

  function closeCropModal(keepFile){
    if (cropCropper) {
      cropCropper.destroy();
      cropCropper = null;
    }
    if (cropObjectUrl) {
      URL.revokeObjectURL(cropObjectUrl);
      cropObjectUrl = null;
    }
    cropPendingFile = null;
    const img = $("cropImage");
    if (img) img.src = "";
    $("cropModalWrap").classList.remove("open");
    $("cropModalWrap").style.display = "none";
    document.body.style.overflow = "";
    if (!keepFile) $("e_avatar").value = "";
  }

  function cropZoomIn(){ cropCropper?.zoom(0.1); }
  function cropZoomOut(){ cropCropper?.zoom(-0.1); }
  function cropRotateLeft(){ cropCropper?.rotate(-90); }
  function cropRotateRight(){ cropCropper?.rotate(90); }

  function cropSave(){
    if (!cropCropper) return;
    const canvas = cropCropper.getCroppedCanvas({ width: 400, height: 400, imageSmoothingEnabled: true, imageSmoothingQuality: "high" });
    canvas.toBlob((blob) => {
      if (!blob) return;
      const ext = (cropPendingFile?.name && /\.(jpe?g|png|webp|gif)$/i.test(cropPendingFile.name))
        ? cropPendingFile.name.replace(/.*\./i, "").toLowerCase() : "jpg";
      const mime = { jpg: "image/jpeg", jpeg: "image/jpeg", png: "image/png", webp: "image/webp", gif: "image/gif" }[ext] || "image/jpeg";
      const file = new File([blob], "avatar." + (ext === "jpg" ? "jpeg" : ext), { type: mime });
      const input = $("e_avatar");
      const dt = new DataTransfer();
      dt.items.add(file);
      input.files = dt.files;
      closeCropModal(true);
    }, "image/jpeg", 0.92);
  }

  $("e_avatar").addEventListener("change", function(){
    const f = this.files?.[0];
    if (f) {
      openCropModal(f);
    }
  });

  // ====== PASS SHEET ======
  function openPass(){
    closeView();
    $("fabAdd")?.classList.add("hidden");
    $("passSheetWrap").style.display = "flex";
    document.body.style.overflow = "hidden";
    setTimeout(() => $("old_pass").focus(), 50);
  }
  function closePass(){
    $("passSheetWrap").style.display = "none";
    document.body.style.overflow = "";
    $("fabAdd")?.classList.remove("hidden");
  }
  function passBackdropClose(e){
    if (e.target && e.target.id === "passSheetWrap") closePass();
  }

  function openAvatarSheet(){
    closeView();
    $("fabAdd")?.classList.add("hidden");
    $("avatarSheetWrap").style.display = "flex";
    document.body.style.overflow = "hidden";
    $("avatarFile").value = "";
  }
  function closeAvatarSheet(){
    $("avatarSheetWrap").style.display = "none";
    document.body.style.overflow = "";
    $("fabAdd")?.classList.remove("hidden");
  }
  function avatarSheetBackdropClose(e){
    if (e.target && e.target.id === "avatarSheetWrap") closeAvatarSheet();
  }
  async function uploadAvatar(e){
    e.preventDefault();
    const input = $("avatarFile");
    if (!input?.files?.length) return false;
    const fd = new FormData();
    fd.append("action", "upload_avatar");
    fd.append("avatar", input.files[0]);
    try {
      const r = await fetch("api_user.php", { method: "POST", body: fd });
      const d = await r.json();
      if (d.ok) {
        const btn = $("profileBtn");
        if (btn) {
          btn.innerHTML = "";
          const img = document.createElement("img");
          img.src = d.avatar;
          img.alt = "";
          img.className = "profileBtnImg";
          btn.appendChild(img);
        }
        closeAvatarSheet();
      } else alert(d.error || "Errore");
    } catch (err) { alert(err.message); }
    return false;
  }

  function openTheme(){
    closeView();
    $("fabAdd")?.classList.add("hidden");
    const wrap = $("themeSheetWrap");
    if (wrap) wrap.style.display = "flex";
    document.body.style.overflow = "hidden";
    const current = document.documentElement.getAttribute("data-theme") || "default";
    $("themeGrid")?.querySelectorAll(".themeItem").forEach(el => {
      el.classList.toggle("active", el.getAttribute("data-theme") === current);
    });
  }
  function closeTheme(){
    $("themeSheetWrap").style.display = "none";
    document.body.style.overflow = "";
    $("fabAdd")?.classList.remove("hidden");
  }
  function themeSheetBackdropClose(e){
    if (e.target && e.target.id === "themeSheetWrap") closeTheme();
  }
  function applyTheme(name){
    document.documentElement.setAttribute("data-theme", name);
    localStorage.setItem("app_theme", name);
    $("themeGrid")?.querySelectorAll(".themeItem").forEach(el => {
      el.classList.toggle("active", el.getAttribute("data-theme") === name);
    });
  }

  function openLanguage(){
    closeView();
    $("fabAdd")?.classList.add("hidden");
    $("langSheetWrap").style.display = "flex";
    document.body.style.overflow = "hidden";
  }
  function closeLanguage(){
    $("langSheetWrap").style.display = "none";
    document.body.style.overflow = "";
    $("fabAdd")?.classList.remove("hidden");
  }
  function langSheetBackdropClose(e){
    if (e.target && e.target.id === "langSheetWrap") closeLanguage();
  }

  function openImportSIM(){
    closeView();
    $("fabAdd")?.classList.add("hidden");
    $("importSIMSheetWrap").style.display = "flex";
    document.body.style.overflow = "hidden";
  }
  function closeImportSIM(){
    $("importSIMSheetWrap").style.display = "none";
    document.body.style.overflow = "";
    $("fabAdd")?.classList.remove("hidden");
    $("import_sim_file").value = "";
  }
  function importSIMBackdropClose(e){
    if (e.target && e.target.id === "importSIMSheetWrap") closeImportSIM();
  }

  function openExport(){
    closeView();
    $("fabAdd")?.classList.add("hidden");
    $("exportSheetWrap").style.display = "flex";
    document.body.style.overflow = "hidden";
  }
  function closeExport(){
    $("exportSheetWrap").style.display = "none";
    document.body.style.overflow = "";
    $("fabAdd")?.classList.remove("hidden");
  }
  function exportBackdropClose(e){
    if (e.target && e.target.id === "exportSheetWrap") closeExport();
  }

  function downloadExport(format){
    const list = filteredContacts();
    if (!list.length) {
      alert(T.export_empty || "Nessun contatto da esportare.");
      return;
    }
    const filename = "contatti_" + new Date().toISOString().slice(0,10) + "." + format;
    if (format === "vcf") {
      let vcf = "";
      for (const c of list) {
        const fn = `${c.nome || ""} ${c.cognome || ""}`.trim() || T.no_name;
        const n = `${c.cognome || ""};${c.nome || ""};;;`;
        vcf += "BEGIN:VCARD\r\nVERSION:3.0\r\n";
        vcf += "N:" + n + "\r\n";
        vcf += "FN:" + fn + "\r\n";
        if (c.telefono) vcf += "TEL;TYPE=CELL:" + c.telefono.replace(/[^\d+]/g, "") + "\r\n";
        if (c.email) vcf += "EMAIL:" + c.email + "\r\n";
        vcf += "END:VCARD\r\n";
      }
      downloadBlob(vcf, filename, "text/vcard");
    } else {
      const BOM = "\uFEFF";
      const header = "First Name,Middle Name,Last Name,Phonetic First Name,Phonetic Middle Name,Phonetic Last Name,Name Prefix,Name Suffix,Nickname,File As,Organization Name,Organization Title,Organization Department,Birthday,Notes,Photo,Labels,Phone 1 - Label,Phone 1 - Value";
      let csv = BOM + header + "\r\n";
      for (const c of list) {
        const firstName = escapeCsv((c.nome || "").trim());
        const middleName = "";
        const lastName = escapeCsv((c.cognome || "").trim());
        const tel = escapeCsv((c.telefono || "").trim());
        csv += firstName + "," + middleName + "," + lastName + ",,,,,,,,,,,,,,,* myContacts,Mobile," + tel + "\r\n";
      }
      downloadBlob(csv, filename, "text/csv;charset=utf-8");
    }
  }
  function escapeCsv(s){
    const str = String(s ?? "");
    if (str.includes(",") || str.includes(";") || str.includes('"') || str.includes("\n") || str.includes("\r")) {
      return '"' + str.replace(/"/g, '""') + '"';
    }
    return str;
  }
  function downloadBlob(content, filename, mime){
    const blob = new Blob([content], { type: mime });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  // ====== USERS ADMIN ======
  <?php if (is_admin($user)): ?>
    const ALL_USERS = <?= $users_json ?: "[]" ?>;
    let usersQuery = "";
    let usersFilterRole = "all";
    let usersFilterActive = "all";

    function openUsersAdmin(){
      closeView();
      $("fabAdd")?.classList.add("hidden");
      renderUsersAdmin();
      $("usersSheetWrap").style.display = "flex";
      document.body.style.overflow = "hidden";
    }
    function closeUsersAdmin(){
      $("usersSheetWrap").style.display = "none";
      document.body.style.overflow = "";
      $("fabAdd")?.classList.remove("hidden");
    }
    function usersBackdropClose(e){
      if (e.target && e.target.id === "usersSheetWrap") closeUsersAdmin();
    }

    const usersSearchInput = $("usersSearch");
    const usersFilterRoleEl = $("usersFilterRole");
    const usersFilterActiveEl = $("usersFilterActive");

    if (usersSearchInput){
      usersSearchInput.addEventListener("input", (e) => {
        usersQuery = normalize(e.target.value);
        renderUsersAdmin();
      });
    }
    if (usersFilterRoleEl){
      usersFilterRoleEl.addEventListener("change", (e) => {
        usersFilterRole = e.target.value || "all";
        renderUsersAdmin();
      });
    }
    if (usersFilterActiveEl){
      usersFilterActiveEl.addEventListener("change", (e) => {
        usersFilterActive = e.target.value || "all";
        renderUsersAdmin();
      });
    }

    function postAdmin(action, payload){
      const f = document.createElement("form");
      f.method = "POST";
      f.action = "app.php";
      const add = (k,v) => {
        const i = document.createElement("input");
        i.type = "hidden";
        i.name = k;
        i.value = String(v);
        f.appendChild(i);
      };
      add("azione", action);
      add("csrf", CSRF);
      Object.entries(payload || {}).forEach(([k,v]) => add(k,v));
      document.body.appendChild(f);
      f.submit();
    }

    // ====== ADMIN: cambia password altro utente ======
    function openAdminPass(u){
      if (!u) return;
      $("adminPassUid").value = String(u.id);
      $("adminPassSubtitle").textContent = `Utente: ${u.username} · ID: ${u.id}`;
      $("adminNewPass").value = "";
      $("adminNewPass2").value = "";
      $("adminPassSheetWrap").style.display = "flex";
      document.body.style.overflow = "hidden";
      setTimeout(() => $("adminNewPass").focus(), 50);
    }
    function closeAdminPass(){
      $("adminPassSheetWrap").style.display = "none";
      document.body.style.overflow = "";
    }
    function adminPassBackdropClose(e){
      if (e.target && e.target.id === "adminPassSheetWrap") closeAdminPass();
    }

    function renderUsersAdmin(){
      const box = $("usersList");
      box.innerHTML = "";

      const list = ALL_USERS.filter(u => {
        const role = String(u.role || "").toLowerCase();
        if (usersFilterRole === "admin" && role !== "admin") return false;
        if (usersFilterRole === "user" && role !== "user") return false;
        if (usersFilterActive === "active" && !u.is_active) return false;
        if (usersFilterActive === "inactive" && u.is_active) return false;
        if (usersQuery) {
          const hay = `${u.username} ${u.id} ${u.role}`.toLowerCase();
          if (!hay.includes(usersQuery)) return false;
        }
        return true;
      });

      if (!list.length){
        const empty = document.createElement("div");
        empty.style.padding = "10px 12px";
        empty.style.color = "rgba(255,255,255,.75)";
        empty.style.fontSize = "13px";
        empty.textContent = T.empty_users;
        box.appendChild(empty);
        return;
      }

      const iconBtn = (icon, label, cls, onClick, disabled) => {
        const b = document.createElement("button");
        b.type = "button";
        b.className = cls || "btn btnGhost";
        b.style.padding = "8px 10px";
        b.style.fontSize = "16px";
        b.style.lineHeight = "1";
        b.innerHTML = icon;
        b.setAttribute("aria-label", label);
        b.setAttribute("data-tooltip", label);
        b.title = label;
        b.disabled = disabled;
        b.onclick = onClick;
        return b;
      };

      for (const u of list) {
        const row = document.createElement("div");
        row.className = "row";
        row.style.alignItems = "center";
        row.style.display = "flex";
        row.style.gap = "12px";
        row.style.padding = "12px 10px";
        row.style.borderBottom = "1px solid rgba(255,255,255,.08)";
        row.style.flexWrap = "wrap";

        const left = document.createElement("div");
        left.className = "rowMain";
        left.style.flex = "1 1 180px";
        left.style.minWidth = "0";

        const val = document.createElement("div");
        val.className = "rowValue";
        val.style.fontSize = "15px";
        val.style.fontWeight = "600";
        val.style.marginBottom = "4px";
        const roleShown = (String(u.role).toLowerCase() === 'admin') ? 'Admin' : 'User';
        val.textContent = u.username;

        const label = document.createElement("div");
        label.className = "rowLabel";
        label.style.fontSize = "12px";
        label.style.color = "rgba(255,255,255,.55)";
        label.textContent = `ID: ${u.id} · ${roleShown} · ${u.is_active ? T.status_active : T.status_inactive}`;

        left.appendChild(val);
        left.appendChild(label);

        const acts = document.createElement("div");
        acts.style.display = "flex";
        acts.style.gap = "6px";
        acts.style.flex = "0 0 auto";
        acts.style.flexWrap = "wrap";

        const isMe = (parseInt(u.id) === MY_UID);
        const isSupreme = String(u.username || "").toLowerCase() === "admin";

        const nextRole = (String(u.role).toLowerCase() === "user") ? "admin" : "user";
        const roleBtn = iconBtn(
          nextRole === 'admin' ? '👑' : '👤',
          nextRole === 'admin' ? 'Imposta admin' : 'Imposta user',
          "btn btnGhost",
          () => postAdmin("admin_set_role", { uid: u.id, role: nextRole }),
          isMe || isSupreme
        );

        const actBtn = iconBtn(
          u.is_active ? '⏸' : '▶',
          u.is_active ? 'Disattiva' : 'Attiva',
          "btn btnGhost",
          () => postAdmin("admin_toggle_active", { uid: u.id, active: u.is_active ? 0 : 1 }),
          isMe || isSupreme
        );

        const passBtn = iconBtn(
          '🔒',
          'Cambia password',
          "btn btnGhost",
          () => openAdminPass(u),
          isMe || isSupreme
        );

        const delBtn = iconBtn(
          '🗑',
          'Elimina',
          "btn btnDanger",
          () => {
            if (confirm(T.confirm_delete_user + u.username + '"?')) {
              postAdmin("admin_delete_user", { uid: u.id });
            }
          },
          isMe || isSupreme
        );

        const contactsBtn = iconBtn(
          '📋',
          'Visualizza contatti',
          "btn btnPrimary",
          () => viewUserContacts(u),
          false
        );

        acts.appendChild(contactsBtn);
        acts.appendChild(roleBtn);
        acts.appendChild(actBtn);
        acts.appendChild(passBtn);
        acts.appendChild(delBtn);

        row.appendChild(left);
        row.appendChild(acts);

        box.appendChild(row);
      }
    }

    function viewUserContacts(u){
      if (!u) return;
      closeUsersAdmin();
      window.location.href = "app.php?view_user_id=" + u.id;
    }
  <?php endif; ?>

  window.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      if ($("chatPopupWrap")?.classList.contains("open")) closeChatPopup();
      else if ($("cropModalWrap")?.classList.contains("open")) closeCropModal();
      else if (selectionMode) toggleSelectMode();
      else if ($("profileMenu")?.classList.contains("open")) closeProfileMenu();
      else if ($("avatarSheetWrap")?.style.display === "flex") closeAvatarSheet();
      else if ($("langSheetWrap")?.style.display === "flex") closeLanguage();
      else if ($("usersSheetWrap")?.style.display === "flex") closeUsersAdmin?.();
      else if ($("adminPassSheetWrap")?.style.display === "flex") closeAdminPass?.();
      else if ($("passSheetWrap")?.style.display === "flex") closePass();
      else if ($("importSIMSheetWrap")?.style.display === "flex") closeImportSIM();
      else if ($("exportSheetWrap")?.style.display === "flex") closeExport();
      else if ($("editSheetWrap")?.style.display === "flex") closeEdit();
      else if ($("viewOverlay")?.style.display === "flex") closeView();
    }
  });

  render();
</script>

<script src="https://cdnjs.cloudflare.com/ajax/libs/cropperjs/1.6.2/cropper.min.js" crossorigin="anonymous"></script>
</body>
</html>

