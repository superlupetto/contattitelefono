<?php
/**
 * API Chat - Sistema chat privata e gruppi
 * Storage: file system a cartelle
 * - chats/private/{chat_id}/history.json + audio/
 * - chats/groups/{group_id}/history.json + audio/
 * Le chat si cancellano automaticamente 7 giorni dopo l'ultimo messaggio.
 */
ob_start();
header('Content-Type: application/json; charset=utf-8');
require __DIR__ . '/config.php';
ob_end_clean();
ob_start(); // Buffer per catturare eventuali output (errori PHP) prima del JSON

$user = require_auth(true);
$uid = (int)$user['id'];
$is_admin = ($user['role'] ?? '') === 'admin';

$CHAT_BASE = __DIR__ . '/chats';
$CHAT_TTL_DAYS = 7;

function chat_response($data) {
  while (ob_get_level()) ob_end_clean();
  echo json_encode($data, JSON_UNESCAPED_UNICODE);
  exit;
}

function chat_error($msg, $code = 400) {
  http_response_code($code);
  chat_response(['ok' => false, 'error' => $msg]);
}

function private_chat_id(int $uid1, int $uid2): string {
  $a = min($uid1, $uid2);
  $b = max($uid1, $uid2);
  return "p_{$a}_{$b}";
}

function group_chat_id(string $gid): string {
  return "g_{$gid}";
}

function chat_dir(string $type, string $chat_id): string {
  global $CHAT_BASE;
  $dir = $CHAT_BASE . '/' . $type . '/' . $chat_id;
  if (!is_dir($dir)) {
    @mkdir($dir, 0755, true);
    if ($type === 'private') {
      @mkdir($dir . '/audio', 0755, true);
    } else {
      @mkdir($dir . '/audio', 0755, true);
    }
  }
  return $dir;
}

function load_history(string $type, string $chat_id): array {
  $dir = chat_dir($type, $chat_id);
  $file = $dir . '/history.json';
  if (!file_exists($file)) {
    return ['meta' => ['type' => $type, 'chat_id' => $chat_id, 'created' => date('c'), 'ttl_days' => 7], 'messages' => []];
  }
  $raw = @file_get_contents($file);
  if ($raw === false) return ['meta' => [], 'messages' => []];
  $data = json_decode($raw, true);
  return is_array($data) ? $data : ['meta' => [], 'messages' => []];
}

function save_history(string $type, string $chat_id, array $data): void {
  $dir = chat_dir($type, $chat_id);
  if (!is_dir($dir) && !@mkdir($dir, 0755, true)) {
    throw new RuntimeException("Impossibile creare la cartella chat: {$dir}");
  }
  if (!is_dir($dir . '/audio') && !@mkdir($dir . '/audio', 0755, true)) {
    throw new RuntimeException("Impossibile creare la cartella audio: {$dir}/audio");
  }
  $file = $dir . '/history.json';
  if (empty($data['meta'])) {
    $data['meta'] = ['type' => $type, 'chat_id' => $chat_id, 'created' => date('c'), 'ttl_days' => 7];
  }
  $data['meta']['updated'] = date('c');
  $json = json_encode($data, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
  if (file_put_contents($file, $json) === false) {
    throw new RuntimeException("Impossibile scrivere history.json in {$dir}");
  }
}

function purge_expired_messages(array $messages, int $ttl_days = 7): array {
  $cutoff = time() - ($ttl_days * 86400);
  return array_values(array_filter($messages, function ($m) use ($cutoff) {
    $ts = is_numeric($m['ts'] ?? 0) ? (int)$m['ts'] : strtotime($m['ts'] ?? '');
    return $ts >= $cutoff;
  }));
}

/** Elimina ricorsivamente una cartella e il suo contenuto */
function delete_dir_recursive(string $dir): bool {
  if (!is_dir($dir)) return true;
  $files = array_diff(scandir($dir), ['.', '..']);
  foreach ($files as $f) {
    $path = $dir . '/' . $f;
    is_dir($path) ? delete_dir_recursive($path) : @unlink($path);
  }
  return @rmdir($dir);
}

/** Elimina le chat inattive (ultimo messaggio > 7 giorni fa). Eseguita alla creazione di un gruppo. */
function purge_inactive_chats(): void {
  global $CHAT_BASE, $CHAT_TTL_DAYS;
  $cutoff = time() - ($CHAT_TTL_DAYS * 86400);
  foreach (['private', 'groups'] as $type) {
    $base = $CHAT_BASE . '/' . $type;
    if (!is_dir($base)) continue;
    foreach (glob($base . '/*', GLOB_ONLYDIR) as $dir) {
      $chat_id = basename($dir);
      $file = $dir . '/history.json';
      if (!file_exists($file)) continue;
      $raw = @file_get_contents($file);
      $data = $raw ? json_decode($raw, true) : null;
      if (!is_array($data)) continue;
      $msgs = $data['messages'] ?? [];
      $lastTs = 0;
      if (!empty($msgs)) {
        $last = end($msgs);
        $lastTs = is_numeric($last['ts'] ?? 0) ? (int)$last['ts'] : strtotime($last['ts'] ?? '');
      } else {
        $created = $data['meta']['created'] ?? $data['meta']['updated'] ?? '';
        $lastTs = $created ? strtotime($created) : 0;
      }
      if ($lastTs > 0 && $lastTs < $cutoff) {
        delete_dir_recursive($dir);
      }
    }
  }
}

function can_access_private_chat(array $user, string $chat_id): bool {
  if (($user['role'] ?? '') === 'admin') return true;
  if (!preg_match('/^p_(\d+)_(\d+)$/', $chat_id, $m)) return false;
  $uid = (int)$user['id'];
  return (int)$m[1] === $uid || (int)$m[2] === $uid;
}

function can_access_group(array $user, array $members): bool {
  if (($user['role'] ?? '') === 'admin') return true;
  $uid = (int)$user['id'];
  return in_array($uid, array_map('intval', $members));
}

// Ensure base dirs exist (crea ricorsivamente se mancano)
$chat_dirs = [$CHAT_BASE, $CHAT_BASE . '/private', $CHAT_BASE . '/groups'];
foreach ($chat_dirs as $d) {
  if (!is_dir($d) && !@mkdir($d, 0755, true)) {
    error_log("API Chat: impossibile creare directory: {$d}");
  }
}

$action = $_GET['action'] ?? $_POST['action'] ?? '';

// --- LIST USERS (search) ---
if ($action === 'search_users') {
  $q = trim((string)($_GET['q'] ?? $_POST['q'] ?? ''));
  $pdo = db();
  $cols = column_exists('users', 'avatar') ? 'id, username, avatar' : 'id, username';
  $st = $pdo->prepare("SELECT {$cols} FROM users WHERE is_active=1 AND id != ? ORDER BY username ASC");
  $st->execute([$uid]);
  $users = $st->fetchAll();
  foreach ($users as &$u) { if (!isset($u['avatar'])) $u['avatar'] = ''; }
  if ($q !== '') {
    $q_lower = strtolower($q);
    $users = array_filter($users, function ($u) use ($q_lower) {
      return strpos(strtolower($u['username'] ?? ''), $q_lower) !== false;
    });
  }
  chat_response(['ok' => true, 'users' => array_values($users)]);
}

// --- MY CHATS (list) ---
if ($action === 'my_chats') {
  $chats = [];
  $pdo = db();
  $userMap = [];
  $userAvatars = [];
  $cols = column_exists('users', 'avatar') ? 'id, username, avatar' : 'id, username';
  $st = $pdo->query("SELECT {$cols} FROM users WHERE is_active=1");
  while ($row = $st->fetch()) {
    $userMap[(int)$row['id']] = $row['username'];
    $userAvatars[(int)$row['id']] = $row['avatar'] ?? '';
  }

  foreach (glob($CHAT_BASE . '/private/*', GLOB_ONLYDIR) as $d) {
    $chat_id = basename($d);
    if (!can_access_private_chat($user, $chat_id)) continue;
    $h = load_history('private', $chat_id);
    $msgs = $h['messages'] ?? [];
    $msgs = purge_expired_messages($msgs, $CHAT_TTL_DAYS);
    if (preg_match('/^p_(\d+)_(\d+)$/', $chat_id, $m)) {
      $other_id = (int)$m[1] === $uid ? (int)$m[2] : (int)$m[1];
      $chats[] = [
        'chat_id' => $chat_id,
        'type' => 'private',
        'other_user_id' => $other_id,
        'other_username' => $userMap[$other_id] ?? '?',
        'other_avatar' => $userAvatars[$other_id] ?? '',
        'last_msg' => end($msgs),
        'count' => count($msgs),
      ];
    }
  }

  foreach (glob($CHAT_BASE . '/groups/*', GLOB_ONLYDIR) as $d) {
    $chat_id = basename($d);
    $h = load_history('groups', $chat_id);
    $members = $h['meta']['members'] ?? [];
    if (!can_access_group($user, $members)) continue;
    $msgs = purge_expired_messages($h['messages'] ?? [], $CHAT_TTL_DAYS);
    $chats[] = [
      'chat_id' => $chat_id,
      'type' => 'group',
      'name' => $h['meta']['name'] ?? $chat_id,
      'members' => $members,
      'admin_id' => (int)($h['meta']['admin_id'] ?? $members[0] ?? 0),
      'avatar' => $h['meta']['avatar'] ?? '',
      'last_msg' => end($msgs),
      'count' => count($msgs),
    ];
  }

  usort($chats, function ($a, $b) {
    $ta = $a['last_msg']['ts'] ?? 0;
    $tb = $b['last_msg']['ts'] ?? 0;
    if (is_string($ta)) $ta = strtotime($ta);
    if (is_string($tb)) $tb = strtotime($tb);
    return $tb <=> $ta;
  });

  chat_response(['ok' => true, 'chats' => $chats, 'ttl_days' => $CHAT_TTL_DAYS]);
}

// --- GET HISTORY ---
if ($action === 'history') {
  $type = (string)($_GET['type'] ?? 'private');
  $chat_id = trim((string)($_GET['chat_id'] ?? ''));
  if ($chat_id === '') chat_error('chat_id required');

  if ($type === 'private') {
    if (!can_access_private_chat($user, $chat_id)) chat_error('Access denied', 403);
    $h = load_history('private', $chat_id);
  } else {
    $h = load_history('groups', $chat_id);
    if (!can_access_group($user, $h['meta']['members'] ?? [])) chat_error('Access denied', 403);
  }

  $h['messages'] = purge_expired_messages($h['messages'] ?? [], $CHAT_TTL_DAYS);
  if ($type === 'groups') {
    $pdo = db();
    $members = $h['meta']['members'] ?? [];
    $memberNames = [];
    foreach ($members as $mid) {
      $st = $pdo->prepare("SELECT username FROM users WHERE id=? LIMIT 1");
      $st->execute([(int)$mid]);
      $memberNames[(int)$mid] = $st->fetchColumn() ?: '?';
    }
    $h['meta']['member_names'] = $memberNames;
  }
  chat_response(['ok' => true, 'history' => $h, 'ttl_days' => $CHAT_TTL_DAYS]);
}

// --- SEND MESSAGE ---
if ($action === 'send') {
  $type = (string)($_POST['type'] ?? 'private');
  $chat_id = trim((string)($_POST['chat_id'] ?? ''));
  $text = trim((string)($_POST['text'] ?? ''));

  if ($chat_id === '') chat_error('chat_id required');
  if ($text === '' && empty($_FILES['audio'])) chat_error('text or audio required');

  if ($type === 'private') {
    if (!can_access_private_chat($user, $chat_id)) chat_error('Access denied', 403);
    $h = load_history('private', $chat_id);
  } else {
    $h = load_history('groups', $chat_id);
    if (!can_access_group($user, $h['meta']['members'] ?? [])) chat_error('Access denied', 403);
  }

  $msg = [
    'id' => uniqid('msg_', true),
    'uid' => $uid,
    'username' => $user['username'],
    'ts' => time(),
    'text' => $text,
  ];

  if (!empty($_FILES['audio']['tmp_name']) && is_uploaded_file($_FILES['audio']['tmp_name'])) {
    $ext = 'webm';
    $audio_dir = chat_dir($type === 'private' ? 'private' : 'groups', $chat_id) . '/audio';
    $fname = $msg['id'] . '.' . $ext;
    $path = $audio_dir . '/' . $fname;
    if (move_uploaded_file($_FILES['audio']['tmp_name'], $path)) {
      $msg['audio'] = 'audio/' . $fname;
      $msg['text'] = '[ messaggio vocale ]';
    }
  }

  $h['messages'] = $h['messages'] ?? [];
  $h['messages'][] = $msg;
  $h['messages'] = purge_expired_messages($h['messages'], $CHAT_TTL_DAYS);

  try {
    if ($type === 'private') {
      save_history('private', $chat_id, $h);
    } else {
      save_history('groups', $chat_id, $h);
    }
  } catch (Throwable $e) {
    chat_error('Errore salvataggio: ' . $e->getMessage(), 500);
  }

  chat_response(['ok' => true, 'message' => $msg]);
}

// --- CREATE PRIVATE CHAT / START ---
if ($action === 'start_private') {
  $other_uid = (int)($_POST['other_user_id'] ?? $_GET['other_user_id'] ?? 0);
  if ($other_uid <= 0 || $other_uid === $uid) chat_error('Invalid user');

  $pdo = db();
  $st = $pdo->prepare("SELECT id FROM users WHERE id=? AND is_active=1 LIMIT 1");
  $st->execute([$other_uid]);
  if (!$st->fetch()) chat_error('User not found');

  $chat_id = private_chat_id($uid, $other_uid);
  chat_dir('private', $chat_id);
  $h = load_history('private', $chat_id);
  chat_response(['ok' => true, 'chat_id' => $chat_id, 'history' => $h]);
}

// --- CREATE GROUP ---
if ($action === 'create_group') {
  purge_inactive_chats();
  $name = trim((string)($_POST['name'] ?? 'Nuovo gruppo'));
  $member_ids = isset($_POST['members']) && is_array($_POST['members']) ? array_map('intval', $_POST['members']) : [];
  $member_ids = array_unique(array_filter($member_ids));
  $member_ids[] = $uid;
  $member_ids = array_unique($member_ids);

  if (count($member_ids) > 50) chat_error('Max 50 membri');

  $gid = 'grp_' . uniqid('', true);
  $chat_id = group_chat_id($gid);
  $avatar_url = '';
  if (!empty($_FILES['avatar']['tmp_name']) && is_uploaded_file($_FILES['avatar']['tmp_name'])) {
    $orig = (string)($_FILES['avatar']['name'] ?? 'avatar');
    $ext = strtolower(pathinfo($orig, PATHINFO_EXTENSION));
    if (in_array($ext, ['jpg', 'jpeg', 'png', 'webp', 'gif'], true)) {
      $upload_dir = __DIR__ . '/uploadslist/groups/';
      if (!is_dir($upload_dir)) @mkdir($upload_dir, 0777, true);
      $fname = preg_replace('/[^a-zA-Z0-9._-]/', '_', $gid) . '_' . time() . '.' . $ext;
      if (move_uploaded_file($_FILES['avatar']['tmp_name'], $upload_dir . $fname)) {
        $avatar_url = 'uploadslist/groups/' . $fname;
      }
    }
  }
  $h = [
    'meta' => [
      'type' => 'group',
      'chat_id' => $chat_id,
      'name' => $name,
      'members' => $member_ids,
      'admin_id' => $uid,
      'avatar' => $avatar_url,
      'created' => date('c'),
      'ttl_days' => 7,
    ],
    'messages' => [],
  ];
  save_history('groups', $chat_id, $h);
  chat_response(['ok' => true, 'chat_id' => $chat_id, 'group_id' => $gid]);
}

// --- UPDATE GROUP (foto, nome) ---
if ($action === 'update_group') {
  $chat_id = trim((string)($_POST['chat_id'] ?? ''));
  if ($chat_id === '' || !preg_match('/^g_grp_/', $chat_id)) chat_error('chat_id required');
  $h = load_history('groups', $chat_id);
  $members = $h['meta']['members'] ?? [];
  if (!can_access_group($user, $members)) chat_error('Access denied', 403);
  $admin_id = (int)($h['meta']['admin_id'] ?? $members[0] ?? 0);
  if ($admin_id !== $uid && !$is_admin) chat_error('Solo l\'admin del gruppo può modificare', 403);
  $changed = false;
  if (!empty($_POST['name'])) {
    $h['meta']['name'] = trim((string)$_POST['name']);
    $changed = true;
  }
  if (!empty($_FILES['avatar']['tmp_name']) && is_uploaded_file($_FILES['avatar']['tmp_name'])) {
    $orig = (string)($_FILES['avatar']['name'] ?? 'avatar');
    $ext = strtolower(pathinfo($orig, PATHINFO_EXTENSION));
    if (in_array($ext, ['jpg', 'jpeg', 'png', 'webp', 'gif'], true)) {
      $upload_dir = __DIR__ . '/uploadslist/groups/';
      if (!is_dir($upload_dir)) @mkdir($upload_dir, 0777, true);
      $fname = basename($chat_id) . '_' . time() . '.' . $ext;
      if (move_uploaded_file($_FILES['avatar']['tmp_name'], $upload_dir . $fname)) {
        $old = $h['meta']['avatar'] ?? '';
        if ($old && file_exists(__DIR__ . '/' . $old)) @unlink(__DIR__ . '/' . $old);
        $h['meta']['avatar'] = 'uploadslist/groups/' . $fname;
        $changed = true;
      }
    }
  }
  if ($changed) save_history('groups', $chat_id, $h);
  chat_response(['ok' => true, 'avatar' => $h['meta']['avatar'] ?? '', 'name' => $h['meta']['name'] ?? '']);
}

// --- TRANSFER ADMIN (gruppo) ---
if ($action === 'transfer_admin') {
  $chat_id = trim((string)($_POST['chat_id'] ?? ''));
  $new_admin_id = (int)($_POST['new_admin_id'] ?? 0);
  if ($chat_id === '' || !preg_match('/^g_grp_/', $chat_id)) chat_error('chat_id required');
  if ($new_admin_id <= 0) chat_error('new_admin_id required');
  $h = load_history('groups', $chat_id);
  $members = array_map('intval', $h['meta']['members'] ?? []);
  if (!can_access_group($user, $members)) chat_error('Access denied', 403);
  $admin_id = (int)($h['meta']['admin_id'] ?? $members[0] ?? 0);
  if ($admin_id !== $uid && !$is_admin) chat_error('Solo l\'admin può trasferire il ruolo', 403);
  if (!in_array($new_admin_id, $members)) chat_error('Il nuovo admin deve essere membro del gruppo', 400);
  $h['meta']['admin_id'] = $new_admin_id;
  save_history('groups', $chat_id, $h);
  chat_response(['ok' => true]);
}

// --- AUDIO URL (serve file) ---
if ($action === 'audio') {
  $type = (string)($_GET['type'] ?? 'private');
  $chat_id = trim((string)($_GET['chat_id'] ?? ''));
  $file = trim((string)($_GET['file'] ?? ''));
  if ($chat_id === '' || $file === '') chat_error('Missing params');

  $file = basename($file);
  if (strpos($file, '..') !== false) chat_error('Invalid file');

  if ($type === 'private') {
    if (!can_access_private_chat($user, $chat_id)) chat_error('Access denied', 403);
  } else {
    $h = load_history('groups', $chat_id);
    if (!can_access_group($user, $h['meta']['members'] ?? [])) chat_error('Access denied', 403);
  }

  $base = $CHAT_BASE . '/' . ($type === 'private' ? 'private' : 'groups') . '/' . $chat_id . '/audio/';
  $path = $base . $file;
  if (!file_exists($path) || !is_file($path)) chat_error('File not found', 404);

  header('Content-Type: audio/webm');
  header('Content-Length: ' . filesize($path));
  readfile($path);
  exit;
}

// --- ADMIN: ALL CHATS ---
if ($action === 'admin_all_chats' && $is_admin) {
  try {
  $chats = [];
  $pdo = db();
  $userMap = [];
  $userAvatars = [];
  $cols = column_exists('users', 'avatar') ? 'id, username, avatar' : 'id, username';
  $st = $pdo->query("SELECT {$cols} FROM users");
  while ($row = $st->fetch()) {
    $userMap[(int)$row['id']] = $row['username'];
    $userAvatars[(int)$row['id']] = $row['avatar'] ?? '';
  }

  foreach (glob($CHAT_BASE . '/private/*', GLOB_ONLYDIR) as $d) {
    $chat_id = basename($d);
    if (!preg_match('/^p_(\d+)_(\d+)$/', $chat_id, $m)) continue;
    $u1 = (int)$m[1];
    $u2 = (int)$m[2];
    $h = load_history('private', $chat_id);
    $msgs = purge_expired_messages($h['messages'] ?? [], $CHAT_TTL_DAYS);
    $chats[] = [
      'chat_id' => $chat_id,
      'type' => 'private',
      'user1_id' => $u1,
      'user1_name' => $userMap[$u1] ?? '?',
      'user1_avatar' => $userAvatars[$u1] ?? '',
      'user2_id' => $u2,
      'user2_name' => $userMap[$u2] ?? '?',
      'user2_avatar' => $userAvatars[$u2] ?? '',
      'interlocutors' => ($userMap[$u1] ?? '?') . ' ↔ ' . ($userMap[$u2] ?? '?'),
      'messages' => $msgs,
      'count' => count($msgs),
    ];
  }

  foreach (glob($CHAT_BASE . '/groups/*', GLOB_ONLYDIR) as $d) {
    $chat_id = basename($d);
    $h = load_history('groups', $chat_id);
    $members = $h['meta']['members'] ?? [];
    $names = array_map(function ($id) use ($userMap) {
      return $userMap[(int)$id] ?? '?';
    }, $members);
    $msgs = purge_expired_messages($h['messages'] ?? [], $CHAT_TTL_DAYS);
    $chats[] = [
      'chat_id' => $chat_id,
      'type' => 'group',
      'name' => $h['meta']['name'] ?? $chat_id,
      'members' => $members,
      'admin_id' => (int)($h['meta']['admin_id'] ?? $members[0] ?? 0),
      'avatar' => $h['meta']['avatar'] ?? '',
      'member_names' => $names,
      'interlocutors' => implode(', ', $names),
      'messages' => $msgs,
      'count' => count($msgs),
    ];
  }

  usort($chats, function ($a, $b) {
    $la = end($a['messages'] ?? []);
    $lb = end($b['messages'] ?? []);
    $ta = $la['ts'] ?? 0;
    $tb = $lb['ts'] ?? 0;
    if (is_string($ta)) $ta = strtotime($ta);
    if (is_string($tb)) $tb = strtotime($tb);
    return $tb <=> $ta;
  });

  chat_response(['ok' => true, 'chats' => $chats, 'ttl_days' => $CHAT_TTL_DAYS]);
  } catch (Throwable $e) {
    error_log('api_chat admin_all_chats: ' . $e->getMessage());
    chat_response(['ok' => false, 'error' => 'Errore caricamento chat admin']);
  }
}

chat_error('Unknown action');
