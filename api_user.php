<?php
/**
 * API Utente - Avatar/foto profilo
 */
require __DIR__ . '/config.php';

header('Content-Type: application/json; charset=utf-8');

$user = require_auth();
$uid = (int)$user['id'];

$action = $_GET['action'] ?? $_POST['action'] ?? '';

if ($action === 'upload_avatar') {
  if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['ok' => false, 'error' => 'Method not allowed']);
    exit;
  }
  if (empty($_FILES['avatar']['tmp_name']) || !is_uploaded_file($_FILES['avatar']['tmp_name'])) {
    echo json_encode(['ok' => false, 'error' => 'Nessun file caricato']);
    exit;
  }
  $orig = (string)($_FILES['avatar']['name'] ?? 'avatar');
  $ext = strtolower(pathinfo($orig, PATHINFO_EXTENSION));
  $allowed = ['jpg', 'jpeg', 'png', 'webp', 'gif'];
  if (!in_array($ext, $allowed, true)) {
    echo json_encode(['ok' => false, 'error' => 'Formato non valido. Usa JPG, PNG, WebP o GIF.']);
    exit;
  }
  $upload_dir = __DIR__ . '/uploadslist/avatars/';
  if (!is_dir($upload_dir)) @mkdir($upload_dir, 0777, true);
  $base = preg_replace('/[^a-zA-Z0-9._-]/', '_', pathinfo($orig, PATHINFO_FILENAME));
  $avatar_name = 'u' . $uid . '_' . time() . '_' . $base . '.' . $ext;
  $full_path = $upload_dir . $avatar_name;
  if (!move_uploaded_file($_FILES['avatar']['tmp_name'], $full_path)) {
    echo json_encode(['ok' => false, 'error' => 'Errore salvataggio file']);
    exit;
  }
  $avatar_url = 'uploadslist/avatars/' . $avatar_name;
  $pdo = db();
  $st = $pdo->prepare("SELECT avatar FROM users WHERE id=? LIMIT 1");
  $st->execute([$uid]);
  $old = $st->fetchColumn();
  if ($old && file_exists(__DIR__ . '/' . $old)) @unlink(__DIR__ . '/' . $old);
  set_user_avatar($uid, $avatar_url);
  echo json_encode(['ok' => true, 'avatar' => $avatar_url]);
  exit;
}

echo json_encode(['ok' => false, 'error' => 'Unknown action']);
