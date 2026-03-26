<?php
require __DIR__ . '/config.php';

// Se già loggato vai direttamente all'app
if (current_user()) {
  header("Location: app.php");
  exit();
}

$toast_msg = $_SESSION['toast_msg'] ?? null;
$toast_err = $_SESSION['toast_err'] ?? null;
unset($_SESSION['toast_msg'], $_SESSION['toast_err']);

$saved_username = $_SESSION['saved_username'] ?? '';
$save_username_checked = !empty($saved_username);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  if (!hash_equals($_SESSION['csrf'] ?? '', (string)($_POST['csrf'] ?? ''))) {
    $toast_err = t('error_csrf');
  } else {
    $username = trim((string)($_POST['username'] ?? ''));
    $pass1 = (string)($_POST['password'] ?? '');
    $pass2 = (string)($_POST['password2'] ?? '');

    if (!empty($_POST['save_username']) && $username !== '') {
      $_SESSION['saved_username'] = $username;
    }
    $save_username_checked = !empty($_POST['save_username']);
    $saved_username = $username;

    if ($username === '' || !preg_match('/^[a-zA-Z0-9._-]{3,50}$/', $username)) {
      $toast_err = t('error_username_invalid');
    } elseif (strlen($pass1) < 6) {
      $toast_err = t('error_password_short');
    } elseif ($pass1 !== $pass2) {
      $toast_err = t('error_password_mismatch');
    } else {
      try {
        $pdo = db();
        $hash = password_hash($pass1, PASSWORD_DEFAULT);
        $st = $pdo->prepare("INSERT INTO users (username, pass_hash, role, is_active) VALUES (?, ?, 'user', 1)");
        $st->execute([$username, $hash]);

        $_SESSION['saved_username'] = $username;
        $_SESSION['toast_msg'] = t('msg_account_created');
        header("Location: login.php");
        exit();
      } catch (PDOException $e) {
        // 23000 = integrity constraint violation (es. username già usato)
        if ((string)$e->getCode() === '23000') {
          $toast_err = t('error_username_exists');
        } else {
          $toast_err = t('error_register') . $e->getMessage();
        }
      } catch (Throwable $e) {
        $toast_err = t('error_register') . $e->getMessage();
      }
    }
  }
}
?>
<!doctype html>
<html lang="<?= htmlspecialchars($CURRENT_LANG) ?>">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover" />
  <title><?= t('register_title') ?></title>
  <script>(function(){var t=localStorage.getItem("app_theme")||"default";document.documentElement.setAttribute("data-theme",t);})();</script>
  <style>
    :root,[data-theme="default"]{
      --bg0:#070b16; --bg1:#0b1630;
      --bg-gradient: radial-gradient(ellipse 140vw 100vh at 15% 5%, rgba(125,211,252,.22), transparent 55%),
        radial-gradient(ellipse 100vw 80vh at 88% 10%, rgba(167,139,250,.20), transparent 50%),
        radial-gradient(ellipse 100vw 90vh at 55% 98%, rgba(52,211,153,.12), transparent 55%),
        linear-gradient(180deg, var(--bg0), var(--bg1));
      --accent1: rgba(125,211,252,.95); --accent2: rgba(167,139,250,.90);
      --accent-gradient: linear-gradient(135deg, var(--accent1), var(--accent2));
      --focus-border: rgba(125,211,252,.55); --focus-ring: rgba(125,211,252,.14);
      --success-bg: rgba(52,211,153,.12); --success-border: rgba(52,211,153,.35);
    }
    [data-theme="ocean"]{ --bg0:#05101a; --bg1:#0a1e2e;
      --bg-gradient: radial-gradient(ellipse 140vw 100vh at 20% 0%, rgba(6,182,212,.25), transparent 50%),
        radial-gradient(ellipse 100vw 80vh at 80% 20%, rgba(14,165,233,.18), transparent 50%),
        radial-gradient(ellipse 100vw 90vh at 50% 100%, rgba(34,211,238,.10), transparent 55%),
        linear-gradient(180deg, var(--bg0), var(--bg1));
      --accent1: rgba(6,182,212,.95); --accent2: rgba(14,165,233,.90);
      --focus-border: rgba(6,182,212,.55); --focus-ring: rgba(6,182,212,.18);
    }
    [data-theme="sunset"]{ --bg0:#1a0a0f; --bg1:#2e1520;
      --bg-gradient: radial-gradient(ellipse 140vw 100vh at 10% 5%, rgba(251,146,60,.22), transparent 55%),
        radial-gradient(ellipse 100vw 80vh at 90% 15%, rgba(244,63,94,.20), transparent 50%),
        radial-gradient(ellipse 100vw 90vh at 50% 95%, rgba(251,113,133,.12), transparent 55%),
        linear-gradient(180deg, var(--bg0), var(--bg1));
      --accent1: rgba(251,146,60,.95); --accent2: rgba(244,63,94,.90);
      --focus-border: rgba(251,146,60,.55); --focus-ring: rgba(251,146,60,.18);
    }
    [data-theme="forest"]{ --bg0:#051508; --bg1:#0a1f0e;
      --bg-gradient: radial-gradient(ellipse 140vw 100vh at 25% 0%, rgba(34,197,94,.20), transparent 55%),
        radial-gradient(ellipse 100vw 80vh at 75% 15%, rgba(22,163,74,.18), transparent 50%),
        radial-gradient(ellipse 100vw 90vh at 50% 100%, rgba(74,222,128,.10), transparent 55%),
        linear-gradient(180deg, var(--bg0), var(--bg1));
      --accent1: rgba(34,197,94,.95); --accent2: rgba(22,163,74,.90);
      --focus-border: rgba(34,197,94,.55); --focus-ring: rgba(34,197,94,.18);
    }
    [data-theme="midnight"]{ --bg0:#030712; --bg1:#0f172a;
      --bg-gradient: radial-gradient(ellipse 140vw 100vh at 30% 0%, rgba(99,102,241,.15), transparent 55%),
        radial-gradient(ellipse 100vw 80vh at 70% 20%, rgba(79,70,229,.12), transparent 50%),
        radial-gradient(ellipse 100vw 90vh at 50% 98%, rgba(129,140,248,.08), transparent 55%),
        linear-gradient(180deg, var(--bg0), var(--bg1));
      --accent1: rgba(99,102,241,.95); --accent2: rgba(129,140,248,.90);
      --focus-border: rgba(99,102,241,.55); --focus-ring: rgba(99,102,241,.18);
    }
    [data-theme="rose"]{ --bg0:#1c0a12; --bg1:#2d1520;
      --bg-gradient: radial-gradient(ellipse 140vw 100vh at 15% 5%, rgba(244,114,182,.22), transparent 55%),
        radial-gradient(ellipse 100vw 80vh at 85% 15%, rgba(236,72,153,.18), transparent 50%),
        radial-gradient(ellipse 100vw 90vh at 55% 98%, rgba(251,113,133,.12), transparent 55%),
        linear-gradient(180deg, var(--bg0), var(--bg1));
      --accent1: rgba(244,114,182,.95); --accent2: rgba(236,72,153,.90);
      --focus-border: rgba(244,114,182,.55); --focus-ring: rgba(244,114,182,.18);
    }
    [data-theme="amber"]{ --bg0:#1a1205; --bg1:#2d1f0a;
      --bg-gradient: radial-gradient(ellipse 140vw 100vh at 20% 0%, rgba(245,158,11,.22), transparent 55%),
        radial-gradient(ellipse 100vw 80vh at 80% 10%, rgba(217,119,6,.18), transparent 50%),
        radial-gradient(ellipse 100vw 90vh at 50% 98%, rgba(251,191,36,.12), transparent 55%),
        linear-gradient(180deg, var(--bg0), var(--bg1));
      --accent1: rgba(245,158,11,.95); --accent2: rgba(217,119,6,.90);
      --focus-border: rgba(245,158,11,.55); --focus-ring: rgba(245,158,11,.18);
    }
    :root{ --glass: rgba(255,255,255,.10); --glass2: rgba(255,255,255,.14);
      --stroke: rgba(255,255,255,.18);
      --text: rgba(255,255,255,.92); --muted: rgba(255,255,255,.70);
      --shadow: 0 20px 60px rgba(0,0,0,.45); --radius: 22px;
    }
    *{box-sizing:border-box}
    html,body{min-height:100%; height:100%}
    body{
      margin:0;
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial, "Apple Color Emoji","Segoe UI Emoji";
      color:var(--text);
      background: var(--bg-gradient);
      background-attachment: fixed;
      background-size: cover;
      background-position: center;
      display:flex; align-items:center; justify-content:center; padding:24px;
    }
    .card{
      width:min(420px, 100%);
      border-radius: var(--radius);
      background: linear-gradient(180deg, var(--glass2), rgba(255,255,255,.06));
      border: 1px solid var(--stroke);
      backdrop-filter: blur(18px); -webkit-backdrop-filter: blur(18px);
      box-shadow: var(--shadow);
      padding: 22px;
      position:relative; overflow:hidden;
    }
    .card:before{
      content:""; position:absolute; inset:-2px;
      background: radial-gradient(700px 260px at 30% 0%, rgba(125,211,252,.25), transparent 60%),
                  radial-gradient(700px 260px at 70% 0%, rgba(167,139,250,.20), transparent 55%);
      pointer-events:none; filter: blur(10px); opacity:.9;
    }
    .inner{position:relative; z-index:1}
    .brand{display:flex; align-items:center; gap:12px; margin-bottom: 14px;}
    .logo{width:42px; height:42px; border-radius: 14px;
      background: var(--accent-gradient);
      box-shadow: 0 14px 30px rgba(0,0,0,.25);
    }
    h1{margin:0; font-size:20px; font-weight: 650;}
    .sub{margin: 6px 0 0; color: var(--muted); font-size: 13.5px; line-height: 1.35;}
    form{margin-top:16px}
    .field{margin-top: 12px; display:flex; flex-direction:column; gap:8px;}
    label{color: var(--muted); font-size: 12px;}
    input{
      width:100%; padding: 14px 14px; border-radius: 16px;
      border: 1px solid rgba(255,255,255,.14);
      background: rgba(0,0,0,.16);
      color: var(--text); outline:none; transition: .2s ease;
    }
    input:focus{
      border-color: var(--focus-border);
      box-shadow: 0 0 0 4px var(--focus-ring);
      transform: translateY(-1px);
    }
    .btn{
      margin-top: 14px; width:100%;
      padding: 13px 14px; border-radius: 16px;
      border: 1px solid rgba(255,255,255,.18);
      background: var(--accent-gradient);
      color: rgba(0,0,0,.88);
      font-weight: 750; cursor:pointer; transition: .2s ease;
      box-shadow: 0 18px 40px rgba(0,0,0,.25);
    }
    .btn:hover{ transform: translateY(-1px); filter: brightness(1.02) }
    .btn:active{ transform: translateY(1px); filter: brightness(.98) }
    .checkRow{margin-top:10px;display:flex;align-items:center;gap:10px;cursor:pointer;}
    .checkRow input[type="checkbox"]{width:18px;height:18px;accent-color:var(--accent1);cursor:pointer;}
    .checkRow span{color:var(--muted);font-size:13px;user-select:none;}

    .btnGhost{
      margin-top: 10px;
      width:100%;
      display:block;
      text-align:center;
      text-decoration:none;
      padding: 13px 14px;
      border-radius: 16px;
      border: 1px solid rgba(255,255,255,.14);
      background: rgba(255,255,255,.06);
      color: rgba(255,255,255,.90);
      font-weight: 750;
      transition: .2s ease;
      box-shadow: 0 18px 40px rgba(0,0,0,.18);
    }
    .btnGhost:hover{ transform: translateY(-1px); background: rgba(255,255,255,.08) }
    .btnGhost:active{ transform: translateY(1px); background: rgba(255,255,255,.05) }

    .alerts{ margin-top: 12px; }
    .msg{
      margin: 0 0 10px; padding: 12px 14px; border-radius: 16px;
      border: 1px solid var(--success-border);
      background: var(--success-bg);
      color: rgba(255,255,255,.92); font-size: 15.5px; line-height: 1.35;
    }
    .error{
      margin: 0 0 10px; padding: 12px 14px; border-radius: 16px;
      border: 1px solid rgba(251,113,133,.35);
      background: rgba(251,113,133,.12);
      color: rgba(255,255,255,.92); font-size: 15.5px; line-height: 1.35;
    }
    .alerts > :last-child{ margin-bottom: 0; }
    .foot{margin-top: 14px; color: rgba(255,255,255,.55); font-size: 12px; text-align:center;}
    .btnLang{position:fixed;top:16px;right:16px;z-index:100;padding:8px 14px;border-radius:12px;border:1px solid rgba(255,255,255,.2);background:rgba(255,255,255,.08);color:rgba(255,255,255,.9);text-decoration:none;font-size:13px;font-weight:600;cursor:pointer;transition:.18s ease;display:inline-flex;align-items:center;gap:8px;}
    .btnLang:hover{background:rgba(255,255,255,.14);transform:translateY(-1px)}
    .sheetWrap{position:fixed;inset:0;z-index:200;display:none;align-items:flex-end;justify-content:center;background:rgba(0,0,0,.48);backdrop-filter:blur(8px);padding:16px;}
    .sheetWrap.show{display:flex;}
    .sheet{width:min(360px,100%);border-radius:24px;border:1px solid rgba(255,255,255,.16);background:linear-gradient(180deg,rgba(255,255,255,.12),rgba(255,255,255,.06));backdrop-filter:blur(18px);box-shadow:0 24px 60px rgba(0,0,.5);overflow:hidden;animation:sheetPop .22s ease forwards;}
    @keyframes sheetPop{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:translateY(0)}}
    .sheetTop{padding:14px 16px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid rgba(255,255,255,.1);}
    .sheetTitle{margin:0;font-size:16px;font-weight:700;}
    .sheetBody{padding:12px 16px 16px;}
    .langItem{display:flex;align-items:center;padding:12px 14px;border-radius:14px;text-decoration:none;color:rgba(255,255,255,.9);font-weight:600;transition:.15s ease;margin-bottom:6px;}
    .langItem:hover{background:rgba(255,255,255,.1)}
    .langItem.active{background: color-mix(in srgb, var(--accent1) 30%, transparent); border:1px solid rgba(255,255,255,.2);}
    .iconbtn{width:36px;height:36px;border-radius:12px;border:none;background:rgba(255,255,255,.08);color:rgba(255,255,255,.9);cursor:pointer;display:grid;place-items:center;font-size:18px;}
    .iconbtn:hover{background:rgba(255,255,255,.12)}
  </style>
</head>
<body>
  <button type="button" class="btnLang" onclick="document.getElementById('langSheetWrap').classList.add('show')" aria-label="<?= t('label_language') ?>" aria-haspopup="dialog">🌐 <?= t('label_language') ?></button>

  <div id="langSheetWrap" class="sheetWrap" role="dialog" aria-modal="true" aria-label="<?= t('sheet_language') ?>" onclick="if(event.target===this)this.classList.remove('show')">
    <div class="sheet" onclick="event.stopPropagation()">
      <div class="sheetTop">
        <h2 class="sheetTitle"><?= t('sheet_language') ?></h2>
        <button type="button" class="iconbtn" onclick="document.getElementById('langSheetWrap').classList.remove('show')" aria-label="<?= t('btn_close') ?>">✕</button>
      </div>
      <div class="sheetBody">
        <?php foreach ($AVAILABLE_LANGS as $code => $label): ?>
          <a href="?lang=<?= $code ?>" class="langItem <?= $code === $CURRENT_LANG ? 'active' : '' ?>" hreflang="<?= $code ?>"><?= h($label) ?></a>
        <?php endforeach; ?>
      </div>
    </div>
  </div>
  <div class="card">
    <div class="inner">
      <div class="brand">
        <div class="logo"></div>
        <div>
          <h1><?= t('register_title') ?></h1>
          <div class="sub"><?= t('register_subtitle') ?></div>
        </div>
      </div>

      <div class="alerts" aria-live="polite" aria-atomic="true">
        <?php if ($toast_msg): ?>
          <div class="msg"><?= h($toast_msg) ?></div>
        <?php endif; ?>
        <?php if ($toast_err): ?>
          <div class="error"><?= h($toast_err) ?></div>
        <?php endif; ?>
      </div>

      <form method="POST" autocomplete="off">
        <input type="hidden" name="csrf" value="<?= h($CSRF) ?>">

        <div class="field">
          <label for="u"><?= t('label_username') ?></label>
          <input id="u" type="text" name="username" placeholder="<?= t('placeholder_username_register') ?>" value="<?= h($saved_username) ?>" required autofocus />
        </div>
        <div class="field">
          <label for="p1"><?= t('label_password') ?></label>
          <input id="p1" type="password" name="password" placeholder="<?= t('placeholder_password_min') ?>" required />
        </div>
        <div class="field">
          <label for="p2"><?= t('label_password_repeat') ?></label>
          <input id="p2" type="password" name="password2" placeholder="<?= t('placeholder_password_repeat') ?>" required />
        </div>

        <label class="checkRow">
          <input type="checkbox" name="save_username" value="1" <?= $save_username_checked ? 'checked' : '' ?> />
          <span><?= t('btn_save_username') ?></span>
        </label>
        <button class="btn" type="submit"><?= t('btn_create_account') ?></button>
      </form>

      <a class="btnGhost" href="login.php"><?= t('link_have_account') ?></a>
    </div>
  </div>
  <script>
    document.addEventListener('keydown', function(e) {
      if (e.key === 'Escape') document.getElementById('langSheetWrap').classList.remove('show');
    });
  </script>
</body>
</html>

