<?php
require __DIR__ . '/config.php';

// Entry point molto semplice:
// - se l'utente è loggato va alla rubrica
// - altrimenti va alla pagina di login

if (current_user()) {
  header("Location: app.php");
} else {
  header("Location: login.php");
}
exit();