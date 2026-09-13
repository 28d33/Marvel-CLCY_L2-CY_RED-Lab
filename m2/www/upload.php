<?php
// upload handler - no validation of name or type (the vulnerability).
$dir  = __DIR__ . '/uploads';
$msg  = '';
$done = false;
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['upload'])) {
    $f = $_FILES['upload'];
    if ($f['error'] === UPLOAD_ERR_OK) {
        $dest = $dir . '/' . basename($f['name']);
        if (move_uploaded_file($f['tmp_name'], $dest)) {
            $msg  = "stored: " . basename($dest);
            $done = true;
        } else {
            $msg = "move_uploaded_file failed";
        }
    } else {
        $msg = "upload error " . $f['error'];
    }
}
?>
<!DOCTYPE html>
<html><head><title>JumpWeb - upload</title>
<style>body{font-family:monospace;background:#102;color:#cfc;margin:3em}
pre{background:#000;padding:1em;border:1px solid #060}
a{color:#8f8}</style></head><body>
<h1>JumpWeb &mdash; upload</h1>
<?php if ($done): ?><pre><?= htmlspecialchars($msg) ?></pre>
<p>run it: <a href="uploads/<?= htmlspecialchars($dest) ?>">uploads/<?= htmlspecialchars($dest) ?></a></p>
<?php elseif ($msg): ?><pre><?= htmlspecialchars($msg) ?></pre>
<?php endif; ?>
<form action="upload.php" method="post" enctype="multipart/form-data">
  File: <input type="file" name="upload">
  <button>Upload</button>
</form>
<p><a href="index.php">back to index</a></p>
</body></html>