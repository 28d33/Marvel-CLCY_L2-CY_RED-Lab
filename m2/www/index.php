<?php
// m2 "jumpweb" - deliberately vulnerable upload directory.
// No filtering on purpose: any file (including *something*.php) is accepted
// and re-served by PHP, so an uploaded PHP "tool" runs directly.
$list = glob(__DIR__ . '/uploads/*');
sort($list);
?>
<!DOCTYPE html>
<html><head><title>JumpWeb - internal file drop</title>
<style>body{font-family:monospace;background:#102;color:#cfc;margin:3em}
pre{background:#000;padding:1em;border:1px solid #060}
a{color:#8f8}</style></head><body>
<h1>JumpWeb &mdash; internal file drop</h1>
<p>Drop files into <code>uploads/</code>. PHP-enabled hosts run the files they host.</p>
<?php if (!$list): ?>
<p><em>no files uploaded yet</em></p>
<?php else: ?>
<ul><?php foreach ($list as $f): $n = basename($f); ?>
  <li><a href="uploads/<?= $n ?>"><?= $n ?></a> (<?= filesize($f) ?> bytes)</li>
<?php endforeach; ?></ul>
<?php endif; ?>
<hr>
<form action="upload.php" method="post" enctype="multipart/form-data">
  File: <input type="file" name="upload">
  <button>Upload</button>
</form>
</body></html>