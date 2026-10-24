"""微信小程序解包工具（GUI + CLI）

适配微信 PC 端 3.x / 4.0 / 4.1.x 的小程序缓存目录：

    3.x     ~/Documents/WeChat Files/Applet/<AppID>/<版本号>/
    4.0     %APPDATA%/Tencent/xwechat/radium/Applet/packages/<AppID>/<版本号>/
    4.1.x   %APPDATA%/Tencent/xwechat/radium/users/<账号>/applet/packages/<AppID>/<版本号>/

PC 端的包是加密的，结构为：
    b"V1MMWX" + AES-256-CBC(头部 1024 字节) + 余下部分按 appid[-2] 逐字节异或
密钥由 AppID 派生：PBKDF2(appid, b"saltiest", 1000, 32)，IV 固定为 b"the iv: 16 bytes"。
解密后是标准 wxapkg：0xBE 开头、0xED 结尾、大端索引表。

命令行用法：
    python wxapkg_gui.py                        # 启动图形界面
    python wxapkg_gui.py scan                   # 扫描本机所有候选目录
    python wxapkg_gui.py scan <目录> --json     # 扫描指定目录并输出 JSON
    python wxapkg_gui.py unpack <目录或包文件> -o <输出目录>
"""

from __future__ import annotations

import argparse
import io
import json
import os
import queue
import re
import struct
import sys
import threading
import time
from urllib.parse import unquote

# ---------------------------------------------------------------- 依赖导入

try:
    from Crypto.Cipher import AES
    from Crypto.Hash import SHA1
    from Crypto.Protocol.KDF import PBKDF2

    HAS_CRYPTO = True
except ImportError:  # 缺 pycryptodome 时只有解密不可用，其余功能仍能跑
    AES = None
    PBKDF2 = None
    SHA1 = None
    HAS_CRYPTO = False

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, simpledialog, ttk

    HAS_TK = True
except Exception:  # 无图形环境（纯 CLI 场景）时不影响命令行功能
    tk = None
    ttk = None
    filedialog = None
    messagebox = None
    simpledialog = None
    HAS_TK = False


# ---------------------------------------------------------------- 常量

APP_NAME = "微信小程序解包工具"
APP_VERSION = "2.0"

ENC_MAGIC = b"V1MMWX"          # PC 端加密包的文件头
MAGIC_LEN = 6
HEADER_CIPHER_BYTES = 1024     # 加密的头部长度
PBKDF2_SALT = b"saltiest"
PBKDF2_ITERATIONS = 1000
AES_KEY_LEN = 32               # AES-256
AES_IV = b"the iv: 16 bytes"

PKG_FIRST_MARK = 0xBE          # 明文 wxapkg 首字节
PKG_LAST_MARK = 0xED           # 明文 wxapkg 第 14 字节

APPID_PATTERN = re.compile(r"(wx[0-9a-f]{16})")
VERSION_PATTERN = re.compile(r"^\d{1,6}$")

# 常见的分包 / 插件包命名前缀，用于展示层面归类
ROLE_LABELS = {
    "__APP__": "主包",
    "__WITHOUT_MULTI_PLUGINCODE__": "插件代码(无多包)",
}

JSON_CACHE_FILE = "wxid.json"

# 联网查询小程序名称的接口（可选功能，失败即降级为 appid）
INFO_API = "https://kainy.cn/api/weapp/info/"


class WxapkgError(Exception):
    """解包 / 解密过程中的可预期错误。"""


class DecryptError(WxapkgError):
    """解密失败。"""


# ---------------------------------------------------------------- 核心：解密

def derive_key(appid: str) -> bytes:
    """由 AppID 派生 AES 密钥（PBKDF2-HMAC-SHA1，1000 轮，32 字节）。"""
    if not HAS_CRYPTO:
        raise DecryptError("缺少 pycryptodome，请先执行：pip install pycryptodome")
    return PBKDF2(
        appid.encode("utf-8"),
        PBKDF2_SALT,
        dkLen=AES_KEY_LEN,
        count=PBKDF2_ITERATIONS,
        hmac_hash_module=SHA1,
    )


def xor_bytes(data: bytes, key: int) -> bytes:
    """整段按单字节异或；用大整数一次算完，比逐字节循环快一个量级。"""
    if not data:
        return b""
    if not 0 <= key <= 0xFF:
        raise DecryptError(f"异或密钥越界: {key}")
    chunk = int.from_bytes(data, "big")
    mask = int.from_bytes(bytes([key]) * len(data), "big")
    return (chunk ^ mask).to_bytes(len(data), "big")


def is_encrypted(raw: bytes) -> bool:
    """判断包是否为 PC 端加密格式（V1MMWX 头）。"""
    return raw[:MAGIC_LEN] == ENC_MAGIC


def is_plain_wxapkg(raw: bytes) -> bool:
    """判断数据是否已经是明文 wxapkg。"""
    return len(raw) >= 14 and raw[0] == PKG_FIRST_MARK and raw[13] == PKG_LAST_MARK


def decrypt_payload(raw: bytes, appid: str) -> bytes:
    """把（可能的）加密包转成明文 wxapkg；明文包原样返回。

    加密方案：
        密文 = b"V1MMWX" + AES-CBC 前 1024 字节 + 其余按 appid[-2] 异或
        明文 = 解出的前 1023 字节 + 异或后的剩余部分
    """
    if not raw:
        raise WxapkgError("空文件")
    if not is_encrypted(raw):
        # 明文包直接透传；既不是加密也不是明文的，交给上层报错
        return raw
    if not appid or not APPID_PATTERN.match(appid):
        raise DecryptError(f"AppID 无效：{appid!r}（解密必须使用 18 位 appid）")
    if len(raw) < MAGIC_LEN + HEADER_CIPHER_BYTES:
        raise DecryptError(
            f"文件太小（{len(raw)} 字节），不足加密头 {MAGIC_LEN + HEADER_CIPHER_BYTES} 字节"
        )

    key = derive_key(appid)
    cipher = AES.new(key, AES.MODE_CBC, AES_IV)
    header = cipher.decrypt(raw[MAGIC_LEN:MAGIC_LEN + HEADER_CIPHER_BYTES])
    xor_key = ord(appid[-2])
    body = xor_bytes(raw[MAGIC_LEN + HEADER_CIPHER_BYTES:], xor_key)
    plain = header[:HEADER_CIPHER_BYTES - 1] + body

    if not is_plain_wxapkg(plain):
        raise DecryptError(
            "解密后校验失败：首字节 {:02x}，第 14 字节 {:02x}（期望 be/ed）。"
            "通常是 AppID 不匹配，或该版本微信已改用其他加密方案。".format(
                plain[0] if plain else 0, plain[13] if len(plain) > 13 else 0
            )
        )
    return plain


# ---------------------------------------------------------------- 核心：解析与写盘

def parse_index(payload: bytes) -> tuple[list[tuple[str, int, int]], int, int]:
    """解析 wxapkg 索引表，返回 ([(文件名, 偏移, 大小)], 索引长度, 数据长度)。"""
    if len(payload) < 18:
        raise WxapkgError(f"wxapkg 数据不完整（{len(payload)} 字节）")
    if not is_plain_wxapkg(payload):
        raise WxapkgError(
            "不是有效的 wxapkg：首字节 {:02x}，第 14 字节 {:02x}".format(
                payload[0], payload[13]
            )
        )

    index_len = struct.unpack(">L", payload[5:9])[0]
    body_len = struct.unpack(">L", payload[9:13])[0]
    pos = 14
    if len(payload) < pos + 4:
        raise WxapkgError("索引表被截断")
    count = struct.unpack(">L", payload[pos:pos + 4])[0]
    pos += 4

    files: list[tuple[str, int, int]] = []
    for i in range(count):
        if pos + 4 > len(payload):
            raise WxapkgError(f"索引表在第 {i} 项处被截断")
        name_len = struct.unpack(">L", payload[pos:pos + 4])[0]
        pos += 4
        if pos + name_len + 8 > len(payload):
            raise WxapkgError(f"索引表在第 {i} 项的名字/偏移处被截断")
        name = payload[pos:pos + name_len].decode("utf-8", "replace")
        pos += name_len
        offset, size = struct.unpack(">LL", payload[pos:pos + 8])
        pos += 8
        files.append((name, offset, size))
    return files, index_len, body_len


def safe_relpath(name: str) -> str:
    """把包内路径规范成安全的相对路径，挡掉 ../ 之类的目录穿越。"""
    raw = name.replace("\\", "/")
    parts = [p for p in raw.split("/") if p not in ("", ".", "..")]
    return "/".join(parts)


def is_game_config(config_bytes: bytes) -> bool:
    """判断 app-config.json 是否属于小游戏（只认强特征，避免误改小程序配置名）。"""
    try:
        start = config_bytes.index(b"{")
        end = config_bytes.rindex(b"}") + 1
        cfg = json.loads(config_bytes[start:end].decode("utf-8", "replace"))
    except Exception:
        return False
    if not isinstance(cfg, dict):
        return False
    return any(k in cfg for k in ("deviceOrientation", "openDataContext", "workers"))


def minify_js(content: bytes) -> bytes:
    """压缩 JS（jsmin 缺失时原样返回）。"""
    try:
        import jsmin

        return jsmin.jsmin(content.decode("utf-8", "replace")).encode("utf-8")
    except Exception:
        return content


def minify_json_bytes(content: bytes) -> bytes:
    """压缩 JSON（解析失败时原样返回）。"""
    try:
        data = json.loads(content.decode("utf-8", "replace"))
        return json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    except Exception:
        return content


def minify_png(content: bytes) -> bytes:
    """用 Pillow 重新压缩 PNG（只有变小才采用）。"""
    try:
        from PIL import Image

        image = Image.open(io.BytesIO(content))
        if image.format != "PNG":
            return content
        out = io.BytesIO()
        image.save(out, format="PNG", optimize=True, compress_level=9)
        compressed = out.getvalue()
        return compressed if len(compressed) < len(content) else content
    except Exception:
        return content


def maybe_compress(path: str, content: bytes, compress_js: bool, compress_png: bool) -> bytes:
    """按扩展名决定是否压缩。"""
    lower = path.lower()
    if compress_js and lower.endswith(".js"):
        return minify_js(content)
    if compress_js and lower.endswith(".json"):
        return minify_json_bytes(content)
    if compress_png and lower.endswith(".png"):
        return minify_png(content)
    return content


def extract_package(
    payload: bytes,
    out_dir: str,
    *,
    compress_js: bool = False,
    compress_png: bool = False,
    on_log=None,
    on_file=None,
) -> dict:
    """把明文 wxapkg 写到 out_dir，返回统计信息。"""
    files, index_len, body_len = parse_index(payload)
    os.makedirs(out_dir, exist_ok=True)

    saved = 0
    skipped = 0
    truncated = 0
    renamed_game = 0
    total = len(files)

    for i, (name, offset, size) in enumerate(files, 1):
        rel = safe_relpath(name)
        if not rel:
            skipped += 1
            continue
        data = payload[offset:offset + size]
        if len(data) != size:
            truncated += 1
            if on_log:
                on_log(f"警告：{name} 数据不完整（预期 {size}，实际 {len(data)}）")

        # app-config.json 属于小游戏时改名为 game.json（沿用原工具行为）
        if os.path.basename(rel) == "app-config.json" and is_game_config(data):
            rel = rel[: -len("app-config.json")] + "game.json"
            renamed_game += 1

        target = os.path.join(out_dir, *rel.split("/"))
        data = maybe_compress(target, data, compress_js, compress_png)
        try:
            parent = os.path.dirname(target)
            if parent:
                os.makedirs(parent, exist_ok=True)
            with open(target, "wb") as f:
                f.write(data)
            saved += 1
        except OSError as exc:
            skipped += 1
            if on_log:
                on_log(f"写入失败 {rel}：{exc}")
        if on_file:
            on_file(i, total, rel)

    return {
        "files": total,
        "saved": saved,
        "skipped": skipped,
        "truncated": truncated,
        "renamed_game": renamed_game,
        "index_len": index_len,
        "body_len": body_len,
    }


# ---------------------------------------------------------------- 核心：目录扫描

def role_of(filename: str) -> str:
    """根据包文件名给出人类可读的角色说明。"""
    stem = os.path.splitext(os.path.basename(filename))[0]
    if stem in ROLE_LABELS:
        return ROLE_LABELS[stem]
    if stem.startswith("_subpackages_"):
        return "分包：" + stem[len("_subpackages_"):].strip("_")
    if stem.startswith("_packages_"):
        return "分包：" + stem[len("_packages_"):].lstrip("_-")
    if "PLUGINCODE" in stem.upper():
        return "插件代码"
    if "wasm" in stem.lower():
        return "WASM 模块"
    return stem


def guess_appid(path: str) -> str:
    """从路径里提取 AppID（目录名或文件名中的 wx + 16 位十六进制）。"""
    m = APPID_PATTERN.search(path.replace("\\", "/"))
    return m.group(1) if m else ""


def guess_version(path: str, appid: str = "") -> str:
    """从路径里取 AppID 之后的第一段纯数字目录作为版本号。"""
    parts = [p for p in path.replace("\\", "/").split("/") if p]
    start = 0
    if appid:
        for i, part in enumerate(parts):
            if appid in part:
                start = i + 1
                break
    for part in parts[start:]:
        if VERSION_PATTERN.match(part):
            return part
    return ""


class PackageInfo:
    """一个 .wxapkg 文件的元信息。"""

    __slots__ = ("path", "appid", "version", "size", "encrypted", "mtime", "title", "icon")

    def __init__(self, path: str, appid: str, version: str, size: int, encrypted: bool, mtime: float):
        self.path = path
        self.appid = appid
        self.version = version
        self.size = size
        self.encrypted = encrypted
        self.mtime = mtime
        self.title = ""   # 从包内 project 配置读到的名称（可能为空）
        self.icon = ""    # applet/icon 下的图标路径（可能为空）

    @property
    def name(self) -> str:
        return os.path.basename(self.path)

    @property
    def role(self) -> str:
        return role_of(self.path)

    @property
    def stem(self) -> str:
        return os.path.splitext(self.name)[0]

    def __repr__(self) -> str:  # 便于调试
        return f"<PackageInfo {self.appid}/{self.version}/{self.name} {self.size}B>"


def probe_encrypted(path: str) -> bool:
    """读前 6 字节判断是否加密包。"""
    try:
        with open(path, "rb") as f:
            return f.read(MAGIC_LEN) == ENC_MAGIC
    except OSError:
        return False


def find_packages(root: str, *, follow_links: bool = False) -> list[PackageInfo]:
    """递归扫描 root 下所有 .wxapkg，不依赖具体目录层级。"""
    if not os.path.isdir(root):
        raise WxapkgError(f"目录不存在：{root}")
    found: list[PackageInfo] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=follow_links):
        for filename in filenames:
            if not filename.lower().endswith(".wxapkg"):
                continue
            full = os.path.join(dirpath, filename)
            try:
                st = os.stat(full)
            except OSError:
                continue
            appid = guess_appid(full)
            found.append(
                PackageInfo(
                    path=full,
                    appid=appid,
                    version=guess_version(full, appid),
                    size=st.st_size,
                    encrypted=probe_encrypted(full),
                    mtime=st.st_mtime,
                )
            )
    found.sort(key=lambda p: (p.appid, p.version, p.name))
    return found


def candidate_roots() -> list[tuple[str, str]]:
    """返回本机可能存在的小程序缓存根目录 [(说明, 路径)]，只列存在的。"""
    home = os.path.expanduser("~")
    appdata = os.environ.get("APPDATA", os.path.join(home, "AppData", "Roaming"))
    cands = [
        ("微信 4.1.x（多账号）", os.path.join(appdata, "Tencent", "xwechat", "radium", "users")),
        ("微信 4.0", os.path.join(appdata, "Tencent", "xwechat", "radium", "Applet")),
        ("微信 4.x 数据目录", os.path.join(home, "Documents", "xwechat_files")),
        ("微信 3.x", os.path.join(home, "Documents", "WeChat Files", "Applet")),
    ]
    return [(label, path) for label, path in cands if os.path.isdir(path)]


def default_output_root() -> str:
    """默认输出根目录：优先当前工作目录下的 unpack。"""
    return os.path.join(os.getcwd(), "unpack")


def app_dir() -> str:
    """程序所在目录；PyInstaller 单文件模式下返回 exe 目录（而非临时解包目录）。"""
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


def data_dir() -> str:
    """运行期数据目录（缓存、上次扫描路径）。

    源码运行写在项目目录，便于查看；打包成 exe 后写 %LOCALAPPDATA%\\wxapkg_gui，
    避免 exe 被放进 Program Files 之类不可写目录时缓存失效。
    """
    if not getattr(sys, "frozen", False):
        return app_dir()
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    target = os.path.join(base, "wxapkg_gui")
    try:
        os.makedirs(target, exist_ok=True)
        probe = os.path.join(target, ".write_probe")
        with open(probe, "w", encoding="utf-8") as f:
            f.write("ok")
        os.remove(probe)
        return target
    except Exception:
        return app_dir()


def package_output_dir(out_root: str, pkg: PackageInfo, flat: bool) -> str:
    """计算单个包的输出目录。

    flat=True  -> 全部平铺到 out_root（多包会互相覆盖）
    flat=False -> out_root/<appid>/<version>/<包名>
    """
    if flat:
        return out_root
    appid = pkg.appid or "unknown_appid"
    version = pkg.version or "0"
    return os.path.join(out_root, appid, version, pkg.stem)


def human_size(size: int) -> str:
    """字节数转可读字符串。"""
    value = float(size)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.1f}{unit}" if unit != "B" else f"{int(value)}B"
        value /= 1024
    return f"{size}B"


# ---------------------------------------------------------------- 联网信息（可选）

class InfoCache:
    """appid -> {nickname, principal_name, description, local_title, title_source} 的本地缓存。"""

    def __init__(self, path: str = JSON_CACHE_FILE):
        self.path = path
        self.data: dict[str, dict] = {}
        self.dirty = False
        self.load()

    def load(self) -> None:
        try:
            if os.path.exists(self.path):
                with open(self.path, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                if isinstance(loaded, dict):
                    self.data = loaded
                    # 旧版本写进去的标题（可能带 minigame- 前缀）在这里修正
                    for info in self.data.values():
                        raw = info.get("local_title")
                        if raw:
                            fixed = clean_title(raw)
                            if fixed != raw:
                                info["local_title"] = fixed
                                self.dirty = True
        except Exception:
            self.data = {}

    def save(self) -> None:
        if not self.dirty:
            return
        # 写盘前把标题规范一遍，保证缓存文件里也是清洗后的名字
        for info in self.data.values():
            raw = info.get("local_title")
            if raw:
                info["local_title"] = clean_title(raw) or ""
        try:
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self.data, f, ensure_ascii=False, indent=2)
            self.dirty = False
        except Exception:
            pass

    def get(self, appid: str) -> dict | None:
        return self.data.get(appid)

    def nickname(self, appid: str) -> str:
        info = self.data.get(appid)
        return (info or {}).get("nickname") or appid

    # ---------- 本地标题（从包内 project 配置读出来的名字） ----------

    def get_title(self, appid: str) -> str:
        """返回本地探测到的标题；没有则空串。旧缓存也会重新清洗一遍。"""
        raw = (self.data.get(appid) or {}).get("local_title") or ""
        return clean_title(raw) if raw else ""

    def set_title(self, appid: str, title: str, source: str = "") -> None:
        title = clean_title(title)
        if not title:
            return
        info = self.data.setdefault(
            appid,
            {
                "wxid": appid,
                "nickname": appid,
                "principal_name": "未知开发者",
                "description": "",
            },
        )
        info["local_title"] = title
        info["title_source"] = source
        self.dirty = True

    def display_title(self, appid: str) -> str:
        """展示用标题：联网昵称优先，其次包内 projectname，最后空。"""
        info = self.data.get(appid) or {}
        nick = info.get("nickname") or ""
        if nick and nick != appid:
            return nick
        return clean_title(info.get("local_title") or "")

    def fetch(self, appid: str, timeout: float = 6.0) -> dict:
        """联网查询；失败返回占位信息。结果合并回缓存（不丢本地标题）。"""
        cached = self.data.get(appid) or {}
        if cached.get("nickname") and cached.get("nickname") != appid:
            return cached
        result = {
            "wxid": appid,
            "nickname": appid,
            "principal_name": "未知开发者",
            "description": "无法获取小程序信息",
        }
        try:
            import requests

            resp = requests.post(
                INFO_API,
                json={"appid": appid},
                headers={
                    "Content-Type": "application/json;charset=utf-8",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                },
                timeout=timeout,
            )
            if resp.status_code == 200:
                payload = resp.json()
                if payload.get("code") == 0:
                    info = payload.get("data") or {}
                    result = {
                        "wxid": appid,
                        "nickname": info.get("nickname") or appid,
                        "principal_name": info.get("principal_name") or "未知开发者",
                        "description": info.get("description") or "无描述信息",
                    }
        except Exception:
            pass
        merged = dict(cached)
        merged.update(result)
        self.data[appid] = merged
        self.dirty = True
        return merged


# ---------------------------------------------------------------- 标题与图标探测

# projectname 常是开发者工具的脚手架默认名，对用户没有意义
TITLE_BLACKLIST = {
    "mp-weixin",
    "mp-weixin-1",
    "miniprogram",
    "miniprogram-1",
    "miniprogram-2",
    "project",
    "wxapp",
    "wechat",
    "unnamed",
    "untitled",
    "test",
    "demo",
    "my-project",
    "quickstart",
    "hello",
    "app",
}


def clean_title(raw: str) -> str:
    """清洗 projectname：URL 解码、去脚手架前缀、过滤默认名与超长串。"""
    if not raw:
        return ""
    try:
        text = unquote(str(raw)).strip()
    except Exception:
        text = str(raw).strip()
    text = re.sub(r"\s+", " ", text)
    # 开发者工具常见前缀：minigame-、miniprogram-、mp- 等
    text = re.sub(r"^(?:minigame|mini-game|miniprogram|mini-program|mp)[-_：: ]+", "", text, flags=re.I).strip()
    if not text or len(text) > 40:
        return ""
    if text.lower() in TITLE_BLACKLIST:
        return ""
    # 纯 ASCII 的英文项目名多半也是脚手架留下的，不当作小程序名
    if text.isascii() and " " not in text and len(text) <= 12:
        return ""
    return text


# 这些文件里可能带小程序/小游戏名称（微信开发者工具的工程配置）
TITLE_SOURCE_FILES = ("project.private.config.json", "project.config.json")


def read_package_title(pkg: PackageInfo, appid_override: str = "") -> tuple[str, str]:
    """解密包后只读工程配置文件，取小程序名称，返回 (标题, 字段名)。

    实测：app-config.json / game.json / app.json 都不含昵称，只有
    project*.config.json 的 projectname 带名字（常为 URL 编码）。
    """
    appid = appid_override or pkg.appid
    try:
        with open(pkg.path, "rb") as f:
            raw = f.read()
        plain = decrypt_payload(raw, appid)
        files, _, _ = parse_index(plain)
    except Exception:
        return "", ""
    for name, offset, size in files:
        base = os.path.basename(name).lower()
        if base not in TITLE_SOURCE_FILES:
            continue
        if size <= 0 or size > 512_000:
            continue
        try:
            cfg = json.loads(plain[offset:offset + size].decode("utf-8", "replace").lstrip("\ufeff"))
        except Exception:
            continue
        if not isinstance(cfg, dict):
            continue
        for key in ("projectname", "projectName", "name"):
            title = clean_title(cfg.get(key) or "")
            if title:
                return title, key
    return "", ""


def find_icon(appid: str, start_dirs: list[str] | None = None) -> str:
    """找小程序图标：applet/icon/<appid>_<hash>.png。找不到返回空串。"""
    if not appid:
        return ""
    roots: list[str] = []
    for start in start_dirs or []:
        cur = os.path.abspath(start)
        for _ in range(5):
            roots.append(cur)
            parent = os.path.dirname(cur)
            if parent == cur:
                break
            cur = parent

    home = os.path.expanduser("~")
    appdata = os.environ.get("APPDATA", os.path.join(home, "AppData", "Roaming"))
    xwechat = os.path.join(appdata, "Tencent", "xwechat", "radium")
    roots += [os.path.join(xwechat, "Applet"), xwechat]
    users_dir = os.path.join(xwechat, "users")
    try:
        for entry in os.listdir(users_dir):
            roots.append(os.path.join(users_dir, entry, "applet"))
    except OSError:
        pass

    seen: set[str] = set()
    prefix = appid + "_"
    for root in roots:
        if root in seen:
            continue
        seen.add(root)
        icon_dir = os.path.join(root, "icon")
        if not os.path.isdir(icon_dir):
            continue
        try:
            for filename in os.listdir(icon_dir):
                if filename.startswith(prefix) and filename.lower().endswith(".png"):
                    return os.path.join(icon_dir, filename)
        except OSError:
            continue
    return ""


# ---------------------------------------------------------------- 解包流程（GUI/CLI 共用）

def unpack_one(
    pkg: PackageInfo,
    out_dir: str,
    *,
    appid_override: str = "",
    allow_decrypt: bool = True,
    compress_js: bool = False,
    compress_png: bool = False,
    on_log=None,
    on_file=None,
) -> dict:
    """解密 + 解包单个包，返回统计信息（含明文大小与是否解密）。"""
    log = on_log or (lambda msg: None)
    appid = appid_override or pkg.appid
    with open(pkg.path, "rb") as f:
        raw = f.read()
    log(f"读取 {pkg.name}（{human_size(len(raw))}，加密={is_encrypted(raw)}）")

    if is_encrypted(raw) and not allow_decrypt:
        raise DecryptError("该包是加密的，但已禁用解密（--no-decrypt）")

    plain = decrypt_payload(raw, appid)
    decrypted = plain is not raw and not plain == raw
    if decrypted:
        log(f"解密成功，明文 {human_size(len(plain))}")
    elif not is_plain_wxapkg(plain):
        raise WxapkgError("数据既不是加密包也不是有效 wxapkg")

    stats = extract_package(
        plain,
        out_dir,
        compress_js=compress_js,
        compress_png=compress_png,
        on_log=log,
        on_file=on_file,
    )
    stats.update(
        {
            "name": pkg.name,
            "appid": appid,
            "version": pkg.version,
            "role": pkg.role,
            "encrypted": is_encrypted(raw),
            "decrypted": decrypted,
            "plain_size": len(plain),
            "out_dir": out_dir,
        }
    )
    return stats


# ---------------------------------------------------------------- 图形界面

class WxapkgUnpacker:
    """主窗口。手动指定目录 → 递归扫描 → 多选批量解包。"""

    def __init__(self, root):
        self.root = root
        self.root.title(f"{APP_NAME} v{APP_VERSION}")
        self._fit_to_screen(1440, 900)

        self.packages: list[PackageInfo] = []
        self._ui_queue: queue.Queue = queue.Queue()
        self.iid_map: dict[str, PackageInfo] = {}
        self._icons: dict[str, object] = {}      # appid -> PhotoImage（必须持有引用）
        self._icon_paths: dict[str, str] = {}    # appid -> 图标文件路径
        self._probed: set[str] = set()           # 已尝试读取过标题的 appid
        self._scan_root = ""
        self.cache = InfoCache(os.path.join(data_dir(), JSON_CACHE_FILE))
        self.default_scan_dir = self._initial_scan_dir()
        self.last_dir_file = os.path.join(data_dir(), ".last_scan_dir")

        self._build_ui()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.log("提示：先用微信打开目标小程序，让客户端把包缓存到本地，再在这里选择目录。")
        self.log(f"本机探测到的候选目录 {len(candidate_roots())} 个，可直接从下拉框跳转。")

    # ---------- 界面搭建 ----------

    def _ui_scale(self) -> float:
        """当前 DPI 相对 100% 缩放的倍率（150% 缩放返回 1.5）。"""
        try:
            scaling = float(self.root.tk.call("tk", "scaling"))
        except Exception:
            return 1.0
        factor = scaling / (96.0 / 72.0)
        return factor if factor > 0.5 else 1.0

    def _fit_to_screen(self, want_w: int, want_h: int) -> None:
        """按屏幕尺寸与 DPI 缩放自适应窗口大小并居中。"""
        try:
            sw = self.root.winfo_screenwidth()
            sh = self.root.winfo_screenheight()
            scaling = float(self.root.tk.call("tk", "scaling"))
        except Exception:
            self.root.geometry(f"{want_w}x{want_h}")
            return
        # tk 的 scaling 以 72dpi 为基准；96dpi（100% 缩放）时约 1.333
        factor = scaling / (96.0 / 72.0) if scaling > 0 else 1.0
        width = min(int(want_w * factor), int(sw * 0.94))
        height = min(int(want_h * factor), int(sh * 0.90))
        x = max(0, (sw - width) // 2)
        y = max(0, (sh - height) // 2 - int(24 * factor))
        self.root.geometry(f"{width}x{height}+{x}+{y}")
        self.root.minsize(int(1024 * factor), int(600 * factor))

    def _initial_scan_dir(self) -> str:
        roots = candidate_roots()
        if roots:
            return roots[0][1]
        return os.path.join(os.path.expanduser("~"), "Documents")

    def _build_ui(self) -> None:
        style = ttk.Style()
        try:
            style.theme_use("vista")
        except Exception:
            pass

        # --- 顶部工具栏 ---
        toolbar = ttk.Frame(self.root)
        toolbar.pack(fill=tk.X, padx=8, pady=(8, 4))

        ttk.Button(toolbar, text="选择小程序目录", command=self.choose_dir).pack(side=tk.LEFT)
        self.unpack_btn = ttk.Button(
            toolbar, text="解包选中", command=self.unpack_selected, state=tk.DISABLED
        )
        self.unpack_btn.pack(side=tk.LEFT, padx=6)
        ttk.Button(toolbar, text="重新扫描", command=self.rescan).pack(side=tk.LEFT)
        ttk.Button(toolbar, text="打开输出目录", command=self.open_output_dir).pack(side=tk.LEFT, padx=6)
        ttk.Button(toolbar, text="指定 AppID", command=self.set_appid_dialog).pack(side=tk.LEFT)

        ttk.Label(toolbar, text="候选路径:").pack(side=tk.LEFT, padx=(16, 4))
        self._roots = candidate_roots()
        self.roots_combo = ttk.Combobox(toolbar, width=24, state="readonly")
        self.roots_combo["values"] = [label for label, _ in self._roots]
        if self._roots:
            self.roots_combo.current(0)
        self.roots_combo.pack(side=tk.LEFT)
        ttk.Button(toolbar, text="跳转", command=self.jump_to_root).pack(side=tk.LEFT, padx=4)
        self.root_path_var = tk.StringVar(value=self._short_path(self._roots[0][1] if self._roots else "未探测到缓存目录"))
        ttk.Label(toolbar, textvariable=self.root_path_var, anchor=tk.W).pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=(4, 0)
        )

        # --- 选项栏 ---
        opt = ttk.Frame(self.root)
        opt.pack(fill=tk.X, padx=8, pady=2)
        self.auto_title_var = tk.BooleanVar(value=False)
        self.js_var = tk.BooleanVar(value=False)
        self.png_var = tk.BooleanVar(value=False)
        self.split_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            opt,
            text="扫描时读取全部标题（每个包解密一次）",
            variable=self.auto_title_var,
        ).pack(side=tk.LEFT)
        ttk.Checkbutton(opt, text="压缩 JS/JSON", variable=self.js_var).pack(side=tk.LEFT, padx=(12, 0))
        ttk.Checkbutton(opt, text="压缩 PNG", variable=self.png_var).pack(side=tk.LEFT, padx=(12, 0))
        ttk.Checkbutton(
            opt, text="每个包独立子目录（推荐）", variable=self.split_var
        ).pack(side=tk.LEFT, padx=(12, 0))
        ttk.Button(opt, text="重命名（F2）", command=self.rename_selected).pack(side=tk.RIGHT)

        # --- 主体 ---
        body = self._body = ttk.Panedwindow(self.root, orient=tk.HORIZONTAL)
        body.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)

        left = ttk.Frame(body)
        body.add(left, weight=3)

        columns = ("title", "name", "appid", "version", "role", "size", "state")
        # 用 tree headings 才能显示每行前面的图标（#0 列）
        self.tree = ttk.Treeview(
            left, columns=columns, show="tree headings", selectmode="extended"
        )
        scale = self._ui_scale()
        self.tree.heading("#0", text="")
        self.tree.column("#0", width=int(30 * scale), minwidth=int(30 * scale), stretch=False)
        headings = {
            "title": ("标题", 140),
            "name": ("包文件名", 250),
            "appid": ("AppID", 165),
            "version": ("版本", 50),
            "role": ("类型", 130),
            "size": ("大小", 75),
            "state": ("加密", 50),
        }
        left_cols = ("title", "name", "appid", "role")
        for key, (text, width) in headings.items():
            self.tree.heading(key, text=text)
            self.tree.column(
                key,
                width=int(width * scale),
                minwidth=int(width * 0.5 * scale),
                anchor=tk.W if key in left_cols else tk.CENTER,
            )
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        tree_scroll = ttk.Scrollbar(left, orient=tk.VERTICAL, command=self.tree.yview)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.configure(yscrollcommand=tree_scroll.set)
        self.tree.bind("<<TreeviewSelect>>", self.on_select)
        self.tree.bind("<Double-1>", lambda _e: self.rename_selected())
        self.tree.bind("<F2>", lambda _e: self.rename_selected())

        right = ttk.Frame(body)
        body.add(right, weight=2)

        out_frame = ttk.Frame(right)
        out_frame.pack(fill=tk.X, pady=(0, 4))
        ttk.Label(out_frame, text="输出目录:").pack(side=tk.LEFT)
        self.output_entry = ttk.Entry(out_frame)
        self.output_entry.insert(0, default_output_root())
        self.output_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        ttk.Button(out_frame, text="浏览", command=self.browse_output).pack(side=tk.RIGHT)

        self.notebook = ttk.Notebook(right)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        detail_page = ttk.Frame(self.notebook)
        self.notebook.add(detail_page, text="详情")
        self.detail_text = tk.Text(detail_page, wrap=tk.WORD, height=12)
        self.detail_text.pack(fill=tk.BOTH, expand=True)

        log_page = ttk.Frame(self.notebook)
        self.notebook.add(log_page, text="日志")
        self.log_text = tk.Text(log_page, wrap=tk.WORD, height=12)
        self.log_text.pack(fill=tk.BOTH, expand=True)

        # --- 底部状态 ---
        bottom = ttk.Frame(self.root)
        bottom.pack(fill=tk.X, padx=8, pady=(4, 8))
        self.progress = ttk.Progressbar(bottom, orient=tk.HORIZONTAL, mode="determinate")
        self.progress.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.status_var = tk.StringVar(value="就绪")
        ttk.Label(bottom, textvariable=self.status_var, width=46, anchor=tk.E).pack(side=tk.RIGHT, padx=(8, 0))

        # 首次打开停在日志页，能看到使用提示；左右按 62/38 分栏
        self.notebook.select(log_page)
        self.root.after(150, self._init_sash)
        self.root.after(60, self._drain_ui_queue)

    def _init_sash(self) -> None:
        try:
            width = self.root.winfo_width()
            if width > 400:
                self._body.sashpos(0, int(width * 0.68))
        except Exception:
            pass

    @staticmethod
    def _short_path(path: str, limit: int = 64) -> str:
        """路径太长时只显示尾部，避免顶部标签撑开布局。"""
        return path if len(path) <= limit else "…" + path[-(limit - 1):]

    # ---------- 跨线程 UI 更新 ----------
    #
    # tkinter 不是线程安全的：后台线程只能往队列里塞回调，由主线程的
    # _drain_ui_queue 统一定时消费。直接在其他线程里调 root.after()
    # 在部分环境下会抛 "main thread is not in main loop"。

    def post(self, func) -> None:
        """把回调投递给主线程执行（可在任意线程调用）。"""
        self._ui_queue.put(func)

    def _drain_ui_queue(self) -> None:
        for _ in range(200):
            try:
                func = self._ui_queue.get_nowait()
            except queue.Empty:
                break
            try:
                func()
            except Exception:
                pass
        self.root.after(60, self._drain_ui_queue)

    # ---------- 小工具 ----------

    def log(self, message: str) -> None:
        """线程安全地写日志。"""
        line = f"[{time.strftime('%H:%M:%S')}] {message}\n"

        def _append():
            self.log_text.insert(tk.END, line)
            self.log_text.see(tk.END)

        self.post(_append)

    def set_status(self, text: str) -> None:
        self.post(lambda: self.status_var.set(text))

    def set_progress(self, value: float) -> None:
        percent = max(0.0, min(1.0, value)) * 100
        self.post(lambda: self.progress.configure(value=percent))

    def _remember_dir(self, path: str) -> None:
        try:
            with open(self.last_dir_file, "w", encoding="utf-8") as f:
                f.write(path)
        except Exception:
            pass

    def _load_remembered_dir(self) -> str:
        try:
            if os.path.exists(self.last_dir_file):
                with open(self.last_dir_file, "r", encoding="utf-8") as f:
                    cached = f.read().strip()
                if cached and os.path.isdir(cached):
                    return cached
        except Exception:
            pass
        return self.default_scan_dir

    # ---------- 目录选择与扫描 ----------

    def choose_dir(self) -> None:
        path = filedialog.askdirectory(
            title="选择小程序缓存目录（可选到 packages / AppID / 版本号任意一层）",
            initialdir=self._load_remembered_dir(),
        )
        if not path:
            return
        self._remember_dir(path)
        self.start_scan(path)

    def jump_to_root(self) -> None:
        """从候选路径下拉框跳到已存在的目录。"""
        if not self._roots:
            messagebox.showinfo("提示", "未探测到常见的小程序缓存目录，请手动选择。")
            return
        index = self.roots_combo.current()
        label, path = self._roots[index if index >= 0 else 0]
        if not os.path.isdir(path):
            messagebox.showerror("错误", f"目录不存在：{path}")
            return
        self.root_path_var.set(self._short_path(path))
        self._remember_dir(path)
        self.start_scan(path)

    def rescan(self) -> None:
        path = self._load_remembered_dir()
        if not os.path.isdir(path):
            self.choose_dir()
            return
        self.start_scan(path)

    def start_scan(self, path: str) -> None:
        self.log(f"开始扫描：{path}")
        self.set_status("扫描中…")
        self.progress.configure(value=0)
        threading.Thread(target=self._scan_worker, args=(path,), daemon=True).start()

    def _scan_worker(self, path: str) -> None:
        try:
            packages = find_packages(path)
        except Exception as exc:
            # 异常变量在 except 块结束后会被清除，闭包必须先绑定成默认参数
            self.post(lambda msg=str(exc): messagebox.showerror("扫描错误", msg))
            self.set_status("扫描失败")
            return
        self.post(lambda: self._fill_tree(packages, path))

    def _fill_tree(self, packages: list[PackageInfo], path: str) -> None:
        self.packages = packages
        self._scan_root = path
        self.iid_map.clear()
        self.tree.delete(*self.tree.get_children())

        # 同一 appid 只加载一次图标
        icon_cache: dict[str, object] = {}
        for idx, pkg in enumerate(packages):
            iid = str(idx)
            self.iid_map[iid] = pkg
            pkg.title = self.cache.display_title(pkg.appid) if pkg.appid else ""
            photo = None
            if pkg.appid:
                if pkg.appid not in icon_cache:
                    icon_cache[pkg.appid] = self._load_icon(pkg.appid, path)
                photo = icon_cache[pkg.appid]
                pkg.icon = self._icon_paths.get(pkg.appid, "")
            self.tree.insert(
                "",
                "end",
                iid=iid,
                text="",
                image=photo if photo is not None else "",
                values=(
                    pkg.title,
                    pkg.name,
                    pkg.appid or "（未识别）",
                    pkg.version or "-",
                    pkg.role,
                    human_size(pkg.size),
                    "是" if pkg.encrypted else "否",
                ),
            )
        total_size = sum(p.size for p in packages)
        self.log(f"扫描完成：{len(packages)} 个包，合计 {human_size(total_size)}")
        self.set_status(f"{len(packages)} 个包 / {human_size(total_size)}")
        if not packages:
            self.log("没有找到 .wxapkg：确认微信里打开过该小程序，且选的是 4.x 的 applet/packages 目录。")
            return

        # 默认不读标题：扫描只做一次 listdir（图标），标题留给「选中时按需读取」。
        # 勾选「扫描时读取全部标题」才批量解密。
        if self.auto_title_var.get():
            missing = sorted({p.appid for p in packages if p.appid and not self.cache.get_title(p.appid)})
            if missing:
                self.log(f"开始批量读取 {len(missing)} 个 AppID 的包内标题…")
                threading.Thread(target=self._probe_titles, args=(packages, missing), daemon=True).start()
        else:
            self.log("标题按需读取：点开哪一行就读哪个包（也可以双击/F2 手动命名）。")

    def _load_icon(self, appid: str, scan_root: str):
        """把 applet/icon 下的图标缩成 20px 供 Treeview 使用；失败返回 ""。"""
        try:
            icon_path = find_icon(appid, [scan_root] if scan_root else None)
            if not icon_path:
                return ""
            self._icon_paths[appid] = icon_path
            from PIL import Image, ImageTk

            image = Image.open(icon_path)
            image.thumbnail((20, 20))
            photo = ImageTk.PhotoImage(image)
            # 必须持有引用，否则会被 GC 掉导致图标空白
            self._icons[appid] = photo
            return photo
        except Exception:
            return ""

    def _probe_titles(self, packages: list[PackageInfo], appids: list[str]) -> None:
        """逐个 appid 读包内 projectname，读到就更新表格与缓存。"""
        # 每个 appid 优先用主包，其次任意一个包
        targets: dict[str, PackageInfo] = {}
        for pkg in packages:
            if pkg.appid not in appids:
                continue
            cur = targets.get(pkg.appid)
            if cur is None or (pkg.role == "主包" and cur.role != "主包"):
                targets[pkg.appid] = pkg

        total = len(targets)
        hits = 0
        failed = []
        for index, (appid, pkg) in enumerate(targets.items(), 1):
            self.set_status(f"读取标题 {index}/{total}…")
            title, source = read_package_title(pkg)
            if title:
                hits += 1
                self.cache.set_title(appid, title, source)
                self.post(lambda a=appid, t=title: self._apply_title(a, t))
            else:
                failed.append(appid)
        self.cache.save()
        msg = f"本地标题探测：{hits}/{total} 个 AppID 从包内 project.config.json 读到名称"
        if failed:
            msg += f"，其余 {len(failed)} 个包里没有该文件（只能联网查询或看图标）"
        self.log(msg)
        self.set_status(f"{len(packages)} 个包 / 本次新增标题 {hits} 个")

    def _apply_title(self, appid: str, title: str) -> None:
        """把探测到的标题写回表格对应行。"""
        for iid, pkg in self.iid_map.items():
            if pkg.appid == appid:
                pkg.title = title
                try:
                    self.tree.set(iid, "title", title)
                except Exception:
                    pass
        pkg_sel = self.selected_packages()
        if any(p.appid == appid for p in pkg_sel):
            self.on_select()

    def _lazy_title(self, pkg: PackageInfo) -> None:
        """选中某行时按需读这一个包的标题；同一 appid 只尝试一次。"""
        appid = pkg.appid
        if not appid or pkg.title:
            return
        if self.cache.get_title(appid) or appid in self._probed:
            return
        self._probed.add(appid)

        def worker():
            title, source = read_package_title(pkg)
            if title:
                self.cache.set_title(appid, title, source)
                self.cache.save()
                self.post(lambda: self._apply_title(appid, title))
            else:
                self.post(lambda: self.log(f"{appid} 包里没有 project 配置，可用 F2 手动命名。"))

        threading.Thread(target=worker, daemon=True).start()

    def rename_selected(self) -> None:
        """手动命名选中项（写进缓存，优先于包内标题）。"""
        pkgs = self.selected_packages()
        if not pkgs:
            messagebox.showinfo("提示", "请先在列表里选中一行。")
            return
        pkg = pkgs[0]
        if not pkg.appid:
            messagebox.showinfo("提示", "这一行没有识别到 AppID，无法保存名称。")
            return
        current = self.cache.display_title(pkg.appid) or ""
        value = simpledialog.askstring(
            "重命名",
            f"给 {pkg.appid} 起个名字（写进 wxid.json，下次直接显示）：",
            initialvalue=current,
            parent=self.root,
        )
        if value is None:
            return
        value = value.strip()
        if not value:
            messagebox.showinfo("提示", "名称不能为空。")
            return
        self.cache.set_title(pkg.appid, value, "手动")
        self.cache.save()
        self._apply_title(pkg.appid, value)
        self.log(f"已重命名 {pkg.appid} → {value}")

    # ---------- 选中与详情 ----------

    def selected_packages(self) -> list[PackageInfo]:
        return [self.iid_map[iid] for iid in self.tree.selection() if iid in self.iid_map]

    def on_select(self, _event=None) -> None:
        pkgs = self.selected_packages()
        if not pkgs:
            return
        self.unpack_btn["state"] = tk.NORMAL
        pkg = pkgs[0]
        info = self.cache.get(pkg.appid) or {}
        title = self.cache.display_title(pkg.appid) if pkg.appid else ""
        lines = [
            f"标题: {title or '（还没读到，正在按需读取…）'}",
            f"AppID: {pkg.appid or '（未识别，需手动指定）'}",
            f"版本: {pkg.version or '（未识别）'}",
            f"类型: {pkg.role}",
            f"文件: {pkg.name}",
            f"大小: {human_size(pkg.size)}",
            f"加密: {'是（V1MMWX，需 AES 解密）' if pkg.encrypted else '否（已是明文 wxapkg）'}",
            f"标题来源: {info.get('title_source') or '未读取（按 F2 可手动命名）'}",
            f"图标: {pkg.icon or '（未找到 applet/icon 下的图标）'}",
            f"开发者: {info.get('principal_name', '未知')}",
            f"描述: {info.get('description', '无')}",
            f"路径: {pkg.path}",
        ]
        if len(pkgs) > 1:
            lines.append(f"\n已选中 {len(pkgs)} 个包，解包时会依次处理。")
        self.detail_text.delete("1.0", tk.END)
        self.detail_text.insert(tk.END, "\n".join(lines))

        if not self.output_entry.get().strip():
            self.output_entry.insert(0, default_output_root())

        # 需要标题时才读这一个包（不遍历）
        self._lazy_title(pkg)

    def set_appid_dialog(self) -> None:
        """给选中项手动指定 AppID（路径里没有 appid 目录时使用）。"""
        pkgs = self.selected_packages()
        if not pkgs:
            messagebox.showinfo("提示", "请先在列表里选中一个包。")
            return
        value = simpledialog.askstring(
            "指定 AppID",
            "输入该小程序的 AppID（wx 开头的 18 位）：",
            initialvalue=pkgs[0].appid or "wx",
            parent=self.root,
        )
        if not value:
            return
        value = value.strip()
        if not APPID_PATTERN.match(value):
            messagebox.showerror("错误", f"AppID 格式不对：{value}")
            return
        for pkg in pkgs:
            pkg.appid = value
            iid = next((k for k, v in self.iid_map.items() if v is pkg), None)
            if iid is not None:
                values = list(self.tree.item(iid, "values"))
                values[2] = value
                self.tree.item(iid, values=values)
        self.log(f"已为 {len(pkgs)} 个包指定 AppID：{value}")

    # ---------- 输出目录 ----------

    def browse_output(self) -> None:
        current = self.output_entry.get().strip() or default_output_root()
        new_dir = filedialog.askdirectory(initialdir=current if os.path.isdir(current) else os.getcwd())
        if new_dir:
            self.output_entry.delete(0, tk.END)
            self.output_entry.insert(0, new_dir)

    def open_output_dir(self) -> None:
        path = self.output_entry.get().strip()
        if not path or not os.path.isdir(path):
            messagebox.showinfo("提示", f"输出目录还不存在：{path}")
            return
        self._open_in_explorer(path)

    @staticmethod
    def _open_in_explorer(path: str) -> None:
        if os.name == "nt":
            os.startfile(path)  # noqa: S606 - 打开资源管理器属于预期行为
        else:
            opener = "open" if sys.platform == "darwin" else "xdg-open"
            os.system(f'{opener} "{path}"')

    # ---------- 解包 ----------

    def unpack_selected(self) -> None:
        pkgs = self.selected_packages()
        if not pkgs:
            messagebox.showinfo("提示", "请先在列表里选中要解包的包。")
            return
        out_root = self.output_entry.get().strip() or default_output_root()
        os.makedirs(out_root, exist_ok=True)

        missing = [p for p in pkgs if not p.appid and p.encrypted]
        if missing:
            messagebox.showerror(
                "缺少 AppID",
                f"有 {len(missing)} 个加密包无法从路径识别 AppID，解密需要它。\n"
                "请选中后点「指定 AppID」再试。",
            )
            return

        flat = not self.split_var.get()
        self.unpack_btn["state"] = tk.DISABLED
        self.set_status("解包中…")
        self.progress.configure(value=0)
        options = {
            "flat": flat,
            "compress_js": self.js_var.get(),
            "compress_png": self.png_var.get(),
        }
        threading.Thread(
            target=self._unpack_worker, args=(pkgs, out_root, options), daemon=True
        ).start()

    def _unpack_worker(self, pkgs: list[PackageInfo], out_root: str, options: dict) -> None:
        total_saved = 0
        total_pkgs = len(pkgs)
        failures: list[str] = []
        for index, pkg in enumerate(pkgs, 1):
            self.set_status(f"解包 {index}/{total_pkgs}：{pkg.name}")
            self.log(f"[{index}/{total_pkgs}] {pkg.appid}/{pkg.version}/{pkg.name}")
            out_dir = package_output_dir(out_root, pkg, options["flat"])

            def on_file(done: int, total: int, rel: str, idx=index, name=pkg.name) -> None:
                # 包内进度只用来刷状态文字，避免频繁操作控件
                if total and done % 50 == 0:
                    self.set_status(f"{name} {done}/{total} 个文件")

            try:
                stats = unpack_one(
                    pkg,
                    out_dir,
                    allow_decrypt=True,
                    compress_js=options["compress_js"],
                    compress_png=options["compress_png"],
                    on_log=self.log,
                    on_file=on_file,
                )
                total_saved += stats["saved"]
                self.log(
                    f"完成：解出 {stats['saved']}/{stats['files']} 个文件"
                    f"（跳过 {stats['skipped']}）→ {out_dir}"
                )
            except Exception as exc:
                failures.append(f"{pkg.name}: {exc}")
                self.log(f"失败：{pkg.name} → {exc}")
            self.set_progress(index / total_pkgs)

        self.cache.save()
        self.set_progress(1.0)
        self.post(lambda: self.unpack_btn.configure(state=tk.NORMAL))
        self.set_status(f"完成，共 {total_saved} 个文件")

        summary = f"解包结束：共写出 {total_saved} 个文件\n输出目录: {out_root}"
        if failures:
            summary += f"\n\n失败 {len(failures)} 个：\n" + "\n".join(failures[:10])
        self.log(summary.replace("\n", " | "))

        if messagebox.askquestion("完成", summary + "\n\n是否打开输出目录？", icon="info") == "yes":
            self._open_in_explorer(out_root)

    # ---------- 关闭 ----------

    def _on_close(self) -> None:
        self.cache.save()
        self.root.destroy()


def _enable_dpi_awareness() -> None:
    """让 Windows 高 DPI 下界面不模糊（非 Windows 直接跳过）。"""
    if os.name != "nt":
        return
    try:
        import ctypes

        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            ctypes.windll.user32.SetProcessDPIAware()
    except Exception:
        pass


def run_gui(root_dir: str = "") -> int:
    """启动图形界面；给定 root_dir 时启动后自动扫描该目录。"""
    if not HAS_TK:
        print("当前环境没有 tkinter，只能使用命令行：python wxapkg_gui.py --help", file=sys.stderr)
        return 2
    _enable_dpi_awareness()
    root = tk.Tk()
    app = WxapkgUnpacker(root)
    if root_dir:
        if os.path.isdir(root_dir):
            app.root_path_var.set(app._short_path(root_dir))
            app._remember_dir(root_dir)
            root.after(300, lambda: app.start_scan(root_dir))
        else:
            app.log(f"指定的目录不存在，已跳过自动扫描：{root_dir}")
    root.mainloop()
    return 0


# ---------------------------------------------------------------- 命令行

def collect_titles(pkgs: list[PackageInfo], cache: InfoCache | None = None) -> dict[str, str]:
    """按 appid 批量探测包内标题；每个 appid 只解密一次（优先主包）。"""
    best: dict[str, PackageInfo] = {}
    for pkg in pkgs:
        if not pkg.appid:
            continue
        cur = best.get(pkg.appid)
        if cur is None or (pkg.role == "主包" and cur.role != "主包"):
            best[pkg.appid] = pkg

    titles: dict[str, str] = {}
    for appid, pkg in best.items():
        cached = cache.get_title(appid) if cache else ""
        if cached:
            titles[appid] = cached
            continue
        title, source = read_package_title(pkg)
        if title:
            titles[appid] = title
            if cache is not None:
                cache.set_title(appid, title, source)
    if cache is not None:
        cache.save()
    return titles


def cmd_scan(args) -> int:
    """扫描目录（或本机所有候选目录）并列出包。"""
    roots: list[tuple[str, str]] = []
    if args.root:
        roots = [("指定目录", args.root)]
    else:
        roots = candidate_roots()
        if not roots:
            print("未探测到常见缓存目录，请显式指定目录。", file=sys.stderr)
            return 1

    groups: list[tuple[str, str, list[PackageInfo]]] = []
    for label, path in roots:
        try:
            pkgs = find_packages(path)
        except Exception as exc:
            print(f"[跳过] {label} {path}：{exc}", file=sys.stderr)
            pkgs = []
        groups.append((label, path, pkgs))
    all_pkgs = [p for _, _, pkgs in groups for p in pkgs]

    # 标题探测：读包内 project.config.json 的 projectname（每个 appid 一次）
    titles: dict[str, str] = {}
    if args.title and all_pkgs:
        cache = InfoCache(os.path.join(data_dir(), JSON_CACHE_FILE))
        titles = collect_titles(all_pkgs, cache)

    for label, path, pkgs in groups:
        print(f"\n=== {label} ===")
        print(f"路径: {path}")
        print(f"包数: {len(pkgs)}")
        for pkg in pkgs:
            title = titles.get(pkg.appid, "") or "-"
            print(
                f"  {title:<18} {pkg.appid or '未知':<20} {pkg.version or '-':<6} "
                f"{human_size(pkg.size):>8}  {'加密' if pkg.encrypted else '明文'}  {pkg.name}"
            )

    if args.json:
        payload = [
            {
                "path": p.path,
                "appid": p.appid,
                "version": p.version,
                "name": p.name,
                "role": p.role,
                "size": p.size,
                "encrypted": p.encrypted,
                "title": titles.get(p.appid, ""),
            }
            for p in all_pkgs
        ]
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


def cmd_unpack(args) -> int:
    """解密 + 解包，支持目录（递归）或单个文件。"""
    target = args.input
    if not os.path.exists(target):
        print(f"路径不存在：{target}", file=sys.stderr)
        return 1

    if os.path.isfile(target):
        appid = args.appid or guess_appid(target)
        pkgs = [
            PackageInfo(
                path=target,
                appid=appid,
                version=guess_version(target, appid),
                size=os.path.getsize(target),
                encrypted=probe_encrypted(target),
                mtime=os.path.getmtime(target),
            )
        ]
    else:
        pkgs = find_packages(target)

    if args.appid:
        for pkg in pkgs:
            pkg.appid = args.appid

    if not pkgs:
        print("没有找到 .wxapkg 文件。", file=sys.stderr)
        return 1

    out_root = args.output or default_output_root()
    os.makedirs(out_root, exist_ok=True)
    print(f"共 {len(pkgs)} 个包，输出根目录：{out_root}")

    failures = 0
    saved_total = 0
    for index, pkg in enumerate(pkgs, 1):
        out_dir = package_output_dir(out_root, pkg, args.flat)
        head = f"[{index}/{len(pkgs)}] {pkg.appid}/{pkg.version}/{pkg.name}"
        print(head)
        try:
            stats = unpack_one(
                pkg,
                out_dir,
                appid_override=args.appid or "",
                allow_decrypt=not args.no_decrypt,
                compress_js=args.compress,
                compress_png=args.compress_png,
                on_log=lambda msg: print(f"    {msg}"),
            )
            saved_total += stats["saved"]
            print(
                f"    解出 {stats['saved']}/{stats['files']} 个文件"
                f"（跳过 {stats['skipped']}，截断 {stats['truncated']}）→ {out_dir}"
            )
        except Exception as exc:
            failures += 1
            print(f"    失败：{exc}", file=sys.stderr)

    print(f"\n完成：写出 {saved_total} 个文件，失败 {failures} 个包。")
    return 0 if failures == 0 else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wxapkg-gui",
        description=f"{APP_NAME} v{APP_VERSION}：微信小程序 .wxapkg 扫描 / 解密 / 解包（3.x / 4.0 / 4.1.x）",
    )
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {APP_VERSION}")
    sub = parser.add_subparsers(dest="cmd")

    p_scan = sub.add_parser("scan", help="扫描小程序缓存目录")
    p_scan.add_argument("root", nargs="?", default="", help="目录；省略则扫描本机所有候选目录")
    p_scan.add_argument("--json", action="store_true", help="额外输出 JSON")
    p_scan.add_argument(
        "--title",
        action="store_true",
        help="解密读每个包的 projectname（每个 AppID 解密一次，慢但列表带名称）",
    )
    p_scan.set_defaults(func=cmd_scan)

    p_unpack = sub.add_parser("unpack", help="解密并解包")
    p_unpack.add_argument("input", help="目录（递归）或单个 .wxapkg 文件")
    p_unpack.add_argument("-o", "--output", default="", help="输出根目录，默认 ./unpack")
    p_unpack.add_argument("--appid", default="", help="强制指定 AppID（路径识别不到时使用）")
    p_unpack.add_argument("--no-decrypt", action="store_true", help="不解密，直接按明文解包")
    p_unpack.add_argument("--flat", action="store_true", help="平铺到输出根目录（多包会互相覆盖）")
    p_unpack.add_argument("--compress", action="store_true", help="压缩 JS / JSON")
    p_unpack.add_argument("--compress-png", action="store_true", help="压缩 PNG")
    p_unpack.set_defaults(func=cmd_unpack)

    p_gui = sub.add_parser("gui", help="启动图形界面")
    p_gui.add_argument("--root", default="", help="启动后自动扫描的目录")
    p_gui.set_defaults(func=lambda a: run_gui(a.root))
    return parser


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        return run_gui()
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "cmd", None):
        parser.print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
