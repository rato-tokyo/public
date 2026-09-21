"""テキストファイルを XOR で暗号化・復号する。

    python crypt.py <key>         # 同じフォルダの a.txt が対象
    python crypt.py <key> <path>  # 対象を指定する

同じキーでもう一度実行すると元に戻る（XOR は自己反転のため）。
キーストリームは SHA-256 のカウンタモードで生成する。

暗号化後のファイルは `A:` で始まる Base64 の1行テキストになる。
この1行はコピー＆ペーストできる。別の場所へ貼り付けて保存し、
同じキーで実行すれば復号できる。貼り付け時の前後の空白・改行・BOM は無視する。
"""

import base64
import binascii
import hashlib
import sys
from pathlib import Path

DEFAULT_TARGET = Path(__file__).with_name("a.txt")
PREFIX = "A:"


def keystream(key: str, length: int) -> bytes:
    """キーから length バイトのキーストリームを作る"""
    out = bytearray()
    counter = 0
    seed = key.encode("utf-8")
    while len(out) < length:
        out += hashlib.sha256(seed + counter.to_bytes(8, "big")).digest()
        counter += 1
    return bytes(out[:length])


def xor(data: bytes, key: str) -> bytes:
    return bytes(a ^ b for a, b in zip(data, keystream(key, len(data))))


def main() -> int:
    if len(sys.argv) not in (2, 3):
        name = Path(__file__).name
        print(f"usage: python {name} <key> [path]", file=sys.stderr)
        return 1

    key = sys.argv[1]
    target = Path(sys.argv[2]) if len(sys.argv) == 3 else DEFAULT_TARGET
    if not target.exists():
        print(f"not found: {target}", file=sys.stderr)
        return 1

    raw = target.read_bytes()
    # utf-8-sig: Windows のエディタが付ける BOM を取り除く
    text = raw.decode("utf-8-sig", errors="replace").strip()

    if text.startswith(PREFIX):
        try:
            body = base64.b64decode(text[len(PREFIX):], validate=True)
        except (binascii.Error, ValueError):
            print("broken encrypted text: base64 decode failed", file=sys.stderr)
            return 1
        target.write_bytes(xor(body, key))
        print(f"decrypted: {target}")
    else:
        body = base64.b64encode(xor(raw, key)).decode("ascii")
        target.write_text(PREFIX + body, encoding="utf-8")
        print(f"encrypted: {target}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
