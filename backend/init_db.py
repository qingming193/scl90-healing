# -*- coding: utf-8 -*-
"""
Initialize 1,000,000 unique 6-character authorization codes (500,000 for Store 1 'pro' + 500,000 for Store 2 'fun')
into SQLite database and export ready-to-upload TXT batches locally.
"""
from __future__ import annotations
import os
import json
import sqlite3
import secrets
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PRODUCT_DIR = os.path.dirname(BASE_DIR)
DB_PATH = os.path.join(BASE_DIR, "auth.db")
EXPORT_DIR = os.path.join(PRODUCT_DIR, "授权码库_双店100万")

# Unambiguous uppercase charset (32 chars: excludes 0, O, 1, I) -> 32^6 = 1,073,741,824 combinations
ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
RESERVED = {"ADMIN8", "PRO888", "FUN888"}


def generate_unique_codes(total_count: int) -> list[str]:
    codes = set()
    choice = secrets.choice
    while len(codes) < total_count:
        batch_needed = total_count - len(codes)
        for _ in range(min(batch_needed + 5000, 100000)):
            c = "".join(choice(ALPHABET) for _ in range(6))
            if c not in RESERVED:
                codes.add(c)
                if len(codes) >= total_count:
                    break
    result = list(codes)
    # Shuffle deterministically with secrets
    return result


def build_questions_json():
    """Extract pro (classic 90) and fun (scenario 90) question banks into backend JSON files."""
    # 1. Extract fun 90 questions from questions_2_0.js
    q20_path = os.path.join(PRODUCT_DIR, "questions_2_0.js")
    with open(q20_path, "r", encoding="utf-8") as f:
        raw = f.read()
    start = raw.find("[")
    end = raw.rfind("]") + 1
    fun_questions = json.loads(raw[start:end])
    assert len(fun_questions) == 90, f"Expected 90 fun questions, got {len(fun_questions)}"

    with open(os.path.join(BASE_DIR, "questions_fun.json"), "w", encoding="utf-8") as f:
        json.dump(fun_questions, f, ensure_ascii=False, separators=(",", ":"))

    # 2. Extract classic 90 standard SCL-90 questions from index.html
    idx_path = os.path.join(PRODUCT_DIR, "index.html")
    with open(idx_path, "r", encoding="utf-8") as f:
        html = f.read()
    import re
    m = re.search(r"const questions\s*=\s*(\[[\s\S]*?\]);", html)
    assert m, "Could not locate classic questions array in index.html"
    pro_questions = json.loads(m.group(1))
    assert len(pro_questions) == 90, f"Expected 90 pro questions, got {len(pro_questions)}"

    with open(os.path.join(BASE_DIR, "questions_pro.json"), "w", encoding="utf-8") as f:
        json.dump(pro_questions, f, ensure_ascii=False, separators=(",", ":"))

    print(f"[OK] Saved questions_pro.json ({len(pro_questions)}) & questions_fun.json ({len(fun_questions)})")


def init_database_and_exports(pro_count=500000, fun_count=500000):
    t0 = time.time()
    os.makedirs(EXPORT_DIR, exist_ok=True)

    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    print(f"Generating {pro_count + fun_count:,} unique 6-char codes...")
    all_codes = generate_unique_codes(pro_count + fun_count)
    pro_codes = all_codes[:pro_count]
    fun_codes = all_codes[pro_count:]
    print(f"[OK] Generated {len(pro_codes):,} PRO + {len(fun_codes):,} FUN codes in {time.time() - t0:.2f}s")

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("PRAGMA journal_mode = WAL;")
    cur.execute("PRAGMA synchronous = OFF;")
    cur.execute("PRAGMA page_size = 4096;")

    cur.execute("""
        CREATE TABLE codes (
            code TEXT PRIMARY KEY,
            version TEXT NOT NULL,
            status INTEGER NOT NULL DEFAULT 0,
            fp1 TEXT,
            fp2 TEXT,
            hw_sig TEXT,
            ip_prefix TEXT,
            activated_at INTEGER,
            use_count INTEGER NOT NULL DEFAULT 0
        ) WITHOUT ROWID;
    """)

    cur.execute("""
        CREATE TABLE orders (
            order_id TEXT PRIMARY KEY,
            version TEXT NOT NULL,
            fp1 TEXT,
            fp2 TEXT,
            hw_sig TEXT,
            ip_prefix TEXT,
            activated_at INTEGER,
            use_count INTEGER NOT NULL DEFAULT 1
        ) WITHOUT ROWID;
    """)

    cur.execute("CREATE INDEX idx_codes_ver_status ON codes(version, status);")

    print("Inserting 1,000,000 codes into SQLite...")
    cur.executemany(
        "INSERT INTO codes (code, version, status, use_count) VALUES (?, 'pro', 0, 0)",
        [(c,) for c in pro_codes]
    )
    cur.executemany(
        "INSERT INTO codes (code, version, status, use_count) VALUES (?, 'fun', 0, 0)",
        [(c,) for c in fun_codes]
    )
    conn.commit()
    cur.execute("PRAGMA synchronous = NORMAL;")
    conn.close()

    db_mb = os.path.getsize(DB_PATH) / (1024 * 1024)
    print(f"[OK] SQLite auth.db ready ({db_mb:.1f} MB) in {time.time() - t0:.2f}s total!")

    # Export TXT files for Store 1 (pro) & Store 2 (fun)
    pro_dir = os.path.join(EXPORT_DIR, "1号店_专业临床版_50万码")
    fun_dir = os.path.join(EXPORT_DIR, "2号店_牛马沉浸版_50万码")
    os.makedirs(pro_dir, exist_ok=True)
    os.makedirs(fun_dir, exist_ok=True)

    with open(os.path.join(pro_dir, "1号店_专业版_全量50万码.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(pro_codes) + "\n")
    with open(os.path.join(fun_dir, "2号店_牛马版_全量50万码.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(fun_codes) + "\n")

    # Also split into 10 batches of 50,000 codes each for easy import into any auto-delivery tool
    chunk = 50000
    for i in range(0, pro_count, chunk):
        batch_no = i // chunk + 1
        with open(os.path.join(pro_dir, f"批次{batch_no:02d}_5万码.txt"), "w", encoding="utf-8") as f:
            f.write("\n".join(pro_codes[i:i + chunk]) + "\n")
    for i in range(0, fun_count, chunk):
        batch_no = i // chunk + 1
        with open(os.path.join(fun_dir, f"批次{batch_no:02d}_5万码.txt"), "w", encoding="utf-8") as f:
            f.write("\n".join(fun_codes[i:i + chunk]) + "\n")

    print(f"[OK] Exported local TXT packs to {EXPORT_DIR}")
    print("Sample PRO codes:", pro_codes[:5])
    print("Sample FUN codes:", fun_codes[:5])


if __name__ == "__main__":
    build_questions_json()
    init_database_and_exports(500000, 500000)
