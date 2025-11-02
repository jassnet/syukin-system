# 出退勤システム（最小セット / No Docker）

**目的:** Docker を使えない環境でも、できるだけ簡単に **ローカル実行** & **PaaS でデプロイ** できる構成。  
DB は本番を **PostgreSQL** 想定。ローカルは簡易に **SQLite** でも動きます（同一コード）。

---

## クイックスタート（ローカル・最短）

> Python 3.11 以上を前提とします

```bash
# 1) 仮想環境
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# 2) 依存インストール
pip install -r requirements.txt

# 3) .env を用意
cp .env.example .env
# 初期状態は SQLite (attendance.db) なので DB セットアップ不要
# Google OAuth を使わずに動作確認したい場合は .env の ALLOW_DEV_LOGIN=true に

# 4) 起動（開発用）
python -m flask --app app run -p 8000
# または本番に近い形:
gunicorn -w 3 -b 0.0.0.0:8000 app:app
```

- ブラウザで <http://localhost:8000>  
- **Google OAuth** で試す場合は、`GOOGLE_CLIENT_ID/SECRET` と `OAUTH_REDIRECT_URI` を設定してください。  
- **簡易確認**だけなら `.env` で `ALLOW_DEV_LOGIN=true` を設定し、`/devlogin` からメール入力でログイン可能（**本番では必ず false**）。

---

## 本番：PostgreSQL を使う

1. PostgreSQL の接続URLを取得（例）
   ```
   postgresql://USER:PASSWORD@HOST:PORT/DBNAME
   ```
2. `.env` の `DATABASE_URL` を上記に変更して再起動。  
   既存の SQLite から移行する場合は、必要に応じてデータ移行を行ってください（将来の拡張で Alembic マイグレーション対応可）。

> **注意:** 監査要件のため、操作ログは `audit_logs` に IP / UA / JSON / HMAC 署名付きで保存します。

---

## デプロイ（Docker 不要の PaaS 想定）

- **手順の基本形**（Heroku/Render等の「Procfile + Python」互換 PaaS）
  - リポジトリを登録（GitHub 連携など）
  - Build コマンド: `pip install -r requirements.txt`
  - Start コマンド: `gunicorn app:app`
  - 環境変数を登録：
    - `SECRET_KEY`
    - `TIMEZONE`（例: `Asia/Tokyo`）
    - `ADMIN_EMAILS`（管理者メール）
    - `DATABASE_URL`（**PostgreSQL** のURL）
    - `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` / `OAUTH_REDIRECT_URI`
    - `SESSION_COOKIE_SECURE=true`（HTTPS運用時）
  - 公開URL を Google OAuth のリダイレクトURIに設定

> 任意の PaaS を使えます（**Docker 不要**）。`Procfile` があるので多くのサービスでそのまま起動できます。

---

## 仕様（抜粋）

- Google ログイン（/login → Google → /auth/callback）
- ダッシュボード：出勤/退勤/休憩開始/休憩終了
- 管理画面：期間/メールで絞込、CSV エクスポート
- 監査ログ：`audit_logs`（IP・UA・HMAC署名）
- すべての時刻は **UTC 保存**、表示は `TIMEZONE`（既定: Asia/Tokyo）

---

## セキュリティ運用メモ

- `ALLOW_DEV_LOGIN=true` は **ローカル開発用のみ**。本番では必ず **false**。
- `SECRET_KEY` は十分な長さのランダム値を設定。
- 本番は必ず **HTTPS** ＋ `SESSION_COOKIE_SECURE=true` を推奨。
- 管理者メールは `ADMIN_EMAILS` に登録。

---

## 困ったとき

- Google OAuth 設定が面倒 → まずは `ALLOW_DEV_LOGIN=true` で画面/動線を確認
- PostgreSQL が準備できない → 一時的に SQLite で試し、後から `DATABASE_URL` を置換
- テーブルは初回アクセス時に自動作成（`before_request: db.create_all()`）
