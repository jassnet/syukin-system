# 出退勤システム（最小セット / No Docker）

**目的:** Docker を使えない環境でも、できるだけ簡単に **ローカル実行** & **PaaS でデプロイ** できる構成。  
DB は本番を **PostgreSQL** 想定。ローカルは簡易に **SQLite** でも動きます（同一コード）。

**本番環境:** Renderにデプロイ済み（2025-11-07）

---

## クイックスタート（ローカル・最短）

> Python 3.11 以上を前提とします

```bash
# 1) 仮想環境
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# 2) 依存インストール
pip install -r requirements.txt

# 3) .env を用意（オプション）
# 初期状態は SQLite (attendance.db) なので DB セットアップ不要
# 必要に応じて .env ファイルを作成して設定をカスタマイズ

# 4) DB初期化（初回のみ）
flask --app app init-db

# 5) 起動（開発用）
python -m flask --app app run -p 8000
# または本番に近い形:
gunicorn -w 3 -b 0.0.0.0:8000 app:app
```

- ブラウザで <http://localhost:8000> にアクセス
- **初回起動時**: `flask --app app init-db` でテーブルを作成してからアクセスしてください
- **初期管理者ユーザーの作成**: アプリ起動後、データベースに直接管理者ユーザーを作成する必要があります（下記参照）

---

## 初期管理者ユーザーの作成

アプリ起動後、以下のいずれかの方法で初期管理者ユーザーを作成してください：

### 方法1: Pythonコンソールから作成（推奨）

```bash
python
```

```python
from app import app, db, User
with app.app_context():
    admin = User(username='admin', role='admin')
    admin.set_password('初期パスワード')  # 適宜変更してください
    admin.name = '管理者'
    db.session.add(admin)
    db.session.commit()
    print("管理者ユーザーを作成しました")
```

### 方法2: 既存の管理者ユーザーから作成

既に管理者ユーザーが存在する場合、管理画面（`/admin/users`）から新しいユーザーを作成できます。

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

## デプロイ（Render推奨）

本システムは **Render** にデプロイされています（2025-11-07）。

### Renderでのデプロイ手順

1. **Renderアカウント作成**: https://dashboard.render.com
2. **PostgreSQLデータベース作成**: 「New」→「Postgres」を選択
3. **Web Service作成**: 「New」→「Web Service」を選択
   - GitHubリポジトリを連携
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `gunicorn app:app`
4. **環境変数設定**:
   - `SECRET_KEY`: セッション暗号化用の秘密鍵（`python -c "import secrets; print(secrets.token_urlsafe(32))"`で生成）
   - `DATABASE_URL`: PostgreSQLのInternal Database URL（自動設定される場合あり）
   - `TIMEZONE`: `Asia/Tokyo`
   - `SESSION_COOKIE_SECURE`: `true`（HTTPS使用時）
5. **デプロイ後**: Shellタブからデータベース初期化と管理者ユーザー作成を実行

詳細は [デプロイメントガイド](docs/12-デプロイメント.md) を参照してください。

> **注意**: 他のPaaS（Heroku、Railway、Fly.io等）でもデプロイ可能です。`Procfile` があるので多くのサービスでそのまま起動できます。

---

## 仕様（抜粋）

- **認証方式**: ユーザーIDとパスワードによるログイン
- **ユーザー管理**: 管理者がユーザーの作成・編集・削除が可能
- ダッシュボード：出勤/退勤/休憩開始/休憩終了
- 管理画面：
  - 期間/ユーザーIDで絞込
  - CSV エクスポート
  - 出退勤データの編集
  - ユーザー管理（作成・編集・削除）
- **CSVエクスポート**: 管理画面から対象期間を指定して手動でCSVを取得可能。取得期間は `CSV_EXPORT_MAX_DAYS` 以内に制限されています。
- **データ編集機能**: 管理者が出退勤時刻を編集可能（変更前後の値が監査ログに記録）
- 監査ログ：`audit_logs`（IP・UA・HMAC署名、編集履歴を含む）
- すべての時刻は **UTC 保存**、表示は `TIMEZONE`（既定: Asia/Tokyo）

---

## セキュリティ運用メモ

- `SECRET_KEY` は十分な長さのランダム値を設定（本番環境では必須）。
- 本番は必ず **HTTPS** ＋ `SESSION_COOKIE_SECURE=true` を推奨。
- **パスワード管理**: 
  - 初期パスワードは強力なものを設定してください
  - 定期的なパスワード変更を推奨
  - 管理者はユーザー管理画面からパスワードをリセット可能
- **ユーザー管理**: 
  - 管理者は `/admin/users` からユーザーの作成・編集・削除が可能
  - 自分自身を削除することはできません
- **データ編集機能**: 管理者による出退勤データの編集は監査ログに変更前後の値が記録されます。監査要件を満たしています。

---

## 困ったとき

- **ログインできない**: 初期管理者ユーザーが作成されているか確認してください
- **パスワードを忘れた**: 他の管理者ユーザーからパスワードをリセットできます。管理者がいない場合は、データベースに直接アクセスしてパスワードをリセットする必要があります
- PostgreSQL が準備できない → 一時的に SQLite で試し、後から `DATABASE_URL` を置換
- 初回は `flask --app app init-db` を実行してテーブルを作成してください

## ユーザー管理について

- **管理者権限**: `role` フィールドが `admin` のユーザーが管理者です
- **ユーザー作成**: 管理者は管理画面（`/admin/users`）からユーザーを作成できます
- **パスワードリセット**: 管理者はユーザー編集画面からパスワードを変更できます
- **ユーザー削除**: 管理者は自分以外のユーザーを削除できます（削除時は関連する出退勤データも削除されます）
