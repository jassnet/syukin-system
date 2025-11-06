# API・ルーティング

## 概要

Flaskアプリケーションのすべてのエンドポイント一覧です。

## ルーティング一覧

### 認証関連

#### GET/POST /login
**ファイル位置**: `app.py` 266-290行目

**認証**: 不要

**機能**: ログインフォーム表示・認証処理

**POST パラメータ**:
- `username`: ユーザーID（必須）
- `password`: パスワード（必須）
- `csrf_token`: CSRFトークン（必須）

**リダイレクト**:
- 成功: `/dashboard`
- 失敗: `/login`（エラーメッセージ付き）

#### GET /logout
**ファイル位置**: `app.py` 292-297行目

**認証**: ログイン必須

**機能**: ログアウト処理

**リダイレクト**: `/login`

### ダッシュボード

#### GET / または GET /dashboard
**ファイル位置**: `app.py` 299-308行目

**認証**: ログイン必須

**機能**: ダッシュボード表示

**テンプレート**: `templates/dashboard.html`

### 出退勤操作

#### POST /clock/in
**ファイル位置**: `app.py` 311-323行目

**認証**: ログイン必須

**機能**: 出勤記録

**POST パラメータ**:
- `csrf_token`: CSRFトークン（必須）

**リダイレクト**: `/dashboard`

#### POST /clock/out
**ファイル位置**: `app.py` 325-338行目

**認証**: ログイン必須

**機能**: 退勤記録

**POST パラメータ**:
- `csrf_token`: CSRFトークン（必須）

**リダイレクト**: `/dashboard`

#### POST /break/start
**ファイル位置**: `app.py` 340-353行目

**認証**: ログイン必須

**機能**: 休憩開始記録

**POST パラメータ**:
- `csrf_token`: CSRFトークン（必須）

**リダイレクト**: `/dashboard`

#### POST /break/end
**ファイル位置**: `app.py` 355-368行目

**認証**: ログイン必須

**機能**: 休憩終了記録

**POST パラメータ**:
- `csrf_token`: CSRFトークン（必須）

**リダイレクト**: `/dashboard`

### 管理者機能

#### GET /admin
**ファイル位置**: `app.py` 383-432行目

**認証**: ログイン必須 + 管理者権限

**機能**: 出退勤記録一覧表示

**クエリパラメータ**:
- `start`: 開始日（YYYY-MM-DD、オプション）
- `end`: 終了日（YYYY-MM-DD、オプション）
- `username`: ユーザーIDフィルタ（オプション）

**テンプレート**: `templates/admin.html`

#### GET /admin/export
**ファイル位置**: `app.py` 467-487行目

**認証**: ログイン必須 + 管理者権限

**機能**: CSVエクスポート

**クエリパラメータ**:
- `start`: 開始日（YYYY-MM-DD、オプション）
- `end`: 終了日（YYYY-MM-DD、オプション）
- `username`: ユーザーIDフィルタ（オプション）

**レスポンス**: CSVファイル（ダウンロード）

#### GET /admin/shift/<shift_id>
**ファイル位置**: `app.py` 633-666行目

**認証**: ログイン必須 + 管理者権限

**機能**: シフト詳細（JSON API）

**レスポンス**: JSON形式

#### GET /admin/shift/<shift_id>/edit
**ファイル位置**: `app.py` 568-632行目

**認証**: ログイン必須 + 管理者権限

**機能**: シフト編集フォーム表示

**テンプレート**: `templates/shift_edit.html`

#### POST /admin/shift/<shift_id>/edit
**ファイル位置**: `app.py` 568-632行目

**認証**: ログイン必須 + 管理者権限

**機能**: シフト編集処理

**POST パラメータ**:
- `csrf_token`: CSRFトークン（必須）
- `clock_in_at`: 出勤時刻（datetime-local形式、オプション）
- `clock_out_at`: 退勤時刻（datetime-local形式、オプション）

**リダイレクト**: `/admin`

#### GET/POST /admin/users
**ファイル位置**: `app.py` 861-944行目

**認証**: ログイン必須 + 管理者権限

**機能**: ユーザー管理（一覧表示・作成・更新・削除）

**POST パラメータ**（action=create）:
- `action`: "create"（必須）
- `csrf_token`: CSRFトークン（必須）
- `username`: ユーザーID（必須）
- `password`: パスワード（必須）
- `name`: 氏名（オプション）
- `email`: メールアドレス（オプション）
- `role`: 権限（user/admin、デフォルト: user）

**POST パラメータ**（action=update）:
- `action`: "update"（必須）
- `csrf_token`: CSRFトークン（必須）
- `user_id`: ユーザーID（必須）
- `password`: パスワード（変更する場合のみ）
- `name`: 氏名（オプション）
- `email`: メールアドレス（オプション）
- `role`: 権限（user/admin）

**POST パラメータ**（action=delete）:
- `action`: "delete"（必須）
- `csrf_token`: CSRFトークン（必須）
- `user_id`: ユーザーID（必須）

**テンプレート**: `templates/admin_users.html`

#### GET /admin/audit
**ファイル位置**: `app.py` 686-716行目

**認証**: ログイン必須 + 管理者権限

**機能**: 監査ログ閲覧

**クエリパラメータ**:
- `action`: アクションフィルタ（オプション）
- `username`: ユーザーIDフィルタ（オプション）
- `limit`: 最大件数（デフォルト: 200、最大: 500）

**テンプレート**: `templates/admin_audit.html`

#### GET /admin/audit/export
**ファイル位置**: `app.py` 718-789行目

**認証**: ログイン必須 + 管理者権限

**機能**: 監査ログCSVエクスポート

**クエリパラメータ**:
- `action`: アクションフィルタ（オプション）
- `username`: ユーザーIDフィルタ（オプション）
- `limit`: 最大件数（デフォルト: 1000、最大: 5000）

**レスポンス**: CSVファイル（ダウンロード）

### ヘルスチェック

#### GET /healthz
**ファイル位置**: `app.py` 946-948行目

**認証**: 不要

**機能**: ヘルスチェック（PaaS用）

**レスポンス**: "ok"（テキスト）

## エラーハンドリング

### 400 Bad Request
- CSRFトークン無効
- 日付形式不正
- 必須パラメータ不足

### 403 Forbidden
- 管理者権限がない場合

### 404 Not Found
- 存在しないリソースへのアクセス

## リダイレクト

多くのエンドポイントは処理後にリダイレクトします:

- ログイン成功: `/dashboard`
- ログアウト: `/login`
- 出退勤操作: `/dashboard`
- 管理操作: `/admin` または `/admin/users`

## 関連機能

- [認証・ログイン機能](02-認証・ログイン機能.md) - 認証の詳細
- [ダッシュボード・出退勤機能](03-ダッシュボード・出退勤機能.md) - 出退勤の詳細
- [管理者機能（出退勤記録管理）](04-管理者機能（出退勤記録管理）.md) - 管理機能の詳細

