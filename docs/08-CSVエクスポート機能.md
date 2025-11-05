# CSVエクスポート機能

## 概要

出退勤データをCSV形式でエクスポートする機能です。手動エクスポートと定期自動送信の両方をサポートします。

## 手動エクスポート

### エンドポイント

**GET /admin/export**

**ファイル位置**: `app.py` 467-487行目

**認証**: ログイン必須 + 管理者権限

### クエリパラメータ

- `start`: 開始日（YYYY-MM-DD形式、オプション）
- `end`: 終了日（YYYY-MM-DD形式、オプション）
- `username`: ユーザーIDフィルタ（オプション）

### デフォルト期間

指定がない場合:
- **終了日**: 今日
- **開始日**: 14日前

### CSV形式

#### ヘッダー

```
user_username,user_email,user_name,shift_id,clock_in_local,clock_out_local,worked_seconds,worked_hms,clock_in_utc,clock_out_utc,clock_in_ip,clock_out_ip,clock_in_ua,clock_out_ua,break_count,breaks_total_seconds,breaks_total_hms
```

#### フィールド説明

- **user_username**: ユーザーID
- **user_email**: メールアドレス（空の場合もある）
- **user_name**: 氏名（空の場合もある）
- **shift_id**: シフトID
- **clock_in_local**: 出勤時刻（ローカル時刻、YYYY-MM-DD HH:MM:SS）
- **clock_out_local**: 退勤時刻（ローカル時刻、YYYY-MM-DD HH:MM:SS）
- **worked_seconds**: 実働時間（秒）
- **worked_hms**: 実働時間（HH:MM:SS形式）
- **clock_in_utc**: 出勤時刻（UTC、ISO形式）
- **clock_out_utc**: 退勤時刻（UTC、ISO形式）
- **clock_in_ip**: 出勤時のIPアドレス
- **clock_out_ip**: 退勤時のIPアドレス
- **clock_in_ua**: 出勤時のUser-Agent
- **clock_out_ua**: 退勤時のUser-Agent
- **break_count**: 休憩回数
- **breaks_total_seconds**: 休憩時間合計（秒）
- **breaks_total_hms**: 休憩時間合計（HH:MM:SS形式）

#### ファイル名

```
attendance_export_YYYY-MM-DD_YYYY-MM-DD.csv
```

例: `attendance_export_2024-01-01_2024-01-14.csv`

#### 文字コード

UTF-8 with BOM (`utf-8-sig`)

Excelで開いた際に文字化けしないようにBOMを付与しています。

## CSV生成関数

### generate_csv関数

**ファイル位置**: `app.py` 434-465行目

```python
def generate_csv(start_date, end_date, user_username=None, user_email=None):
    """CSVデータを生成する共通関数"""
    # 1. UTC時刻範囲を計算
    start_utc = datetime.combine(start_date, datetime.min.time()).replace(tzinfo=LOCAL_TZ).astimezone(timezone.utc)
    end_utc = datetime.combine(end_date, datetime.max.time()).replace(tzinfo=LOCAL_TZ).astimezone(timezone.utc)
    
    # 2. Shiftクエリ作成
    q = Shift.query.join(User).filter(Shift.clock_in_at >= start_utc, Shift.clock_in_at <= end_utc)
    if user_username:
        q = q.filter(User.username == user_username)
    elif user_email:
        q = q.filter(User.email == user_email)
    
    # 3. シフトを取得（出勤時刻の昇順）
    shifts = q.order_by(Shift.clock_in_at.asc()).all()
    
    # 4. CSVデータ生成
    # 5. バイト列として返す
    return buf.getvalue().encode("utf-8-sig"), len(shifts)
```

### 戻り値

- **CSVデータ**: バイト列（UTF-8 with BOM）
- **件数**: エクスポートされたシフト数

## 定期自動送信

### 概要

設定されたスケジュールに従って、自動的にCSVをメール送信します。

### スケジューラー

**ライブラリ**: APScheduler 3.10.4

**ファイル位置**: `app.py` 913-988行目

### 設定項目

- **CSV_EXPORT_EMAIL**: 送信先メールアドレス
- **CSV_EXPORT_SCHEDULE**: スケジュール（daily/weekly/monthly/cron形式）
- **CSV_EXPORT_DAYS**: 過去何日分をエクスポートするか

### ジョブ関数

**scheduled_csv_export関数**

**ファイル位置**: `app.py` 576-594行目

```python
def scheduled_csv_export():
    """定期CSVエクスポートのジョブ関数"""
    with app.app_context():
        email, schedule, days = get_csv_export_config()
        if not email:
            return
        
        now_local = datetime.now(LOCAL_TZ)
        end_date = now_local.date()
        start_date = end_date - timedelta(days=days)
        
        try:
            csv_data, shift_count = generate_csv(start_date, end_date, None, None)
            send_csv_email(email, csv_data, start_date, end_date)
            log_audit("scheduled_csv_export", ...)
        except Exception as e:
            app.logger.exception(f"Scheduled CSV export failed: {e}")
```

### スケジュール形式

詳細は[システム設定機能](07-システム設定機能.md)を参照してください。

- **daily**: 毎日朝9時
- **weekly**: 毎週月曜日朝9時
- **monthly**: 毎月1日朝9時
- **cron形式**: `0 9 * * *`（毎日9時）

## メール送信

### send_csv_email関数

**ファイル位置**: `app.py` 489-567行目

```python
def send_csv_email(to_email, csv_data, start_date, end_date):
    """CSVファイルをメールで送信"""
    # 1. SMTP設定を取得
    smtp_host = SystemConfig.get("SMTP_HOST", os.getenv("SMTP_HOST", "localhost"))
    smtp_port = int(SystemConfig.get("SMTP_PORT", os.getenv("SMTP_PORT", "25")))
    # ...
    
    # 2. メールメッセージ作成
    msg = MIMEMultipart()
    msg["From"] = smtp_from
    msg["To"] = to_email
    msg["Subject"] = f"出退勤データ CSV - {start_date.isoformat()} ～ {end_date.isoformat()}"
    
    # 3. 本文追加
    body = f"""出退勤システムからの定期CSVエクスポートです。

期間: {start_date.isoformat()} ～ {end_date.isoformat()}

CSVファイルを添付しています。
"""
    msg.attach(MIMEText(body, "plain", "utf-8"))
    
    # 4. CSVファイルを添付
    attachment = MIMEBase("application", "octet-stream")
    attachment.set_payload(csv_data)
    encoders.encode_base64(attachment)
    attachment.add_header("Content-Disposition", f"attachment; filename={filename}")
    msg.attach(attachment)
    
    # 5. SMTPサーバーに接続して送信
    with smtplib.SMTP(smtp_host, smtp_port) as server:
        if smtp_use_tls:
            server.starttls()
        if smtp_user and smtp_password:
            server.login(smtp_user, smtp_password)
        server.send_message(msg)
```

### SMTP設定

以下の設定が必要です（詳細は[システム設定機能](07-システム設定機能.md)を参照）:

- `SMTP_HOST`: SMTPサーバーのホスト名
- `SMTP_PORT`: ポート番号
- `SMTP_USER`: 認証ユーザー名（オプション）
- `SMTP_PASSWORD`: 認証パスワード（オプション）
- `SMTP_USE_TLS`: TLS使用フラグ
- `SMTP_FROM`: 送信元メールアドレス

### メール件名

```
出退勤データ CSV - YYYY-MM-DD ～ YYYY-MM-DD
```

### エラーハンドリング

メール送信に失敗した場合、例外をキャッチしてログに記録します。

```python
try:
    send_csv_email(...)
except Exception as e:
    app.logger.exception(f"Failed to send CSV email: {e}")
    return False
```

## 時刻の扱い

### 保存・検索

- **データベース**: UTC（timezone aware）
- **検索範囲**: ローカル時刻の日付範囲をUTCに変換して検索

```python
start_utc = datetime.combine(start_date, datetime.min.time()).replace(tzinfo=LOCAL_TZ).astimezone(timezone.utc)
end_utc = datetime.combine(end_date, datetime.max.time()).replace(tzinfo=LOCAL_TZ).astimezone(timezone.utc)
```

### CSV出力

- **ローカル時刻**: `clock_in_local`, `clock_out_local`（表示用）
- **UTC時刻**: `clock_in_utc`, `clock_out_utc`（データ整合性確認用）

## 監査ログ

手動エクスポートと定期自動送信の両方が監査ログに記録されます。

### 手動エクスポート

```python
log_audit("admin_export", target_type="shift", target_id=None,
         metadata_dict={
             "start": start_date.isoformat(),
             "end": end_date.isoformat(),
             "email": user_email,
             "shift_count": shift_count
         })
```

### 定期自動送信

```python
log_audit("scheduled_csv_export", target_type="system", target_id=None,
         metadata_dict={
             "email": email,
             "start": start_date.isoformat(),
             "end": end_date.isoformat(),
             "shift_count": shift_count
         })
```

## パフォーマンス

### 大量データへの対応

- 日付範囲でフィルタリング
- ユーザーIDでフィルタリング（オプション）
- インデックス活用（`clock_in_at`にインデックス）

### メモリ使用量

CSVデータはStringIOを使用してメモリ上で生成し、最後にバイト列に変換します。

## エクスポート制限

現バージョンでは明示的な制限はありませんが、大量データをエクスポートする場合は:

- 期間を短くする
- ユーザーIDでフィルタリングする
- 必要に応じてページネーションを実装する

## 関連機能

- [管理者機能（出退勤記録管理）](04-管理者機能（出退勤記録管理）.md) - 手動エクスポートの呼び出し元
- [システム設定機能](07-システム設定機能.md) - CSV送信設定
- [監査ログ機能](06-監査ログ機能.md) - エクスポートの記録

