# Player Configs Migration Guide

## Overview

Đây là tài liệu hướng dẫn migrate player settings từ bảng `user_preferences` sang bảng `player_configs` mới.

### Tại sao cần migrate?

- **user_preferences**: Một hàng mỗi user, không thể có nhiều cấu hình player
- **player_configs**: Nhiều hàng mỗi user, hỗ trợ nhiều cấu hình player khác nhau

### Các bước thực hiện

## Bước 1: Chạy Migration SQL

```bash
cd /home/dat/projects/stream/stream.api

# Cách 1: Dùng script tự động (khuyến nghị)
./migrate_player_configs.sh

# Cách 2: Chạy SQL thủ công
psql -h 47.84.63.130 -U postgres -d video_db -f full_player_configs_migration.sql
```

### Script sẽ thực hiện:

1. ✅ Tạo bảng `player_configs` với các columns:
   - id, user_id, name, description
   - autoplay, loop, muted, show_controls, pip, airplay, chromecast
   - is_active, is_default, created_at, updated_at, version

2. ✅ Migrate dữ liệu từ `user_preferences` sang `player_configs`:
   - Mỗi user sẽ có 1 config mặc định tên "Default Config"
   - Description là "Migrated from user_preferences"

3. ✅ Xóa các columns player khỏi `user_preferences`:
   - autoplay, loop, muted
   - show_controls, pip, airplay, chromecast
   - encrytion_m3u8 (VIP feature không dùng)

4. ✅ Tạo indexes và triggers

## Bước 2: Regenerate Go Models

Sau khi migration xong, chạy:

```bash
go run cmd/gendb/main.go
```

Script này sẽ đọc schema mới từ database và regenerate:
- `internal/database/model/user_preferences.gen.go` (không còn player fields)
- `internal/database/model/player_configs.gen.go` (mới)
- `internal/database/query/*.gen.go`

## Bước 3: Cập nhật Code

Sau khi models được regenerate, cập nhật các file sau:

### 3.1. Cập nhật `internal/api/preferences/service.go`

```go
// Xóa các field player settings khỏi UpdateInput
type UpdateInput struct {
    EmailNotifications     *bool
    PushNotifications      *bool
    MarketingNotifications *bool
    TelegramNotifications  *bool
    // XÓA: Autoplay, Loop, Muted, ShowControls, Pip, Airplay, Chromecast
    Language               *string
    Locale                 *string
}

// Xóa logic update player settings khỏi UpdateUserPreferences
```

### 3.2. Cập nhật `internal/rpc/app/service_account.go`

```go
// UpdatePreferences chỉ update notification settings + language/locale
func (s *appServices) UpdatePreferences(...) {
    // Chỉ update các fields không phải player settings
    pref, err := preferencesapi.UpdateUserPreferences(ctx, s.db, s.logger, result.UserID, preferencesapi.UpdateInput{
        EmailNotifications:     req.EmailNotifications,
        PushNotifications:      req.PushNotifications,
        MarketingNotifications: req.MarketingNotifications,
        TelegramNotifications:  req.TelegramNotifications,
        Language:               req.Language,
        Locale:                 req.Locale,
        // XÓA: Autoplay, Loop, Muted, ShowControls, Pip, Airplay, Chromecast
    })
}
```

### 3.3. Sử dụng PlayerConfigs API cho player settings

Thay vì dùng `UpdatePreferences` cho player settings, dùng:

```go
// Tạo hoặc cập nhật default player config
func (s *appServices) UpdatePlayerSettings(ctx context.Context, req *appv1.UpdatePlayerSettingsRequest) {
    // Dùng player_configs API đã implement
    // ListPlayerConfigs, CreatePlayerConfig, UpdatePlayerConfig
}
```

## Bước 4: Build và Test

```bash
# Build
go build -o bin/api ./cmd/api

# Test migration
# 1. Kiểm tra bảng player_configs
psql -h 47.84.63.130 -U postgres -d video_db -c "SELECT COUNT(*) FROM player_configs;"

# 2. Kiểm tra user_preferences không còn player columns
psql -h 47.84.63.130 -U postgres -d video_db -c "\d user_preferences"
```

## Rollback (nếu cần)

Nếu muốn rollback:

```sql
-- Thêm lại columns vào user_preferences
ALTER TABLE user_preferences
    ADD COLUMN IF NOT EXISTS autoplay BOOLEAN DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS loop BOOLEAN DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS muted BOOLEAN DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS show_controls BOOLEAN DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS pip BOOLEAN DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS airplay BOOLEAN DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS chromecast BOOLEAN DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS encrytion_m3u8 BOOLEAN DEFAULT FALSE;

-- Copy dữ liệu từ player_configs về (cho default config)
UPDATE user_preferences up
SET autoplay = pc.autoplay,
    loop = pc.loop,
    muted = pc.muted,
    show_controls = pc.show_controls,
    pip = pc.pip,
    airplay = pc.airplay,
    chromecast = pc.chromecast
FROM player_configs pc
WHERE pc.user_id = up.user_id AND pc.is_default = TRUE;

-- Xóa bảng player_configs
DROP TABLE IF EXISTS player_configs CASCADE;
```

## Files liên quan

### Migration scripts:
- `migrations/001_create_player_configs_table.sql` - Tạo bảng
- `migrations/002_migrate_player_settings.sql` - Migrate data
- `full_player_configs_migration.sql` - Kết hợp cả 2
- `install_player_configs.sql` - Script đơn giản để chạy trực tiếp
- `migrate_player_configs.sh` - Shell script tự động hóa

### Models:
- `internal/database/model/player_configs.gen.go` - Model mới
- `internal/database/model/user_preferences.gen.go` - Model cũ (sẽ thay đổi)

### Services:
- `internal/rpc/app/service_user_features.go` - Player configs CRUD
- `internal/rpc/app/service_admin_finance_catalog.go` - Admin player configs
- `internal/api/preferences/service.go` - Legacy preferences (cần update)

### Frontend:
- `stream.ui/src/routes/settings/PlayerConfigs/PlayerConfigs.vue` - UI mới
- `stream.ui/src/routes/settings/Settings.vue` - Menu navigation

## Timeline khuyến nghị

1. **Tuần 1**: Chạy migration trên staging, test kỹ
2. **Tuần 2**: Cập nhật code backend (preferences service)
3. **Tuần 3**: Cập nhật frontend nếu cần
4. **Tuần 4**: Deploy production

## Lưu ý

- ✅ Backup database trước khi chạy migration
- ✅ Test trên staging trước khi production
- ✅ Migration có transaction, sẽ rollback nếu lỗi
- ✅ Dữ liệu user_preferences được giữ nguyên cho notification settings
