package database

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/glebarez/sqlite"
	"github.com/openppp2/openppp2-management/internal/config"
	"github.com/openppp2/openppp2-management/internal/model"
	"github.com/openppp2/openppp2-management/internal/security"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func Open(cfg config.Config) (*gorm.DB, error) {
	gormConfig := &gorm.Config{Logger: logger.Default.LogMode(logger.Warn)}

	if cfg.DatabaseDriver == "mysql" {
		return gorm.Open(mysql.Open(cfg.DatabaseDSN), gormConfig)
	}

	if err := os.MkdirAll(filepath.Dir(cfg.DatabasePath), 0o755); err != nil {
		return nil, err
	}
	dsn := fmt.Sprintf("file:%s?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)", filepath.ToSlash(cfg.DatabasePath))
	return gorm.Open(sqlite.Open(dsn), gormConfig)
}

func Migrate(db *gorm.DB) error {
	return db.AutoMigrate(
		&model.SystemSetting{},
		&model.User{},
		&model.PermissionGroup{},
		&model.UserPermissionGroup{},
		&model.NodePermissionGroup{},
		&model.Session{},
		&model.Device{},
		&model.SubscriptionToken{},
		&model.Node{},
		&model.DeviceNode{},
		&model.GUIDRule{},
		&model.OnlineSession{},
	)
}

func EnsurePermissionDefaults(db *gorm.DB) error {
	var group model.PermissionGroup
	result := db.Where("`key` = ?", "default").First(&group)
	if result.Error == nil {
		return nil
	}
	if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return result.Error
	}

	group = model.PermissionGroup{Key: "default", Name: "默认权限组", Enabled: true}
	return db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&group).Error; err != nil {
			return err
		}
		var users []model.User
		if err := tx.Find(&users).Error; err != nil {
			return err
		}
		for _, user := range users {
			if err := tx.Create(&model.UserPermissionGroup{UserID: user.ID, GroupID: group.ID}).Error; err != nil {
				return err
			}
		}
		var nodes []model.Node
		if err := tx.Find(&nodes).Error; err != nil {
			return err
		}
		for _, node := range nodes {
			if err := tx.Create(&model.NodePermissionGroup{NodeID: node.ID, GroupID: group.ID}).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

func EnsureInitialAdmin(db *gorm.DB, cfg config.Config) error {
	var count int64
	if err := db.Model(&model.User{}).Count(&count).Error; err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	if strings.TrimSpace(cfg.AdminPassword) == "" {
		return errors.New("OPENPPP2_ADMIN_PASSWORD is required when creating the initial administrator")
	}
	hash, err := security.HashPassword(cfg.AdminPassword)
	if err != nil {
		return err
	}
	return db.Create(&model.User{
		Username:     cfg.AdminUsername,
		DisplayName:  "Administrator",
		PasswordHash: hash,
		Role:         "admin",
		Enabled:      true,
	}).Error
}
