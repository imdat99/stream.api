package main

import (
	"log"

	"gorm.io/datatypes"
	"gorm.io/driver/postgres"
	"gorm.io/gen"
	"gorm.io/gen/field"
	"gorm.io/gorm"
	"stream.api/internal/config"
)

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatal(err)
	}

	dsn := cfg.Database.DSN
	if dsn == "" {
		log.Fatal("APP_DATABASE_DSN is required")
	}

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("Không thể kết nối database:", err)
	}

	g := gen.NewGenerator(gen.Config{
		OutPath:      "internal/database/query",
		ModelPkgPath: "internal/database/model",
		Mode:         gen.WithDefaultQuery | gen.WithQueryInterface,

		FieldNullable:     true,
		FieldCoverable:    true,
		FieldSignable:     true,
		FieldWithIndexTag: true,
		FieldWithTypeTag:  true,
	})

	g.UseDB(db)

	dataMap := map[string]func(gorm.ColumnType) string{
		"decimal": func(columnType gorm.ColumnType) string {
			return "float64"
		},
		"numeric": func(columnType gorm.ColumnType) string {
			return "float64"
		},
		"text[]": func(columnType gorm.ColumnType) string {
			return "pq.StringArray"
		},
		"_text": func(columnType gorm.ColumnType) string {
			return "pq.StringArray"
		},
		"json": func(columnType gorm.ColumnType) string {
			return "datatypes.JSON"
		},
		"jsonb": func(columnType gorm.ColumnType) string {
			return "datatypes.JSON"
		},
	}

	g.WithDataTypeMap(dataMap)
	g.WithImportPkgPath("github.com/lib/pq", "gorm.io/datatypes")

	g.WithOpts(
		gen.FieldType("id", "string"),
		gen.FieldType("features", "pq.StringArray"),
		gen.FieldGenType("features", "Field"),
		gen.FieldGORMTag("version", func(tag field.GormTag) field.GormTag {
			return tag.Set("version", "")
		}),
		gen.FieldJSONTag("password", "-"),
		gen.FieldJSONTag("version", "-"),
	)

	allTables := g.GenerateAllTable()
	g.ApplyBasic(allTables...)
	g.Execute()

	_ = datatypes.JSON{} // tránh import bị báo unused trong vài trường hợp
}
