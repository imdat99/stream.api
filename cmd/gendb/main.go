package main

import (
	"log"
	"os"

	"gorm.io/driver/postgres"
	"gorm.io/gen"
	"gorm.io/gen/field"
	"gorm.io/gorm"
)

func main() {
	dsn := os.Getenv("APP_DATABASE_DSN")
	if dsn == "" {
		log.Fatal("APP_DATABASE_DSN is required")
	}

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("Không thể kết nối database:", err)
	}

	// 2. CẤU HÌNH GENERATOR
	g := gen.NewGenerator(gen.Config{
		OutPath:      "internal/database/query",
		ModelPkgPath: "internal/database/model",
		Mode:         gen.WithDefaultQuery | gen.WithQueryInterface, // Tạo cả query mặc định và interface để dễ mock test

		// Tùy chọn sinh code cho Model
		FieldNullable:     true, // Sinh pointer (*) cho các field có thể NULL trong DB
		FieldCoverable:    true, // Sinh pointer cho tất cả field (hữu ích khi dùng hàm Update zero value)
		FieldSignable:     true, // Hỗ trợ unsigned integer
		FieldWithIndexTag: true, // Sinh tag gorm:index
		FieldWithTypeTag:  true, // Sinh tag gorm:type
	})

	g.UseDB(db)

	// 3. XỬ LÝ KIỂU DỮ LIỆU (Data Mapping)
	// Ví dụ: Map decimal sang float64 thay vì string hoặc mảng byte
	dataMap := map[string]func(gorm.ColumnType) (dataType string){
		"decimal": func(columnType gorm.ColumnType) (dataType string) {
			return "float64" // Hoặc "decimal.Decimal" nếu dùng shopspring/decimal
		},
		"numeric": func(columnType gorm.ColumnType) (dataType string) {
			return "float64"
		},
		"text[]": func(columnType gorm.ColumnType) (dataType string) {
			return "[]string"
		},
		"_text": func(columnType gorm.ColumnType) (dataType string) {
			return "[]string"
		},
	}
	g.WithDataTypeMap(dataMap)
	g.WithImportPkgPath("github.com/lib/pq")

	// 4. CÁC TÙY CHỌN (OPTIONS)
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

	// 5. CHỌN TABLE ĐỂ GENERATE
	// GenerateAllTable() sẽ lấy tất cả, bao gồm cả bảng migration nếu có.
	// Nếu muốn loại trừ bảng nào đó, hãy dùng logic filter hoặc liệt kê cụ thể.

	// Cách 1: Lấy tất cả (như code cũ)
	allTables := g.GenerateAllTable()

	// Cách 2: (Khuyên dùng) Lọc bỏ các bảng rác hoặc hệ thống
	// var tableModels []interface{}
	// for _, tbl := range allTables {
	// 	  // Logic lọc bảng ở đây nếu cần
	//    tableModels = append(tableModels, tbl)
	// }

	g.ApplyBasic(allTables...)

	g.Execute()
}
