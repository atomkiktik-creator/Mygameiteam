// =====================================================================
//  Digital Item Market — ตลาดกลางแลกเปลี่ยนไอเทมเกม (ธีม Steam Store)
//  ไฟล์เดียวจบ: Go (net/http) + GORM + MySQL-compatible DB + bcrypt
//
//  ฐานข้อมูลเดียวกันทั้งในเครื่อง (XAMPP) และบนคลาวด์ (TiDB Cloud) ตั้งค่าผ่าน env ล้วน ๆ
//  (ไม่ฝังรหัสผ่านในโค้ด):
//      DB_HOST (127.0.0.1)   DB_PORT (3306)   DB_USER (root)
//      DB_PASS (ว่าง)         DB_NAME (digital_market)
//      DB_TLS=true     <- จำเป็นสำหรับ TiDB Cloud (บังคับต่อแบบ TLS)
//      DB_NO_FK=1      <- ไม่บังคับ: ไม่สร้าง Foreign Key (ใช้ถ้าฐานข้อมูลไม่รองรับ)
//  อื่น ๆ: PORT (Render ตั้งให้เอง), ADMIN_PASSWORD, SEED_DEMO=1 (ข้อมูลตัวอย่าง)
//
//  รันในเครื่อง (XAMPP): เปิด MySQL ใน XAMPP -> go mod tidy -> go run .
//      เปิด http://localhost:8080  (admin / admin1234)  ดูข้อมูลที่ http://localhost/phpmyadmin
//  รันบนคลาวด์: ดูขั้นตอน GitHub + TiDB Cloud + Render (ใช้ Dockerfile ที่แนบมา)
//
//  ฟีเจอร์: สมัคร/ล็อกอิน, user/admin, CRUD ไอเทม (มีเจ้าของ) + อัปโหลดรูป, ความหายาก,
//           สถานะขายแล้ว, ยื่นข้อเสนอ + เจ้าของกดตกลง/ปฏิเสธ, รายการโปรด, หน้าผู้ขาย,
//           ค้นหา/กรอง/เรียง/แบ่งหน้า, เปลี่ยนรหัสผ่าน, Admin Dashboard (ลบไอเทม/ผู้ใช้)
//
//  🔒 สรุปความปลอดภัย (ดู comment "🔒" ในโค้ด)
//   1. SQL Injection      -> GORM + placeholder (?) ทุกคำสั่ง
//   2. Password           -> bcrypt
//   3. Broken Access Ctrl -> เช็ค OwnerID / Role ฝั่งเซิร์ฟเวอร์ก่อนแก้/ลบ/ตอบข้อเสนอเสมอ
//   4. XSS                -> html/template escape อัตโนมัติ
//   5. CSRF               -> token ทุกฟอร์ม POST + cookie SameSite
//   6. Session            -> token สุ่ม 256 บิต เก็บเฉพาะ hash, cookie HttpOnly (+Secure บน HTTPS)
//   7. Brute force        -> จำกัดล็อกอินผิด 5 ครั้ง / 10 นาที
//   8. Privilege escalation -> role ไม่รับจากฟอร์ม
//   9. File upload        -> ถอดรหัส+วาดรูปใหม่เป็น JPEG ทุกครั้ง (ล้างโค้ดแฝง), จำกัดขนาด/พิกเซล
//  10. Security headers + จำกัดขนาด request body
//  11. Secrets           -> รหัสฐานข้อมูล/แอดมินอยู่ใน env ไม่อยู่ในโค้ด
// =====================================================================
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"image"
	"image/color"
	"image/draw"
	_ "image/gif" // ลงทะเบียน decoder (ใช้ผ่าน image.Decode)
	"image/jpeg"
	_ "image/png"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	_ "time/tzdata" // ให้ตั้ง TZ=Asia/Bangkok ได้แม้ในคอนเทนเนอร์เปล่า
	"unicode/utf8"

	mysqldrv "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

// ---------------------------------------------------------------------
// 1) Models (GORM)
// ---------------------------------------------------------------------

type User struct {
	ID        uint   `gorm:"primaryKey"`
	Username  string `gorm:"uniqueIndex;size:30;not null"`
	Password  string `gorm:"size:100;not null"`             // 🔒 เก็บ bcrypt hash เท่านั้น
	Role      string `gorm:"size:20;not null;default:user"` // "user" | "admin"
	Bio       string `gorm:"size:200"`
	CreatedAt time.Time
}

// รูปไอเทม เก็บเป็น BLOB ในฐานข้อมูล (JPEG ที่ถูกย่อแล้ว) แยกตารางเพื่อไม่ให้ query รายการช้า
type Image struct {
	ID        uint `gorm:"primaryKey"`
	Data      []byte
	CreatedAt time.Time
}

type Item struct {
	ID          uint    `gorm:"primaryKey"`
	OwnerID     uint    `gorm:"index;not null"` // เจ้าของโพสต์ -> User.ID
	Owner       User    `gorm:"foreignKey:OwnerID"`
	Name        string  `gorm:"size:60;not null"`
	Game        string  `gorm:"size:40;not null"`
	Price       float64 `gorm:"not null"`
	Description string  `gorm:"size:300"`
	Rarity      string  `gorm:"size:20;not null;default:common"`    // common|rare|epic|legendary
	Status      string  `gorm:"size:20;not null;default:available"` // available|sold
	ImageID     uint    `gorm:"not null;default:0"`                 // 0 = ไม่มีรูป
	CreatedAt   time.Time
}

// ข้อเสนอต่อราคา
type Offer struct {
	ID        uint `gorm:"primaryKey"`
	ItemID    uint `gorm:"index;not null"`
	UserID    uint `gorm:"index;not null"`
	User      User `gorm:"foreignKey:UserID"`
	Item      Item `gorm:"-"` // เติมเองตอนแสดงผล ไม่อยู่ใน DB
	Amount    float64
	Message   string `gorm:"size:200"`
	Status    string `gorm:"size:20;not null;default:pending"` // pending|accepted|rejected
	CreatedAt time.Time
}

// รายการโปรด (wishlist)
type Favorite struct {
	ID        uint `gorm:"primaryKey"`
	UserID    uint `gorm:"uniqueIndex:idx_fav;not null"`
	ItemID    uint `gorm:"uniqueIndex:idx_fav;not null"`
	CreatedAt time.Time
}

type Session struct {
	TokenHash string `gorm:"primaryKey;size:64"` // 🔒 เก็บ hash ของ token
	UserID    uint   `gorm:"index"`
	Expiry    time.Time
}

// ---------------------------------------------------------------------
// 2) ค่าคงที่ / ตัวแปรกลาง
// ---------------------------------------------------------------------

const (
	perPage       = 12
	maxImageBytes = 5 << 20 // 5 MB
)

var (
	db         *gorm.DB
	pages      map[string]*template.Template
	dummyHash  []byte
	usernameRe = regexp.MustCompile(`^[A-Za-z0-9_]{3,20}$`)
	games      = []string{"Genshin Impact", "Valorant", "ROV", "Roblox", "Minecraft", "Free Fire", "PUBG", "RO Origin", "อื่น ๆ"}
)

type Opt struct {
	Value, Label string
	Selected     bool
}

var rarities = []Opt{
	{Value: "common", Label: "ทั่วไป"},
	{Value: "rare", Label: "หายาก"},
	{Value: "epic", Label: "มหากาพย์"},
	{Value: "legendary", Label: "ในตำนาน"},
}

var sorts = []Opt{
	{Value: "new", Label: "ใหม่ล่าสุด"},
	{Value: "price_asc", Label: "ราคา: ต่ำ → สูง"},
	{Value: "price_desc", Label: "ราคา: สูง → ต่ำ"},
}

// 🔒 whitelist สำหรับ ORDER BY (ห้ามเอาค่าจากผู้ใช้ไปต่อ SQL ตรง ๆ)
var orders = map[string]string{
	"new":        "id DESC",
	"price_asc":  "price ASC, id DESC",
	"price_desc": "price DESC, id DESC",
}

func markSelected(src []Opt, sel string) []Opt {
	out := make([]Opt, len(src))
	for i, o := range src {
		o.Selected = o.Value == sel
		out[i] = o
	}
	return out
}
func gameOpts(sel string) []Opt {
	out := make([]Opt, 0, len(games))
	for _, g := range games {
		out = append(out, Opt{Value: g, Label: g, Selected: g == sel})
	}
	return out
}
func rarityOpts(sel string) []Opt { return markSelected(rarities, sel) }
func sortOpts(sel string) []Opt   { return markSelected(sorts, sel) }

func validGame(g string) bool {
	for _, x := range games {
		if x == g {
			return true
		}
	}
	return false
}
func validRarity(k string) bool {
	for _, x := range rarities {
		if x.Value == k {
			return true
		}
	}
	return false
}
func rarityLabel(k string) string {
	for _, x := range rarities {
		if x.Value == k {
			return x.Label
		}
	}
	return k
}
func offerStatusLabel(s string) string {
	switch s {
	case "accepted":
		return "ตกลงขายแล้ว"
	case "rejected":
		return "ปฏิเสธ"
	}
	return "รอการตอบรับ"
}

// ข้อความแจ้งเตือนแบบกำหนดตายตัว (รับแค่ key ผ่าน URL จึงฉีดข้อความมั่วไม่ได้)
var flashes = map[string]string{
	"registered": "สมัครสมาชิกสำเร็จ! เข้าสู่ระบบได้เลย",
	"loggedout":  "ออกจากระบบแล้ว",
	"created":    "ตั้งขายไอเทมเรียบร้อย 🎉",
	"updated":    "บันทึกการแก้ไขแล้ว",
	"deleted":    "ลบเรียบร้อยแล้ว",
	"status":     "เปลี่ยนสถานะไอเทมแล้ว",
	"offer":      "ส่งข้อเสนอเรียบร้อย",
	"accepted":   "ตกลงขายแล้ว! ไอเทมถูกทำเครื่องหมายว่าขายแล้ว",
	"rejected":   "ปฏิเสธข้อเสนอแล้ว",
	"fav":        "อัปเดตรายการโปรดแล้ว",
	"profile":    "บันทึกโปรไฟล์แล้ว",
	"pwd":        "เปลี่ยนรหัสผ่านแล้ว (อุปกรณ์อื่นถูกออกจากระบบ)",
}

type ctxKey string

const (
	userKey ctxKey = "user"
	csrfKey ctxKey = "csrf"
)

// ---------------------------------------------------------------------
// 3) main
// ---------------------------------------------------------------------

func main() {
	var err error
	// บนคลาวด์ฐานข้อมูลอาจตื่นช้าตอนเริ่มต้น จึงลองต่อซ้ำได้หลายครั้ง (ในเครื่องลองครั้งเดียว)
	attempts := 1
	if os.Getenv("RENDER") != "" || isTrue(env("DB_TLS", "")) {
		attempts = 6
	}
	for i := 1; i <= attempts; i++ {
		db, err = openDB()
		if err == nil {
			break
		}
		log.Printf("เชื่อมฐานข้อมูลไม่สำเร็จ (ครั้งที่ %d/%d): %v", i, attempts, err)
		if i < attempts {
			time.Sleep(5 * time.Second)
		}
	}
	if err != nil {
		log.Fatal("เปิดฐานข้อมูลไม่ได้: ", err)
	}
	if err := db.AutoMigrate(&User{}, &Image{}, &Item{}, &Offer{}, &Favorite{}, &Session{}); err != nil {
		log.Fatal("สร้างตารางไม่ได้: ", err)
	}

	dummyHash, _ = bcrypt.GenerateFromPassword([]byte("dummy-password"), bcrypt.DefaultCost)
	seedAdmin()
	seedDemo()
	parseTemplates()

	mux := http.NewServeMux()
	// สาธารณะ
	mux.HandleFunc("GET /{$}", homeHandler)
	mux.HandleFunc("GET /item/{id}", itemHandler)
	mux.HandleFunc("GET /img/{id}", imageHandler)
	mux.HandleFunc("GET /u/{id}", userPageHandler)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("GET /login", loginPage)
	mux.HandleFunc("POST /login", loginPost)
	mux.HandleFunc("GET /register", registerPage)
	mux.HandleFunc("POST /register", registerPost)
	// ต้องล็อกอิน
	mux.HandleFunc("POST /logout", logoutPost)
	mux.HandleFunc("GET /my", requireLogin(myItemsHandler))
	mux.HandleFunc("GET /my/offers", requireLogin(myOffersHandler))
	mux.HandleFunc("GET /favorites", requireLogin(favoritesHandler))
	mux.HandleFunc("GET /items/new", requireLogin(newItemPage))
	mux.HandleFunc("POST /items/new", requireLogin(newItemPost))
	mux.HandleFunc("GET /items/{id}/edit", requireLogin(editItemPage))
	mux.HandleFunc("POST /items/{id}/edit", requireLogin(editItemPost))
	mux.HandleFunc("POST /items/{id}/delete", requireLogin(deleteItemPost))
	mux.HandleFunc("POST /items/{id}/status", requireLogin(statusPost))
	mux.HandleFunc("POST /item/{id}/offer", requireLogin(offerPost))
	mux.HandleFunc("POST /item/{id}/fav", requireLogin(favPost))
	mux.HandleFunc("POST /offers/{id}/accept", requireLogin(offerDecision(true)))
	mux.HandleFunc("POST /offers/{id}/reject", requireLogin(offerDecision(false)))
	mux.HandleFunc("GET /profile", requireLogin(profilePage))
	mux.HandleFunc("POST /profile", requireLogin(profilePost))
	mux.HandleFunc("POST /profile/password", requireLogin(passwordPost))
	// เฉพาะแอดมิน
	mux.HandleFunc("GET /admin", requireAdmin(adminPage))
	mux.HandleFunc("POST /admin/items/{id}/delete", requireAdmin(adminDeleteItem))
	mux.HandleFunc("POST /admin/users/{id}/delete", requireAdmin(adminDeleteUser))

	srv := &http.Server{
		Addr:              ":" + env("PORT", "8080"),
		Handler:           secureHeaders(csrfProtect(loadUser(mux))),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Println("🎮 Digital Item Market รันที่ http://localhost" + srv.Addr)
	log.Fatal(srv.ListenAndServe())
}

func isTrue(v string) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	return v == "1" || v == "true" || v == "yes"
}

// เชื่อม MySQL-compatible DB: XAMPP (MySQL/MariaDB) ในเครื่อง หรือ TiDB Cloud บนคลาวด์
// ตั้งค่าทั้งหมดผ่าน env (ดูหัวไฟล์)
func openDB() (*gorm.DB, error) {
	name := env("DB_NAME", "digital_market")
	// 🔒 ชื่อ DB ถูกต่อในคำสั่ง CREATE DATABASE (ใส่ placeholder ไม่ได้) จึงจำกัดอักขระก่อน
	if !regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`).MatchString(name) {
		return nil, errors.New("DB_NAME ใช้ได้เฉพาะ a-z A-Z 0-9 _")
	}

	cfg := mysqldrv.NewConfig()
	cfg.User = env("DB_USER", "root")
	cfg.Passwd = env("DB_PASS", "") // XAMPP ค่าเริ่มต้น root ไม่มีรหัสผ่าน
	cfg.Net = "tcp"
	cfg.Addr = env("DB_HOST", "127.0.0.1") + ":" + env("DB_PORT", "3306")
	cfg.Collation = "utf8mb4_unicode_ci" // รองรับภาษาไทย + อีโมจิ
	cfg.ParseTime = true
	cfg.Loc = time.Local
	cfg.Timeout = 15 * time.Second
	if isTrue(env("DB_TLS", "")) {
		cfg.TLSConfig = "true" // TiDB Cloud บังคับ TLS (ตรวจใบรับรองกับ CA ของระบบ)
	}
	gcfg := &gorm.Config{DisableForeignKeyConstraintWhenMigrating: isTrue(env("DB_NO_FK", ""))}

	// ขั้นที่ 1: ต่อเข้าเซิร์ฟเวอร์ (ยังไม่ระบุ DB) แล้วพยายามสร้างฐานข้อมูลถ้ายังไม่มี
	boot, err := gorm.Open(mysql.Open(cfg.FormatDSN()), gcfg)
	if err != nil {
		return nil, fmt.Errorf("ต่อฐานข้อมูลที่ %s ไม่ได้ — XAMPP: เปิด MySQL แล้วหรือยัง? / TiDB: ตรวจ DB_HOST DB_USER DB_PASS และ DB_TLS=true (%w)", cfg.Addr, err)
	}
	if err := boot.Exec("CREATE DATABASE IF NOT EXISTS `" + name + "` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci").Error; err != nil {
		// บนคลาวด์บางบัญชีสร้าง DB ไม่ได้ — ข้ามไป ใช้ฐานข้อมูลที่มีอยู่แล้ว (เช่น "test")
		log.Println("ข้ามการสร้างฐานข้อมูลอัตโนมัติ:", err)
	}
	if sqlDB, err := boot.DB(); err == nil {
		sqlDB.Close()
	}

	// ขั้นที่ 2: ต่อเข้าฐานข้อมูลของโปรเจกต์
	cfg.DBName = name
	d, err := gorm.Open(mysql.Open(cfg.FormatDSN()), gcfg)
	if err != nil {
		return nil, err
	}
	// ตั้งอายุ connection (TiDB Cloud แนะนำ) กัน connection ค้างเก่าแล้วหลุดกลางคัน
	if sqlDB, err := d.DB(); err == nil {
		sqlDB.SetMaxOpenConns(10)
		sqlDB.SetMaxIdleConns(5)
		sqlDB.SetConnMaxLifetime(4 * time.Minute)
		sqlDB.SetConnMaxIdleTime(2 * time.Minute)
	}
	log.Println("เชื่อมฐานข้อมูลสำเร็จ:", cfg.Addr, "ฐานข้อมูล", name, "| TLS:", cfg.TLSConfig == "true")
	return d, nil
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func seedAdmin() {
	var n int64
	db.Model(&User{}).Where("role = ?", "admin").Count(&n)
	if n > 0 {
		return
	}
	pw := os.Getenv("ADMIN_PASSWORD")
	switch {
	case pw == "" && os.Getenv("RENDER") != "":
		// 🔒 บนคลาวด์ห้ามใช้รหัสเริ่มต้น: สุ่มให้และแสดงใน Logs ครั้งเดียว (ควรตั้ง ADMIN_PASSWORD เอง)
		pw = randToken(8)
		log.Println("⚠️ ไม่ได้ตั้ง ADMIN_PASSWORD — สุ่มรหัสแอดมินให้: admin /", pw, "(รีบเปลี่ยนที่หน้าโปรไฟล์)")
	case pw == "":
		pw = "admin1234"
		log.Println("สร้างบัญชีแอดมินสำหรับทดสอบ: admin / admin1234 (ตั้ง ADMIN_PASSWORD เพื่อเปลี่ยน)")
	case len(pw) < 8 || len(pw) > 72:
		log.Println("⚠️ ADMIN_PASSWORD ควรยาว 8-72 ตัวอักษร")
	default:
		log.Println("สร้างบัญชีแอดมิน: admin (รหัสผ่านตาม ADMIN_PASSWORD)")
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err := db.Create(&User{Username: "admin", Password: string(hash), Role: "admin", Bio: "ผู้ดูแลระบบ"}).Error; err != nil {
		log.Println("สร้าง admin ไม่สำเร็จ:", err)
	}
}

// ข้อมูลตัวอย่าง (เปิดด้วย SEED_DEMO=1) ไว้ให้หน้าเว็บดูมีชีวิตตอนสาธิต
func seedDemo() {
	if env("SEED_DEMO", "") != "1" {
		return
	}
	var n int64
	db.Model(&Item{}).Count(&n)
	if n > 0 {
		return
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte("demo12345"), bcrypt.DefaultCost)
	u := User{Username: "demo_seller", Password: string(hash), Role: "user", Bio: "Discord: demo_seller#0001"}
	if err := db.Create(&u).Error; err != nil {
		return
	}
	demo := []Item{
		{Name: "ดาบมังกรเพลิง +15", Game: "ROV", Price: 1290, Rarity: "legendary", Description: "ไอเทมสายตี ค่าสถานะเต็ม พร้อมส่งมอบทันที"},
		{Name: "Primogem 3,280 เม็ด", Game: "Genshin Impact", Price: 1590, Rarity: "epic", Description: "เติมตรงเข้าบัญชี ปลอดภัย มีประกัน"},
		{Name: "Vandal Reaver Skin", Game: "Valorant", Price: 2450, Rarity: "legendary", Description: "สกินปืนยอดฮิต สภาพใหม่"},
		{Name: "Diamond Pickaxe (Enchanted)", Game: "Minecraft", Price: 89.5, Rarity: "rare", Description: "Efficiency V, Unbreaking III"},
		{Name: "Robux 800", Game: "Roblox", Price: 349, Rarity: "common", Description: "เติมผ่านโค้ด ส่งภายใน 10 นาที"},
		{Name: "ชุดไอดอลสุดแรร์", Game: "Free Fire", Price: 599, Rarity: "epic", Description: "ชุดอีเวนต์ที่ไม่มีขายแล้ว"},
	}
	for i := range demo {
		demo[i].OwnerID = u.ID
		demo[i].Status = "available"
		db.Create(&demo[i])
	}
	log.Println("เพิ่มข้อมูลตัวอย่างแล้ว (ผู้ขาย: demo_seller / demo12345)")
}

// ---------------------------------------------------------------------
// 4) Middleware
// ---------------------------------------------------------------------

// 🔒 Security headers + จำกัดขนาด body (หน้าอัปโหลดรูปให้ได้ 6 MB, อื่น ๆ 1 MB)
func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Content-Security-Policy", "frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'")
		limit := int64(1 << 20)
		if strings.HasPrefix(r.URL.Path, "/items/") {
			limit = 6 << 20
		}
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		next.ServeHTTP(w, r)
	})
}

// 🔒 CSRF: cookie "csrf" แบบสุ่ม + ทุกฟอร์ม POST ต้องส่งค่าเดียวกันใน hidden field
func csrfProtect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := ""
		if c, err := r.Cookie("csrf"); err == nil && len(c.Value) == 64 {
			token = c.Value
		} else {
			token = randToken(32)
			http.SetCookie(w, &http.Cookie{
				Name: "csrf", Value: token, Path: "/", MaxAge: 60 * 60 * 24 * 30,
				HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: isHTTPS(r),
			})
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
			if err := r.ParseMultipartForm(8 << 20); err != nil && !errors.Is(err, http.ErrNotMultipart) {
				http.Error(w, "ข้อมูลที่ส่งมาใหญ่เกินไปหรือไม่ถูกต้อง (รูปต้องไม่เกิน 5 MB)", http.StatusRequestEntityTooLarge)
				return
			}
			sent := r.PostFormValue("csrf_token")
			if subtle.ConstantTimeCompare([]byte(sent), []byte(token)) != 1 {
				http.Error(w, "CSRF token ไม่ถูกต้อง (403)", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), csrfKey, token)))
	})
}

func loadUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("session"); err == nil {
			var s Session
			// 🔒 GORM ใช้ placeholder => ปลอดภัยจาก SQL Injection
			if db.Where("token_hash = ? AND expiry > ?", hashToken(c.Value), time.Now()).First(&s).Error == nil {
				var u User
				if db.First(&u, s.UserID).Error == nil {
					r = r.WithContext(context.WithValue(r.Context(), userKey, &u))
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

func requireLogin(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if userFrom(r) == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		h(w, r)
	}
}

// 🔒 เช็ค role จากฐานข้อมูล (ผ่าน session) ไม่เชื่อค่าที่ client ส่งมา
func requireAdmin(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := userFrom(r)
		if u == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if u.Role != "admin" {
			errorPage(w, r, http.StatusForbidden, "หน้านี้สำหรับผู้ดูแลระบบเท่านั้น")
			return
		}
		h(w, r)
	}
}

func userFrom(r *http.Request) *User {
	u, _ := r.Context().Value(userKey).(*User)
	return u
}
func csrfFrom(r *http.Request) string {
	s, _ := r.Context().Value(csrfKey).(string)
	return s
}
func isHTTPS(r *http.Request) bool {
	return r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
}
func randToken(nBytes int) string {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
func hashToken(t string) string {
	s := sha256.Sum256([]byte(t))
	return hex.EncodeToString(s[:])
}
func clip(s string, n int) string {
	if utf8.RuneCountInString(s) > n {
		return string([]rune(s)[:n])
	}
	return s
}
func pathID(r *http.Request) (uint, bool) {
	n, err := strconv.ParseUint(r.PathValue("id"), 10, 32)
	return uint(n), err == nil && n > 0
}

// ---------------------------------------------------------------------
// 5) Auth
// ---------------------------------------------------------------------

func registerPage(w http.ResponseWriter, r *http.Request) {
	render(w, r, 200, "register", Page{Title: "สมัครสมาชิก", Data: ""})
}

func registerPost(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(r.PostFormValue("username"))
	password := r.PostFormValue("password")
	fail := func(msg string) {
		render(w, r, http.StatusBadRequest, "register", Page{Title: "สมัครสมาชิก", Error: msg, Data: username})
	}
	// 🔒 Validate input
	if !usernameRe.MatchString(username) {
		fail("ชื่อผู้ใช้ต้องเป็น a-z, 0-9, _ ความยาว 3-20 ตัว")
		return
	}
	if len(password) < 8 || len(password) > 72 { // bcrypt รองรับสูงสุด 72 ไบต์
		fail("รหัสผ่านต้องยาว 8-72 ตัวอักษร")
		return
	}
	if password != r.PostFormValue("confirm") {
		fail("รหัสผ่านทั้งสองช่องไม่ตรงกัน")
		return
	}
	var n int64
	db.Model(&User{}).Where("LOWER(username) = ?", strings.ToLower(username)).Count(&n)
	if n > 0 {
		fail("ชื่อผู้ใช้นี้ถูกใช้แล้ว")
		return
	}
	// 🔒 bcrypt: hash + salt อัตโนมัติ
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		fail("เกิดข้อผิดพลาด ลองใหม่อีกครั้ง")
		return
	}
	// 🔒 role ถูกกำหนดฝั่งเซิร์ฟเวอร์เป็น "user" เสมอ ไม่มีใครสมัครเป็น admin เองได้
	if err := db.Create(&User{Username: username, Password: string(hash), Role: "user"}).Error; err != nil {
		fail("ชื่อผู้ใช้นี้ถูกใช้แล้ว")
		return
	}
	http.Redirect(w, r, "/login?m=registered", http.StatusSeeOther)
}

func loginPage(w http.ResponseWriter, r *http.Request) {
	render(w, r, 200, "login", Page{Title: "เข้าสู่ระบบ"})
}

func loginPost(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(r.PostFormValue("username"))
	password := r.PostFormValue("password")
	key := clientIP(r) + "|" + strings.ToLower(username)

	if tooManyFails(key) { // 🔒 กัน brute force
		render(w, r, http.StatusTooManyRequests, "login", Page{Title: "เข้าสู่ระบบ", Error: "ลองผิดหลายครั้งเกินไป กรุณารอ 10 นาที"})
		return
	}
	var u User
	err := db.Where("username = ?", username).First(&u).Error
	hash := []byte(u.Password)
	if err != nil {
		hash = dummyHash // ไม่พบ user ก็ยังเทียบ hash หลอก ให้เวลาตอบใกล้เคียงกัน
	}
	if bcrypt.CompareHashAndPassword(hash, []byte(password)) != nil || err != nil {
		addFail(key)
		render(w, r, http.StatusUnauthorized, "login", Page{Title: "เข้าสู่ระบบ", Error: "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง"}) // 🔒 ข้อความกลาง ๆ
		return
	}
	clearFails(key)

	token := randToken(32)
	exp := time.Now().Add(7 * 24 * time.Hour)
	db.Where("expiry < ?", time.Now()).Delete(&Session{})
	if err := db.Create(&Session{TokenHash: hashToken(token), UserID: u.ID, Expiry: exp}).Error; err != nil {
		errorPage(w, r, 500, "สร้าง session ไม่สำเร็จ")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: "session", Value: token, Path: "/", Expires: exp,
		HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: isHTTPS(r),
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func logoutPost(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("session"); err == nil {
		db.Where("token_hash = ?", hashToken(c.Value)).Delete(&Session{})
	}
	http.SetCookie(w, &http.Cookie{Name: "session", Value: "", Path: "/", MaxAge: -1, HttpOnly: true})
	http.Redirect(w, r, "/login?m=loggedout", http.StatusSeeOther)
}

var (
	failMu sync.Mutex
	fails  = map[string][]time.Time{}
)

func recentFails(key string) []time.Time {
	var keep []time.Time
	for _, t := range fails[key] {
		if time.Since(t) < 10*time.Minute {
			keep = append(keep, t)
		}
	}
	return keep
}
func tooManyFails(key string) bool {
	failMu.Lock()
	defer failMu.Unlock()
	fails[key] = recentFails(key)
	return len(fails[key]) >= 5
}
func addFail(key string) {
	failMu.Lock()
	defer failMu.Unlock()
	fails[key] = append(recentFails(key), time.Now())
}
func clearFails(key string) {
	failMu.Lock()
	defer failMu.Unlock()
	delete(fails, key)
}
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ---------------------------------------------------------------------
// 6) รูปภาพ: อัปโหลด -> ตรวจ -> ย่อ -> บันทึก JPEG ลง DB
// ---------------------------------------------------------------------

// 🔒 ไม่เก็บไฟล์ที่ผู้ใช้ส่งมาตรง ๆ: ถอดรหัสเป็นภาพ แล้ววาดใหม่ + encode เป็น JPEG
// ทำให้ไฟล์ปลอม (เช่น .exe/.html ที่เปลี่ยนนามสกุล) หรือโค้ดแฝงในรูปใช้ไม่ได้
func readImage(r *http.Request) ([]byte, error) {
	file, hdr, err := r.FormFile("image")
	if err != nil {
		if errors.Is(err, http.ErrMissingFile) {
			return nil, nil // ไม่ได้เลือกรูป
		}
		return nil, errors.New("อ่านไฟล์รูปไม่สำเร็จ")
	}
	defer file.Close()
	if hdr.Size > maxImageBytes {
		return nil, errors.New("รูปต้องมีขนาดไม่เกิน 5 MB")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxImageBytes+1))
	if err != nil || len(raw) > maxImageBytes {
		return nil, errors.New("รูปต้องมีขนาดไม่เกิน 5 MB")
	}
	// กันรูป "ระเบิดพิกเซล" (ไฟล์เล็กแต่ขนาดภาพมหาศาล)
	cfg, _, err := image.DecodeConfig(bytes.NewReader(raw))
	if err != nil || cfg.Width < 1 || cfg.Height < 1 || cfg.Width > 5000 || cfg.Height > 5000 || cfg.Width*cfg.Height > 16_000_000 {
		return nil, errors.New("ไฟล์ต้องเป็นรูป JPG / PNG / GIF และขนาดไม่เกิน 4000×4000 พิกเซล")
	}
	img, _, err := image.Decode(bytes.NewReader(raw))
	if err != nil {
		return nil, errors.New("ไฟล์รูปเสียหาย หรือไม่ใช่รูปภาพ")
	}
	img = resizeFit(img, 1000, 1000)

	// วางบนพื้นหลังสีเข้ม (กันรูปโปร่งใสกลายเป็นสีดำเพี้ยน) แล้ว encode JPEG
	b := img.Bounds()
	canvas := image.NewRGBA(image.Rect(0, 0, b.Dx(), b.Dy()))
	draw.Draw(canvas, canvas.Bounds(), &image.Uniform{C: color.RGBA{R: 27, G: 40, B: 56, A: 255}}, image.Point{}, draw.Src)
	draw.Draw(canvas, canvas.Bounds(), img, b.Min, draw.Over)

	var buf bytes.Buffer
	// ลดคุณภาพลงเรื่อย ๆ จนไฟล์ < 900 KB (ให้ผ่าน max_allowed_packet 1 MB ของ MySQL ค่าเริ่มต้น)
	for q := 85; q >= 40; q -= 15 {
		buf.Reset()
		if err := jpeg.Encode(&buf, canvas, &jpeg.Options{Quality: q}); err != nil {
			return nil, errors.New("แปลงรูปไม่สำเร็จ")
		}
		if buf.Len() <= 900*1024 {
			break
		}
	}
	return buf.Bytes(), nil
}

// ย่อรูปให้พอดีกรอบ (เฉลี่ยพิกเซลแบบ box filter) ไม่ต้องพึ่งไลบรารีเพิ่ม
func resizeFit(src image.Image, maxW, maxH int) image.Image {
	b := src.Bounds()
	w, h := b.Dx(), b.Dy()
	if w <= maxW && h <= maxH {
		return src
	}
	scale := math.Min(float64(maxW)/float64(w), float64(maxH)/float64(h))
	nw, nh := int(float64(w)*scale), int(float64(h)*scale)
	if nw < 1 {
		nw = 1
	}
	if nh < 1 {
		nh = 1
	}
	dst := image.NewRGBA(image.Rect(0, 0, nw, nh))
	for y := 0; y < nh; y++ {
		sy0 := b.Min.Y + y*h/nh
		sy1 := b.Min.Y + (y+1)*h/nh
		if sy1 <= sy0 {
			sy1 = sy0 + 1
		}
		for x := 0; x < nw; x++ {
			sx0 := b.Min.X + x*w/nw
			sx1 := b.Min.X + (x+1)*w/nw
			if sx1 <= sx0 {
				sx1 = sx0 + 1
			}
			var sr, sg, sb, sa, n uint64
			for yy := sy0; yy < sy1; yy++ {
				for xx := sx0; xx < sx1; xx++ {
					cr, cg, cb, ca := src.At(xx, yy).RGBA()
					sr += uint64(cr)
					sg += uint64(cg)
					sb += uint64(cb)
					sa += uint64(ca)
					n++
				}
			}
			dst.SetRGBA(x, y, color.RGBA{
				R: uint8((sr / n) >> 8), G: uint8((sg / n) >> 8),
				B: uint8((sb / n) >> 8), A: uint8((sa / n) >> 8),
			})
		}
	}
	return dst
}

func imageHandler(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	var img Image
	if !ok || db.First(&img, id).Error != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "image/jpeg")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Write(img.Data)
}

// ---------------------------------------------------------------------
// 7) Items: หน้าแรก / รายละเอียด / CRUD + Data Ownership
// ---------------------------------------------------------------------

func parsePrice(s string) (float64, error) {
	f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) || f <= 0 || f > 1_000_000 {
		return 0, errors.New("ราคาต้องเป็นตัวเลขมากกว่า 0 และไม่เกิน 1,000,000")
	}
	return math.Round(f*100) / 100, nil
}

func findItem(w http.ResponseWriter, r *http.Request) (Item, bool) {
	id, ok := pathID(r)
	var it Item
	if !ok || db.Preload("Owner").First(&it, id).Error != nil {
		errorPage(w, r, http.StatusNotFound, "ไม่พบไอเทมนี้")
		return it, false
	}
	return it, true
}

func parseItemForm(r *http.Request) (Item, error) {
	it := Item{
		Name:        strings.TrimSpace(r.PostFormValue("name")),
		Game:        r.PostFormValue("game"),
		Rarity:      r.PostFormValue("rarity"),
		Description: strings.TrimSpace(r.PostFormValue("description")),
	}
	if n := utf8.RuneCountInString(it.Name); n < 2 || n > 60 {
		return it, errors.New("ชื่อไอเทมต้องยาว 2-60 ตัวอักษร")
	}
	if !validGame(it.Game) {
		return it, errors.New("กรุณาเลือกเกมจากรายการ")
	}
	if !validRarity(it.Rarity) {
		return it, errors.New("กรุณาเลือกความหายาก")
	}
	if utf8.RuneCountInString(it.Description) > 300 {
		return it, errors.New("รายละเอียดต้องไม่เกิน 300 ตัวอักษร")
	}
	p, err := parsePrice(r.PostFormValue("price"))
	if err != nil {
		return it, err
	}
	it.Price = p
	return it, nil
}

type ItemFormData struct {
	Heading, Action, Name, Price, Description string
	ImageID                                   uint
	Games, Rarities                           []Opt
}

func itemFormData(heading, action string, it Item, price string) ItemFormData {
	return ItemFormData{
		Heading: heading, Action: action, Name: it.Name, Price: price, Description: it.Description,
		ImageID: it.ImageID, Games: gameOpts(it.Game), Rarities: rarityOpts(it.Rarity),
	}
}

type HomeData struct {
	Items                    []Item
	Q                        string
	Games, Rarities, Sorts   []Opt
	Avail                    bool
	Total, Members, OnSale   int64
	Page, TotalPages         int
	PrevURL, NextURL         template.URL
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	qv := r.URL.Query()
	q := clip(strings.TrimSpace(qv.Get("q")), 60)
	game := qv.Get("game")
	if !validGame(game) {
		game = ""
	}
	rar := qv.Get("rarity")
	if !validRarity(rar) {
		rar = ""
	}
	sortKey := qv.Get("sort")
	orderBy, ok := orders[sortKey]
	if !ok {
		sortKey, orderBy = "new", orders["new"]
	}
	avail := qv.Get("avail") == "1"
	page, _ := strconv.Atoi(qv.Get("page"))
	if page < 1 {
		page = 1
	}

	// 🔒 ทุกเงื่อนไขใช้ placeholder; ORDER BY มาจาก whitelist เท่านั้น
	filter := func() *gorm.DB {
		tx := db.Model(&Item{})
		if q != "" {
			tx = tx.Where("name LIKE ?", "%"+q+"%")
		}
		if game != "" {
			tx = tx.Where("game = ?", game)
		}
		if rar != "" {
			tx = tx.Where("rarity = ?", rar)
		}
		if avail {
			tx = tx.Where("status = ?", "available")
		}
		return tx
	}
	var total int64
	filter().Count(&total)
	totalPages := int((total + perPage - 1) / perPage)
	if totalPages > 0 && page > totalPages {
		page = totalPages
	}
	var items []Item
	filter().Preload("Owner").Order(orderBy).Limit(perPage).Offset((page - 1) * perPage).Find(&items)

	v := url.Values{}
	if q != "" {
		v.Set("q", q)
	}
	if game != "" {
		v.Set("game", game)
	}
	if rar != "" {
		v.Set("rarity", rar)
	}
	if sortKey != "new" {
		v.Set("sort", sortKey)
	}
	if avail {
		v.Set("avail", "1")
	}
	link := func(p int) template.URL {
		vv := url.Values{}
		for k, x := range v {
			vv[k] = x
		}
		vv.Set("page", strconv.Itoa(p))
		return template.URL("/?" + vv.Encode())
	}
	d := HomeData{
		Items: items, Q: q, Games: gameOpts(game), Rarities: rarityOpts(rar), Sorts: sortOpts(sortKey),
		Avail: avail, Total: total, Page: page, TotalPages: totalPages,
	}
	if page > 1 {
		d.PrevURL = link(page - 1)
	}
	if page < totalPages {
		d.NextURL = link(page + 1)
	}
	db.Model(&User{}).Count(&d.Members)
	db.Model(&Item{}).Where("status = ?", "available").Count(&d.OnSale)
	render(w, r, 200, "home", Page{Title: "ร้านค้า", Data: d})
}

type ItemPageData struct {
	Item                              Item
	Offers                            []Offer
	IsOwner, IsAdmin, Fav, CanOffer   bool
	FavCount                          int64
	OfferAmount, OfferMsg             string
}

func itemHandler(w http.ResponseWriter, r *http.Request) {
	it, ok := findItem(w, r)
	if !ok {
		return
	}
	showItem(w, r, 200, it, "", "", "")
}

func showItem(w http.ResponseWriter, r *http.Request, status int, it Item, errMsg, amount, msg string) {
	var offers []Offer
	db.Preload("User").Where("item_id = ?", it.ID).Order("id DESC").Find(&offers)
	u := userFrom(r)
	d := ItemPageData{Item: it, Offers: offers, OfferAmount: amount, OfferMsg: msg}
	db.Model(&Favorite{}).Where("item_id = ?", it.ID).Count(&d.FavCount)
	if u != nil {
		d.IsOwner = u.ID == it.OwnerID
		d.IsAdmin = u.Role == "admin"
		d.CanOffer = !d.IsOwner && it.Status == "available"
		var n int64
		db.Model(&Favorite{}).Where("user_id = ? AND item_id = ?", u.ID, it.ID).Count(&n)
		d.Fav = n > 0
	}
	render(w, r, status, "item", Page{Title: it.Name, Error: errMsg, Data: d})
}

func myItemsHandler(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	var items []Item
	db.Where("owner_id = ?", u.ID).Order("id DESC").Find(&items)
	render(w, r, 200, "my", Page{Title: "ไอเทมของฉัน", Data: items})
}

func myOffersHandler(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	var offers []Offer
	db.Where("user_id = ?", u.ID).Order("id DESC").Find(&offers)
	ids := make([]uint, 0, len(offers))
	for _, o := range offers {
		ids = append(ids, o.ItemID)
	}
	byID := map[uint]Item{}
	if len(ids) > 0 {
		var its []Item
		db.Where("id IN ?", ids).Find(&its)
		for _, it := range its {
			byID[it.ID] = it
		}
	}
	for i := range offers {
		offers[i].Item = byID[offers[i].ItemID]
	}
	render(w, r, 200, "my_offers", Page{Title: "ข้อเสนอของฉัน", Data: offers})
}

func favoritesHandler(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	var items []Item
	db.Preload("Owner").Select("items.*").
		Joins("JOIN favorites ON favorites.item_id = items.id").
		Where("favorites.user_id = ?", u.ID).
		Order("favorites.id DESC").Find(&items)
	render(w, r, 200, "favorites", Page{Title: "รายการโปรด", Data: items})
}

type UserPageData struct {
	Seller User
	Items  []Item
}

func userPageHandler(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	var s User
	if !ok || db.First(&s, id).Error != nil {
		errorPage(w, r, http.StatusNotFound, "ไม่พบผู้ใช้นี้")
		return
	}
	var items []Item
	db.Preload("Owner").Where("owner_id = ?", s.ID).Order("id DESC").Find(&items)
	render(w, r, 200, "user", Page{Title: "ร้านของ " + s.Username, Data: UserPageData{Seller: s, Items: items}})
}

// ----- สร้าง (Create) -----

func newItemPage(w http.ResponseWriter, r *http.Request) {
	render(w, r, 200, "item_form", Page{Title: "ตั้งขายไอเทม",
		Data: itemFormData("ตั้งขายไอเทมใหม่", "/items/new", Item{Rarity: "common"}, "")})
}

func newItemPost(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	it, err := parseItemForm(r)
	var img []byte
	if err == nil {
		img, err = readImage(r)
	}
	if err != nil {
		render(w, r, http.StatusBadRequest, "item_form", Page{Title: "ตั้งขายไอเทม", Error: err.Error(),
			Data: itemFormData("ตั้งขายไอเทมใหม่", "/items/new", it, r.PostFormValue("price"))})
		return
	}
	// 🔒 OwnerID มาจาก session เสมอ ไม่รับจากฟอร์ม (กันสวมรอยเป็นเจ้าของคนอื่น)
	it.OwnerID = u.ID
	it.Status = "available"
	err = db.Transaction(func(tx *gorm.DB) error {
		if img != nil {
			im := Image{Data: img}
			if err := tx.Create(&im).Error; err != nil {
				return err
			}
			it.ImageID = im.ID
		}
		return tx.Create(&it).Error
	})
	if err != nil {
		log.Println("สร้างไอเทมไม่สำเร็จ:", err)
		errorPage(w, r, 500, "บันทึกไม่สำเร็จ (ถ้าใช้ MySQL ลองเพิ่มค่า max_allowed_packet)")
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/item/%d?m=created", it.ID), http.StatusSeeOther)
}

// ----- แก้ไข (Update) -----

func editItemPage(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	it, ok := findItem(w, r)
	if !ok {
		return
	}
	// 🔒 BROKEN ACCESS CONTROL: ผู้ใช้ A เปิดหน้าแก้ไขของ B ไม่ได้
	if it.OwnerID != u.ID {
		errorPage(w, r, http.StatusForbidden, "คุณไม่ใช่เจ้าของไอเทมนี้ จึงแก้ไขไม่ได้")
		return
	}
	render(w, r, 200, "item_form", Page{Title: "แก้ไขไอเทม", Data: itemFormData("แก้ไขไอเทม",
		fmt.Sprintf("/items/%d/edit", it.ID), it, strconv.FormatFloat(it.Price, 'f', -1, 64))})
}

func editItemPost(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	cur, ok := findItem(w, r)
	if !ok {
		return
	}
	// 🔒 BROKEN ACCESS CONTROL: เช็คเจ้าของก่อนแก้ไขทุกครั้ง (แอดมินก็แก้โพสต์คนอื่นไม่ได้ ลบได้อย่างเดียว)
	if cur.OwnerID != u.ID {
		errorPage(w, r, http.StatusForbidden, "คุณไม่ใช่เจ้าของไอเทมนี้ จึงแก้ไขไม่ได้")
		return
	}
	action := fmt.Sprintf("/items/%d/edit", cur.ID)
	in, err := parseItemForm(r)
	var newImg []byte
	if err == nil {
		newImg, err = readImage(r)
	}
	if err != nil {
		in.ImageID = cur.ImageID
		render(w, r, http.StatusBadRequest, "item_form", Page{Title: "แก้ไขไอเทม", Error: err.Error(),
			Data: itemFormData("แก้ไขไอเทม", action, in, r.PostFormValue("price"))})
		return
	}
	remove := r.PostFormValue("remove_image") == "1"
	err = db.Transaction(func(tx *gorm.DB) error {
		upd := map[string]any{
			"name": in.Name, "game": in.Game, "rarity": in.Rarity, "price": in.Price, "description": in.Description,
		}
		if newImg != nil {
			im := Image{Data: newImg}
			if err := tx.Create(&im).Error; err != nil {
				return err
			}
			upd["image_id"] = im.ID
		} else if remove {
			upd["image_id"] = 0
		}
		// 🔒 ป้องกันซ้ำชั้นที่ 2 ในระดับ SQL: WHERE owner_id = ผู้ใช้ปัจจุบัน
		if err := tx.Model(&Item{}).Where("id = ? AND owner_id = ?", cur.ID, u.ID).Updates(upd).Error; err != nil {
			return err
		}
		if cur.ImageID > 0 && (newImg != nil || remove) {
			return tx.Delete(&Image{}, cur.ImageID).Error // ลบรูปเก่า
		}
		return nil
	})
	if err != nil {
		log.Println("แก้ไขไอเทมไม่สำเร็จ:", err)
		errorPage(w, r, 500, "บันทึกไม่สำเร็จ (ถ้าใช้ MySQL ลองเพิ่มค่า max_allowed_packet)")
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/item/%d?m=updated", cur.ID), http.StatusSeeOther)
}

// ----- สถานะ ขายแล้ว / เปิดขาย -----

func statusPost(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	it, ok := findItem(w, r)
	if !ok {
		return
	}
	if it.OwnerID != u.ID { // 🔒 เฉพาะเจ้าของ
		errorPage(w, r, http.StatusForbidden, "คุณไม่ใช่เจ้าของไอเทมนี้")
		return
	}
	st := r.PostFormValue("status")
	if st != "sold" && st != "available" {
		errorPage(w, r, http.StatusBadRequest, "สถานะไม่ถูกต้อง")
		return
	}
	db.Model(&Item{}).Where("id = ? AND owner_id = ?", it.ID, u.ID).Update("status", st)
	http.Redirect(w, r, fmt.Sprintf("/item/%d?m=status", it.ID), http.StatusSeeOther)
}

// ----- ลบ (Delete) -----

func deleteItemPost(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	it, ok := findItem(w, r)
	if !ok {
		return
	}
	// 🔒 BROKEN ACCESS CONTROL: ลบได้เฉพาะ "เจ้าของ" หรือ "admin"
	if it.OwnerID != u.ID && u.Role != "admin" {
		errorPage(w, r, http.StatusForbidden, "คุณไม่ใช่เจ้าของไอเทมนี้ จึงลบไม่ได้")
		return
	}
	if err := removeItem(it.ID); err != nil {
		errorPage(w, r, 500, "ลบไม่สำเร็จ")
		return
	}
	if it.OwnerID != u.ID { // admin ลบของคนอื่น
		http.Redirect(w, r, "/admin?m=deleted", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/my?m=deleted", http.StatusSeeOther)
}

// ลบไอเทมพร้อมข้อมูลที่เกี่ยวข้อง (ข้อเสนอ, รายการโปรด, รูป)
func removeItemTx(tx *gorm.DB, id uint) error {
	var it Item
	if err := tx.First(&it, id).Error; err != nil {
		return err
	}
	if err := tx.Where("item_id = ?", id).Delete(&Offer{}).Error; err != nil {
		return err
	}
	if err := tx.Where("item_id = ?", id).Delete(&Favorite{}).Error; err != nil {
		return err
	}
	if err := tx.Delete(&Item{}, id).Error; err != nil {
		return err
	}
	if it.ImageID > 0 {
		return tx.Delete(&Image{}, it.ImageID).Error
	}
	return nil
}
func removeItem(id uint) error {
	return db.Transaction(func(tx *gorm.DB) error { return removeItemTx(tx, id) })
}

// ---------------------------------------------------------------------
// 8) ข้อเสนอ / รายการโปรด / โปรไฟล์
// ---------------------------------------------------------------------

func offerPost(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	it, ok := findItem(w, r)
	if !ok {
		return
	}
	if it.OwnerID == u.ID {
		errorPage(w, r, http.StatusForbidden, "ไม่สามารถเสนอราคาให้ไอเทมของตัวเองได้")
		return
	}
	if it.Status != "available" {
		errorPage(w, r, http.StatusBadRequest, "ไอเทมนี้ขายแล้ว ไม่รับข้อเสนอใหม่")
		return
	}
	amountRaw := r.PostFormValue("amount")
	msg := strings.TrimSpace(r.PostFormValue("message"))
	amount, err := parsePrice(amountRaw)
	if err != nil {
		showItem(w, r, http.StatusBadRequest, it, err.Error(), amountRaw, msg)
		return
	}
	if utf8.RuneCountInString(msg) > 200 {
		showItem(w, r, http.StatusBadRequest, it, "ข้อความต้องไม่เกิน 200 ตัวอักษร", amountRaw, msg)
		return
	}
	db.Create(&Offer{ItemID: it.ID, UserID: u.ID, Amount: amount, Message: msg, Status: "pending"})
	http.Redirect(w, r, fmt.Sprintf("/item/%d?m=offer", it.ID), http.StatusSeeOther)
}

// เจ้าของไอเทมกด ตกลง / ปฏิเสธ ข้อเสนอ
func offerDecision(accept bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := userFrom(r)
		oid, ok := pathID(r)
		var of Offer
		if !ok || db.First(&of, oid).Error != nil {
			errorPage(w, r, http.StatusNotFound, "ไม่พบข้อเสนอนี้")
			return
		}
		var it Item
		if db.First(&it, of.ItemID).Error != nil {
			errorPage(w, r, http.StatusNotFound, "ไม่พบไอเทมของข้อเสนอนี้")
			return
		}
		// 🔒 BROKEN ACCESS CONTROL: ตอบข้อเสนอได้เฉพาะ "เจ้าของไอเทม" เท่านั้น
		if it.OwnerID != u.ID {
			errorPage(w, r, http.StatusForbidden, "เฉพาะเจ้าของไอเทมเท่านั้นที่ตอบข้อเสนอได้")
			return
		}
		back := fmt.Sprintf("/item/%d", it.ID)
		if of.Status != "pending" {
			http.Redirect(w, r, back, http.StatusSeeOther)
			return
		}
		err := db.Transaction(func(tx *gorm.DB) error {
			if !accept {
				return tx.Model(&Offer{}).Where("id = ?", of.ID).Update("status", "rejected").Error
			}
			if it.Status != "available" {
				return errors.New("ไอเทมขายไปแล้ว")
			}
			if err := tx.Model(&Offer{}).Where("id = ?", of.ID).Update("status", "accepted").Error; err != nil {
				return err
			}
			if err := tx.Model(&Offer{}).Where("item_id = ? AND id <> ? AND status = ?", it.ID, of.ID, "pending").
				Update("status", "rejected").Error; err != nil {
				return err
			}
			return tx.Model(&Item{}).Where("id = ? AND owner_id = ?", it.ID, u.ID).Update("status", "sold").Error
		})
		if err != nil {
			errorPage(w, r, http.StatusBadRequest, "ดำเนินการไม่สำเร็จ: ไอเทมนี้อาจขายไปแล้ว")
			return
		}
		m := "rejected"
		if accept {
			m = "accepted"
		}
		http.Redirect(w, r, back+"?m="+m, http.StatusSeeOther)
	}
}

func favPost(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	it, ok := findItem(w, r)
	if !ok {
		return
	}
	var n int64
	db.Model(&Favorite{}).Where("user_id = ? AND item_id = ?", u.ID, it.ID).Count(&n)
	if n > 0 {
		db.Where("user_id = ? AND item_id = ?", u.ID, it.ID).Delete(&Favorite{})
	} else {
		db.Create(&Favorite{UserID: u.ID, ItemID: it.ID})
	}
	http.Redirect(w, r, fmt.Sprintf("/item/%d?m=fav", it.ID), http.StatusSeeOther)
}

func profilePage(w http.ResponseWriter, r *http.Request) {
	render(w, r, 200, "profile", Page{Title: "โปรไฟล์", Data: userFrom(r).Bio})
}

func profilePost(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	bio := strings.TrimSpace(r.PostFormValue("bio"))
	if utf8.RuneCountInString(bio) > 200 {
		render(w, r, http.StatusBadRequest, "profile", Page{Title: "โปรไฟล์", Error: "Bio ต้องไม่เกิน 200 ตัวอักษร", Data: bio})
		return
	}
	// 🔒 แก้เฉพาะแถวของตัวเอง (ID จาก session ไม่ใช่จากฟอร์ม)
	db.Model(&User{}).Where("id = ?", u.ID).Update("bio", bio)
	http.Redirect(w, r, "/profile?m=profile", http.StatusSeeOther)
}

func passwordPost(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	fail := func(msg string) {
		render(w, r, http.StatusBadRequest, "profile", Page{Title: "โปรไฟล์", Error: msg, Data: u.Bio})
	}
	old, nw := r.PostFormValue("old"), r.PostFormValue("new")
	if bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(old)) != nil {
		fail("รหัสผ่านเดิมไม่ถูกต้อง")
		return
	}
	if len(nw) < 8 || len(nw) > 72 {
		fail("รหัสผ่านใหม่ต้องยาว 8-72 ตัวอักษร")
		return
	}
	if nw != r.PostFormValue("confirm") {
		fail("รหัสผ่านใหม่ทั้งสองช่องไม่ตรงกัน")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(nw), bcrypt.DefaultCost)
	if err != nil {
		fail("เกิดข้อผิดพลาด ลองใหม่อีกครั้ง")
		return
	}
	db.Model(&User{}).Where("id = ?", u.ID).Update("password", string(hash))
	// 🔒 ออกจากระบบทุกอุปกรณ์อื่น (เก็บ session ปัจจุบันไว้)
	cur := ""
	if c, err := r.Cookie("session"); err == nil {
		cur = hashToken(c.Value)
	}
	db.Where("user_id = ? AND token_hash <> ?", u.ID, cur).Delete(&Session{})
	http.Redirect(w, r, "/profile?m=pwd", http.StatusSeeOther)
}

// ---------------------------------------------------------------------
// 9) Admin Dashboard
// ---------------------------------------------------------------------

type AdminData struct {
	Items                 []Item
	Users                 []User
	OfferCount, FavCount  int64
}

func adminPage(w http.ResponseWriter, r *http.Request) {
	var d AdminData
	db.Preload("Owner").Order("id DESC").Find(&d.Items)
	db.Order("id ASC").Find(&d.Users)
	db.Model(&Offer{}).Count(&d.OfferCount)
	db.Model(&Favorite{}).Count(&d.FavCount)
	render(w, r, 200, "admin", Page{Title: "Admin Dashboard", Data: d})
}

func adminDeleteItem(w http.ResponseWriter, r *http.Request) {
	it, ok := findItem(w, r)
	if !ok {
		return
	}
	if err := removeItem(it.ID); err != nil { // requireAdmin ตรวจ role ที่ชั้น route แล้ว
		errorPage(w, r, 500, "ลบไม่สำเร็จ")
		return
	}
	http.Redirect(w, r, "/admin?m=deleted", http.StatusSeeOther)
}

func adminDeleteUser(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	var target User
	if !ok || db.First(&target, id).Error != nil {
		errorPage(w, r, http.StatusNotFound, "ไม่พบผู้ใช้นี้")
		return
	}
	if target.Role == "admin" { // 🔒 ห้ามลบบัญชีแอดมิน (รวมถึงตัวเอง)
		errorPage(w, r, http.StatusForbidden, "ลบบัญชีแอดมินไม่ได้")
		return
	}
	err := db.Transaction(func(tx *gorm.DB) error {
		var ids []uint
		if err := tx.Model(&Item{}).Where("owner_id = ?", target.ID).Pluck("id", &ids).Error; err != nil {
			return err
		}
		for _, iid := range ids {
			if err := removeItemTx(tx, iid); err != nil {
				return err
			}
		}
		if err := tx.Where("user_id = ?", target.ID).Delete(&Offer{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", target.ID).Delete(&Favorite{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", target.ID).Delete(&Session{}).Error; err != nil {
			return err
		}
		return tx.Delete(&User{}, target.ID).Error
	})
	if err != nil {
		errorPage(w, r, 500, "ลบผู้ใช้ไม่สำเร็จ")
		return
	}
	http.Redirect(w, r, "/admin?m=deleted", http.StatusSeeOther)
}

// ---------------------------------------------------------------------
// 10) Template rendering
// ---------------------------------------------------------------------

type Page struct {
	Title string
	User  *User
	CSRF  string
	Flash string
	Error string
	Data  any
}

func render(w http.ResponseWriter, r *http.Request, status int, name string, p Page) {
	p.User = userFrom(r)
	p.CSRF = csrfFrom(r)
	if p.Flash == "" {
		p.Flash = flashes[r.URL.Query().Get("m")]
	}
	var buf bytes.Buffer
	// 🔒 html/template escape ข้อมูลผู้ใช้ทุกจุดอัตโนมัติ => กัน XSS
	if err := pages[name].ExecuteTemplate(&buf, "base", p); err != nil {
		log.Println("template error:", err)
		http.Error(w, "เกิดข้อผิดพลาดภายในระบบ", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	buf.WriteTo(w)
}

func errorPage(w http.ResponseWriter, r *http.Request, status int, msg string) {
	render(w, r, status, "error", Page{Title: "เกิดข้อผิดพลาด " + strconv.Itoa(status), Data: msg})
}

func parseTemplates() {
	funcs := template.FuncMap{"rarity": rarityLabel, "offerStatus": offerStatusLabel}
	pages = map[string]*template.Template{}
	for name, body := range pageSrc {
		t := template.Must(template.New("base").Funcs(funcs).Parse(baseTmpl))
		template.Must(t.New("content").Parse(body))
		pages[name] = t
	}
}

// ---------------------------------------------------------------------
// 11) HTML — ธีม Steam Store (Tailwind CDN + CSS ของเราเอง)
// ---------------------------------------------------------------------

const baseTmpl = `<!DOCTYPE html>
<html lang="th">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}} · Item Market</title>
<script src="https://cdn.tailwindcss.com"></script>
<link href="https://fonts.googleapis.com/css2?family=Noto+Sans+Thai:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<style>
  body{font-family:'Noto Sans Thai',Arial,Helvetica,sans-serif;color:#c6d4df;background:#1b2838 linear-gradient(180deg,#2a475e 0,#1b2838 520px) no-repeat;min-height:100vh}
  .topbar{background:#171a21;border-bottom:1px solid #000}
  .logo{font-weight:700;letter-spacing:.08em;color:#fff;text-transform:uppercase}
  .subnav{background:linear-gradient(90deg,rgba(61,108,142,.85),rgba(42,84,114,.5));border-radius:3px;display:flex;flex-wrap:wrap}
  .subnav a{padding:.55rem 1rem;font-size:.82rem;color:#c6d4df;text-transform:uppercase;letter-spacing:.03em}
  .subnav a:hover{background:#c6d4df;color:#1b2838}
  .card{background:rgba(0,0,0,.24);border:1px solid rgba(102,192,244,.1);border-radius:4px;box-shadow:0 0 12px rgba(0,0,0,.3)}
  .hero{background:linear-gradient(120deg,rgba(26,68,194,.4),rgba(102,192,244,.14) 55%,transparent),rgba(0,0,0,.28);border:1px solid rgba(102,192,244,.18);border-radius:4px}
  .sec-title{font-size:.8rem;text-transform:uppercase;letter-spacing:.06em;color:#fff;font-weight:600;border-bottom:1px solid rgba(255,255,255,.08);padding-bottom:.5rem}
  .page-title{font-size:1.9rem;font-weight:600;color:#fff;margin:.4rem 0 1rem;line-height:1.25}
  .crumbs{font-size:.8rem;color:#8f98a0}
  .crumbs a:hover{color:#fff}
  .muted{color:#8f98a0}
  .link{color:#66c0f4}
  .link:hover{color:#fff}
  .inp{width:100%;background:rgba(103,193,245,.1);border:1px solid #000;box-shadow:inset 1px 1px 0 rgba(0,0,0,.25);color:#fff;border-radius:3px;padding:.55rem .75rem}
  .inp:focus{outline:none;background:rgba(103,193,245,.2);border-color:#66c0f4}
  .inp::placeholder{color:#6b7c8c}
  select.inp option{background:#1b2838;color:#fff}
  .btn{display:inline-block;text-align:center;cursor:pointer;border:0;border-radius:2px;padding:.5rem 1.1rem;font-weight:500;color:#fff;background:linear-gradient(to right,#47bfff 5%,#1a44c2 95%);transition:.15s}
  .btn:hover{filter:brightness(1.15)}
  .btn-green{background:linear-gradient(to right,#75b022 5%,#588a1b 95%);color:#e8f7c8}
  .btn-ghost{background:rgba(103,193,245,.2);color:#67c1f5}
  .btn-ghost:hover{background:rgba(103,193,245,.35);color:#fff;filter:none}
  .btn-danger{background:linear-gradient(to right,#d9534f 5%,#a33a2e 95%)}
  .btn-sm{padding:.25rem .7rem;font-size:.82rem}
  .capsule{display:flex;flex-direction:column;background:linear-gradient(135deg,rgba(23,26,33,.92),rgba(30,45,62,.82));border-radius:3px;overflow:hidden;border:1px solid rgba(255,255,255,.04);transition:.15s}
  .capsule:hover{transform:translateY(-3px);border-color:#66c0f4;box-shadow:0 8px 24px rgba(0,0,0,.5)}
  .thumb{position:relative;aspect-ratio:460/215;background:#0e141b;overflow:hidden}
  .thumb img{width:100%;height:100%;object-fit:cover;display:block}
  .noimg{width:100%;height:100%;display:flex;align-items:center;justify-content:center;font-size:2.4rem;background:linear-gradient(135deg,#1b2838,#2a475e)}
  .noimg.big{font-size:5rem}
  .soldflag{position:absolute;top:.5rem;left:.5rem;background:#a33a2e;color:#fff;font-size:.72rem;font-weight:700;padding:.15rem .55rem;border-radius:2px;letter-spacing:.05em;z-index:1}
  .cbody{padding:.7rem .8rem .8rem;display:flex;flex-direction:column;gap:.45rem;flex:1}
  .cname{color:#fff;font-weight:500;font-size:1rem;line-height:1.3}
  .ctags{display:flex;flex-wrap:wrap;gap:.35rem}
  .tag{font-size:.72rem;padding:.1rem .5rem;border-radius:2px;background:rgba(103,193,245,.2);color:#67c1f5}
  .rar{font-size:.72rem;padding:.1rem .5rem;border-radius:2px;border:1px solid currentColor}
  .r-common{color:#9fb3c8}
  .r-rare{color:#4fb3ff}
  .r-epic{color:#c47bff}
  .r-legendary{color:#ffb84d}
  .cfoot{display:flex;justify-content:space-between;align-items:flex-end;margin-top:auto;padding-top:.3rem}
  .seller{font-size:.75rem;color:#8f98a0}
  .price{background:rgba(0,0,0,.45);color:#c6d4df;padding:.2rem .6rem;border-radius:2px;font-weight:600;white-space:nowrap}
  .pricebig{display:inline-block;font-size:1.7rem;font-weight:700;color:#a4d007;background:#000;padding:.15rem .8rem;border-radius:3px}
  .hero-img{position:relative;aspect-ratio:16/9;background:#0e141b;border-radius:4px;overflow:hidden;border:1px solid rgba(102,192,244,.12)}
  .hero-img img{width:100%;height:100%;object-fit:contain;display:block}
  .row{display:flex;justify-content:space-between;gap:1rem;padding:.4rem 0;border-top:1px solid rgba(255,255,255,.06);font-size:.88rem}
  .row span:first-child{color:#8f98a0}
  .offer{border-top:1px solid rgba(255,255,255,.07);padding:.8rem 0}
  .ost{font-size:.7rem;padding:.1rem .45rem;border-radius:2px;margin-left:.4rem}
  .st-pending{background:rgba(255,184,77,.15);color:#ffb84d}
  .st-accepted{background:rgba(164,208,7,.15);color:#a4d007}
  .st-rejected{background:rgba(217,83,79,.15);color:#ff8a85}
  .alert{border-radius:3px;padding:.7rem 1rem;margin-bottom:1rem;font-size:.92rem}
  .alert-ok{background:rgba(164,208,7,.12);border:1px solid rgba(164,208,7,.4);color:#c9e86a}
  .alert-err{background:rgba(217,83,79,.12);border:1px solid rgba(217,83,79,.45);color:#ff9a96}
  .chip{display:inline-block;background:rgba(0,0,0,.35);border:1px solid rgba(102,192,244,.2);border-radius:999px;padding:.2rem .8rem;font-size:.82rem;color:#c6d4df}
  label{display:block;font-size:.8rem;color:#8f98a0;margin-bottom:.3rem}
  table{width:100%;border-collapse:collapse}
  th{text-align:left;font-weight:500;color:#8f98a0;font-size:.76rem;text-transform:uppercase;padding:.6rem}
  td{padding:.6rem;border-top:1px solid rgba(255,255,255,.06);vertical-align:middle}
  .mini{width:64px;height:30px;object-fit:cover;border-radius:2px;background:#0e141b}
  .stat{font-size:2rem;font-weight:700;color:#fff;line-height:1}
</style>
</head>
<body class="antialiased">

<header class="topbar">
  <div class="max-w-6xl mx-auto px-4 h-14 flex items-center gap-4">
    <a href="/" class="logo text-lg">🎮 Item<span style="color:#66c0f4">Market</span></a>
    <div class="flex-1"></div>
    {{if .User}}
      <span class="text-sm hidden sm:inline">สวัสดี, <a class="link" href="/profile">{{.User.Username}}</a>{{if eq .User.Role "admin"}} <span class="tag">ADMIN</span>{{end}}</span>
      <form method="POST" action="/logout">
        <input type="hidden" name="csrf_token" value="{{.CSRF}}">
        <button class="btn btn-ghost btn-sm">ออกจากระบบ</button>
      </form>
    {{else}}
      <a href="/login" class="text-sm hover:text-white">เข้าสู่ระบบ</a>
      <a href="/register" class="btn btn-sm">สมัครสมาชิก</a>
    {{end}}
  </div>
</header>

<div class="max-w-6xl mx-auto px-4 mt-4">
  <nav class="subnav">
    <a href="/">ร้านค้า</a>
    {{if .User}}
      <a href="/items/new">+ ตั้งขายไอเทม</a>
      <a href="/my">ไอเทมของฉัน</a>
      <a href="/my/offers">ข้อเสนอของฉัน</a>
      <a href="/favorites">❤ รายการโปรด</a>
      <a href="/profile">โปรไฟล์</a>
      {{if eq .User.Role "admin"}}<a href="/admin">🛡 แอดมิน</a>{{end}}
    {{end}}
  </nav>
</div>

<main class="max-w-6xl mx-auto px-4 py-6">
  {{if .Flash}}<div class="alert alert-ok">{{.Flash}}</div>{{end}}
  {{if .Error}}<div class="alert alert-err">{{.Error}}</div>{{end}}
  {{template "content" .}}
</main>
<footer class="text-center text-xs py-8 muted">Digital Item Market · Go + GORM + MySQL</footer>
</body>
</html>

{{define "cards"}}
{{if .}}
<div class="grid sm:grid-cols-2 lg:grid-cols-3 gap-4">
  {{range .}}
  <a href="/item/{{.ID}}" class="capsule">
    <div class="thumb">
      {{if .ImageID}}<img src="/img/{{.ImageID}}" alt="{{.Name}}" loading="lazy">{{else}}<div class="noimg">🎮</div>{{end}}
      {{if eq .Status "sold"}}<span class="soldflag">ขายแล้ว</span>{{end}}
    </div>
    <div class="cbody">
      <div class="cname">{{.Name}}</div>
      <div class="ctags"><span class="tag">{{.Game}}</span><span class="rar r-{{.Rarity}}">{{rarity .Rarity}}</span></div>
      <div class="cfoot"><span class="seller">โดย {{.Owner.Username}}</span><span class="price">฿{{printf "%.2f" .Price}}</span></div>
    </div>
  </a>
  {{end}}
</div>
{{else}}
<div class="card p-10 text-center muted">ยังไม่มีไอเทมในรายการนี้</div>
{{end}}
{{end}}`

var pageSrc = map[string]string{

	// ---------------- ร้านค้า (หน้าแรก) ----------------
	"home": `
<section class="hero p-6 md:p-8 mb-6">
  <h1 class="text-3xl md:text-4xl font-bold text-white">ตลาดกลางแลกเปลี่ยนไอเทมเกม</h1>
  <p class="mt-2 muted">ซื้อ · ขาย · ต่อราคา ไอเทมเกมระหว่างเกมเมอร์ ปลอดภัย โปร่งใส</p>
  <div class="mt-4 flex flex-wrap gap-2 items-center">
    <span class="chip">🛒 วางขายอยู่ {{.Data.OnSale}} รายการ</span>
    <span class="chip">👥 สมาชิก {{.Data.Members}} คน</span>
    {{if .User}}<a href="/items/new" class="btn btn-green btn-sm">+ ตั้งขายไอเทม</a>{{else}}<a href="/register" class="btn btn-sm">เริ่มต้นใช้งานฟรี</a>{{end}}
  </div>
</section>

<div class="grid lg:grid-cols-4 gap-6">
  <aside class="lg:order-last">
    <form method="GET" action="/" class="card p-4 space-y-3">
      <div class="sec-title">ค้นหาและกรอง</div>
      <div><label>คำค้นหา</label><input class="inp" name="q" value="{{.Data.Q}}" placeholder="ชื่อไอเทม..."></div>
      <div><label>เกม</label>
        <select class="inp" name="game"><option value="">ทุกเกม</option>
          {{range .Data.Games}}<option value="{{.Value}}" {{if .Selected}}selected{{end}}>{{.Label}}</option>{{end}}
        </select></div>
      <div><label>ความหายาก</label>
        <select class="inp" name="rarity"><option value="">ทั้งหมด</option>
          {{range .Data.Rarities}}<option value="{{.Value}}" {{if .Selected}}selected{{end}}>{{.Label}}</option>{{end}}
        </select></div>
      <div><label>เรียงตาม</label>
        <select class="inp" name="sort">
          {{range .Data.Sorts}}<option value="{{.Value}}" {{if .Selected}}selected{{end}}>{{.Label}}</option>{{end}}
        </select></div>
      <label class="flex items-center gap-2" style="color:#c6d4df"><input type="checkbox" name="avail" value="1" {{if .Data.Avail}}checked{{end}}> แสดงเฉพาะที่ยังขายอยู่</label>
      <button class="btn w-full">ค้นหา</button>
      <a href="/" class="block text-center text-sm link">ล้างตัวกรอง</a>
    </form>
  </aside>

  <section class="lg:col-span-3">
    <div class="flex items-center justify-between mb-3">
      <h2 class="sec-title flex-1">ไอเทมทั้งหมด <span class="muted normal-case">({{.Data.Total}})</span></h2>
    </div>
    {{template "cards" .Data.Items}}
    {{if gt .Data.TotalPages 1}}
    <div class="flex items-center justify-center gap-4 mt-6">
      {{if .Data.PrevURL}}<a class="btn btn-ghost btn-sm" href="{{.Data.PrevURL}}">« ก่อนหน้า</a>{{end}}
      <span class="muted text-sm">หน้า {{.Data.Page}} / {{.Data.TotalPages}}</span>
      {{if .Data.NextURL}}<a class="btn btn-ghost btn-sm" href="{{.Data.NextURL}}">ถัดไป »</a>{{end}}
    </div>
    {{end}}
  </section>
</div>`,

	// ---------------- รายละเอียดไอเทม ----------------
	"item": `
<div class="crumbs"><a href="/">ร้านค้า</a> › <a href="/?game={{.Data.Item.Game}}">{{.Data.Item.Game}}</a> › {{.Data.Item.Name}}</div>
<h1 class="page-title">{{.Data.Item.Name}}</h1>

<div class="grid lg:grid-cols-3 gap-6">
  <div class="lg:col-span-2 space-y-6">
    <div class="hero-img">
      {{if .Data.Item.ImageID}}<img src="/img/{{.Data.Item.ImageID}}" alt="{{.Data.Item.Name}}">{{else}}<div class="noimg big">🎮</div>{{end}}
      {{if eq .Data.Item.Status "sold"}}<span class="soldflag">ขายแล้ว</span>{{end}}
    </div>

    <div class="card p-5">
      <div class="sec-title">รายละเอียดไอเทม</div>
      <p class="mt-3 whitespace-pre-line">{{if .Data.Item.Description}}{{.Data.Item.Description}}{{else}}<span class="muted">ผู้ขายไม่ได้ระบุรายละเอียดเพิ่มเติม</span>{{end}}</p>
    </div>

    <div class="card p-5">
      <div class="sec-title">ข้อเสนอต่อราคา ({{len .Data.Offers}})</div>
      {{range .Data.Offers}}
      <div class="offer">
        <div class="flex justify-between gap-3 flex-wrap items-center">
          <div><a class="link font-medium" href="/u/{{.UserID}}">{{.User.Username}}</a><span class="ost st-{{.Status}}">{{offerStatus .Status}}</span></div>
          <span class="price">฿{{printf "%.2f" .Amount}}</span>
        </div>
        {{if .Message}}<p class="muted text-sm mt-1">{{.Message}}</p>{{end}}
        <div class="flex items-center justify-between mt-2">
          <span class="text-xs muted">{{.CreatedAt.Format "02/01/2006 15:04"}}</span>
          {{if and $.Data.IsOwner (eq .Status "pending") (eq $.Data.Item.Status "available")}}
          <div class="flex gap-2">
            <form method="POST" action="/offers/{{.ID}}/accept"><input type="hidden" name="csrf_token" value="{{$.CSRF}}"><button class="btn btn-green btn-sm">✔ ตกลงขาย</button></form>
            <form method="POST" action="/offers/{{.ID}}/reject"><input type="hidden" name="csrf_token" value="{{$.CSRF}}"><button class="btn btn-danger btn-sm">✖ ปฏิเสธ</button></form>
          </div>
          {{end}}
        </div>
      </div>
      {{else}}
      <p class="muted mt-3">ยังไม่มีข้อเสนอ</p>
      {{end}}
    </div>
  </div>

  <aside class="space-y-4">
    <div class="card p-5">
      <div class="sec-title">ข้อมูลไอเทม</div>
      <div class="mt-2">
        <div class="row"><span>เกม</span><span class="tag">{{.Data.Item.Game}}</span></div>
        <div class="row"><span>ความหายาก</span><span class="rar r-{{.Data.Item.Rarity}}">{{rarity .Data.Item.Rarity}}</span></div>
        <div class="row"><span>สถานะ</span><span>{{if eq .Data.Item.Status "sold"}}<span style="color:#ff8a85">ขายแล้ว</span>{{else}}<span style="color:#a4d007">พร้อมขาย</span>{{end}}</span></div>
        <div class="row"><span>ลงขายเมื่อ</span><span>{{.Data.Item.CreatedAt.Format "02/01/2006"}}</span></div>
        <div class="row"><span>รายการโปรด</span><span>❤ {{.Data.FavCount}}</span></div>
      </div>
    </div>

    <div class="card p-5">
      <div class="pricebig">฿{{printf "%.2f" .Data.Item.Price}}</div>
      {{if .User}}{{if not .Data.IsOwner}}
      <form method="POST" action="/item/{{.Data.Item.ID}}/fav" class="mt-3">
        <input type="hidden" name="csrf_token" value="{{.CSRF}}">
        <button class="btn btn-ghost w-full">{{if .Data.Fav}}💔 เอาออกจากรายการโปรด{{else}}❤ เพิ่มในรายการโปรด{{end}}</button>
      </form>
      {{end}}{{end}}

      <div class="mt-4">
      {{if eq .Data.Item.Status "sold"}}
        <p class="muted text-sm">ไอเทมนี้ขายแล้ว ไม่รับข้อเสนอใหม่</p>
      {{else if not .User}}
        <p class="text-sm"><a class="link underline" href="/login">เข้าสู่ระบบ</a> เพื่อยื่นข้อเสนอราคา</p>
      {{else if .Data.IsOwner}}
        <p class="muted text-sm">นี่คือไอเทมของคุณเอง</p>
      {{else}}
        <form method="POST" action="/item/{{.Data.Item.ID}}/offer" class="space-y-3">
          <input type="hidden" name="csrf_token" value="{{.CSRF}}">
          <div><label>ราคาที่เสนอ (บาท)</label><input class="inp" type="number" step="0.01" min="0.01" name="amount" value="{{.Data.OfferAmount}}" required></div>
          <div><label>ข้อความถึงผู้ขาย</label><textarea class="inp" rows="3" maxlength="200" name="message">{{.Data.OfferMsg}}</textarea></div>
          <button class="btn btn-green w-full">ส่งข้อเสนอ</button>
        </form>
      {{end}}
      </div>
    </div>

    <div class="card p-5">
      <div class="sec-title">ผู้ขาย</div>
      <a class="link text-lg font-medium block mt-2" href="/u/{{.Data.Item.OwnerID}}">{{.Data.Item.Owner.Username}}</a>
      <p class="muted text-sm mt-1">{{if .Data.Item.Owner.Bio}}{{.Data.Item.Owner.Bio}}{{else}}ยังไม่มีข้อมูลติดต่อ{{end}}</p>
    </div>

    {{if or .Data.IsOwner .Data.IsAdmin}}
    <div class="card p-5 space-y-2">
      <div class="sec-title">จัดการ</div>
      {{if .Data.IsOwner}}
        <a class="btn btn-ghost w-full mt-2" href="/items/{{.Data.Item.ID}}/edit">✏️ แก้ไขไอเทม</a>
        <form method="POST" action="/items/{{.Data.Item.ID}}/status">
          <input type="hidden" name="csrf_token" value="{{.CSRF}}">
          {{if eq .Data.Item.Status "available"}}
            <input type="hidden" name="status" value="sold"><button class="btn btn-green w-full">✔ ทำเครื่องหมายว่าขายแล้ว</button>
          {{else}}
            <input type="hidden" name="status" value="available"><button class="btn btn-ghost w-full">เปิดขายอีกครั้ง</button>
          {{end}}
        </form>
      {{end}}
      <form method="POST" action="/items/{{.Data.Item.ID}}/delete" onsubmit="return confirm('ยืนยันลบไอเทมนี้?')">
        <input type="hidden" name="csrf_token" value="{{.CSRF}}">
        <button class="btn btn-danger w-full">🗑 ลบไอเทม</button>
      </form>
    </div>
    {{end}}
  </aside>
</div>`,

	// ---------------- ฟอร์มตั้งขาย / แก้ไข ----------------
	"item_form": `
<div class="max-w-2xl mx-auto card p-6">
  <h1 class="text-2xl font-semibold text-white">{{.Data.Heading}}</h1>
  <form method="POST" action="{{.Data.Action}}" enctype="multipart/form-data" class="mt-5 space-y-4">
    <input type="hidden" name="csrf_token" value="{{.CSRF}}">
    <div class="grid md:grid-cols-2 gap-4">
      <div><label>ชื่อไอเทม</label><input class="inp" name="name" value="{{.Data.Name}}" minlength="2" maxlength="60" required></div>
      <div><label>หมวดหมู่เกม</label>
        <select class="inp" name="game" required>
          {{range .Data.Games}}<option value="{{.Value}}" {{if .Selected}}selected{{end}}>{{.Label}}</option>{{end}}
        </select></div>
    </div>
    <div class="grid md:grid-cols-2 gap-4">
      <div><label>ความหายาก</label>
        <select class="inp" name="rarity" required>
          {{range .Data.Rarities}}<option value="{{.Value}}" {{if .Selected}}selected{{end}}>{{.Label}}</option>{{end}}
        </select></div>
      <div><label>ราคา (บาท)</label><input class="inp" type="number" step="0.01" min="0.01" max="1000000" name="price" value="{{.Data.Price}}" required></div>
    </div>
    <div><label>รายละเอียด (ไม่บังคับ)</label><textarea class="inp" rows="4" maxlength="300" name="description">{{.Data.Description}}</textarea></div>
    <div>
      <label>รูปไอเทม (JPG / PNG / GIF ไม่เกิน 5 MB — ระบบจะย่อรูปให้อัตโนมัติ)</label>
      {{if .Data.ImageID}}
      <div class="mb-3">
        <img src="/img/{{.Data.ImageID}}" alt="" class="rounded" style="max-height:160px">
        <label class="mt-2 flex items-center gap-2" style="color:#c6d4df"><input type="checkbox" name="remove_image" value="1"> ลบรูปปัจจุบัน (หรือเลือกไฟล์ใหม่ด้านล่างเพื่อเปลี่ยนรูป)</label>
      </div>
      {{end}}
      <input id="imgfile" class="inp" type="file" name="image" accept="image/png,image/jpeg,image/gif">
      <img id="imgprev" alt="" class="rounded mt-3" style="display:none;max-height:200px">
    </div>
    <div class="flex gap-3"><button class="btn btn-green">บันทึก</button><a class="btn btn-ghost" href="/">ยกเลิก</a></div>
  </form>
</div>
<script>
  var fileInput = document.getElementById('imgfile');
  if (fileInput) {
    fileInput.addEventListener('change', function (e) {
      var f = e.target.files[0];
      var p = document.getElementById('imgprev');
      if (!f) { p.style.display = 'none'; return; }
      if (f.size > 5 * 1024 * 1024) { alert('รูปต้องมีขนาดไม่เกิน 5 MB'); e.target.value = ''; p.style.display = 'none'; return; }
      p.src = URL.createObjectURL(f);
      p.style.display = 'block';
    });
  }
</script>`,

	// ---------------- ไอเทมของฉัน ----------------
	"my": `
<div class="flex items-center justify-between mb-4">
  <h1 class="page-title" style="margin:0">ไอเทมของฉัน</h1>
  <a href="/items/new" class="btn btn-green">+ ตั้งขายไอเทม</a>
</div>
<div class="card overflow-x-auto">
  <table>
    <thead><tr><th></th><th>ไอเทม</th><th>เกม</th><th>ราคา</th><th>สถานะ</th><th></th></tr></thead>
    <tbody>
    {{range .Data}}
      <tr>
        <td>{{if .ImageID}}<img class="mini" src="/img/{{.ImageID}}" alt="">{{else}}<span class="mini flex items-center justify-center">🎮</span>{{end}}</td>
        <td><a class="link" href="/item/{{.ID}}">{{.Name}}</a><div class="text-xs"><span class="r-{{.Rarity}}">{{rarity .Rarity}}</span></div></td>
        <td>{{.Game}}</td>
        <td>฿{{printf "%.2f" .Price}}</td>
        <td>{{if eq .Status "sold"}}<span style="color:#ff8a85">ขายแล้ว</span>{{else}}<span style="color:#a4d007">พร้อมขาย</span>{{end}}</td>
        <td>
          <div class="flex gap-2 justify-end flex-wrap">
            <a class="btn btn-ghost btn-sm" href="/items/{{.ID}}/edit">แก้ไข</a>
            <form method="POST" action="/items/{{.ID}}/status">
              <input type="hidden" name="csrf_token" value="{{$.CSRF}}">
              {{if eq .Status "available"}}<input type="hidden" name="status" value="sold"><button class="btn btn-green btn-sm">ขายแล้ว</button>
              {{else}}<input type="hidden" name="status" value="available"><button class="btn btn-ghost btn-sm">เปิดขาย</button>{{end}}
            </form>
            <form method="POST" action="/items/{{.ID}}/delete" onsubmit="return confirm('ยืนยันลบไอเทมนี้?')">
              <input type="hidden" name="csrf_token" value="{{$.CSRF}}">
              <button class="btn btn-danger btn-sm">ลบ</button>
            </form>
          </div>
        </td>
      </tr>
    {{else}}
      <tr><td colspan="6" class="text-center muted py-10">คุณยังไม่ได้ตั้งขายไอเทม</td></tr>
    {{end}}
    </tbody>
  </table>
</div>`,

	// ---------------- ข้อเสนอที่ฉันส่ง ----------------
	"my_offers": `
<h1 class="page-title">ข้อเสนอของฉัน</h1>
<div class="card overflow-x-auto">
  <table>
    <thead><tr><th>ไอเทม</th><th>ราคาที่เสนอ</th><th>ข้อความ</th><th>สถานะ</th><th>เมื่อ</th></tr></thead>
    <tbody>
    {{range .Data}}
      <tr>
        <td>{{if .Item.ID}}<a class="link" href="/item/{{.Item.ID}}">{{.Item.Name}}</a>{{else}}<span class="muted">(ไอเทมถูกลบ)</span>{{end}}</td>
        <td>฿{{printf "%.2f" .Amount}}</td>
        <td class="muted text-sm">{{.Message}}</td>
        <td><span class="ost st-{{.Status}}" style="margin-left:0">{{offerStatus .Status}}</span></td>
        <td class="muted text-sm">{{.CreatedAt.Format "02/01/2006 15:04"}}</td>
      </tr>
    {{else}}
      <tr><td colspan="5" class="text-center muted py-10">คุณยังไม่ได้ยื่นข้อเสนอให้ใคร</td></tr>
    {{end}}
    </tbody>
  </table>
</div>`,

	// ---------------- รายการโปรด ----------------
	"favorites": `
<h1 class="page-title">❤ รายการโปรดของฉัน</h1>
{{template "cards" .Data}}`,

	// ---------------- หน้าผู้ขาย ----------------
	"user": `
<section class="hero p-6 mb-6">
  <div class="text-xs muted uppercase tracking-wider">ร้านค้าของ</div>
  <h1 class="text-3xl font-bold text-white">{{.Data.Seller.Username}} {{if eq .Data.Seller.Role "admin"}}<span class="tag">ADMIN</span>{{end}}</h1>
  <p class="mt-2 muted">{{if .Data.Seller.Bio}}{{.Data.Seller.Bio}}{{else}}ยังไม่มีข้อมูลติดต่อ{{end}}</p>
  <p class="mt-2 text-xs muted">สมาชิกตั้งแต่ {{.Data.Seller.CreatedAt.Format "02/01/2006"}} · {{len .Data.Items}} ไอเทม</p>
</section>
{{template "cards" .Data.Items}}`,

	// ---------------- โปรไฟล์ ----------------
	"profile": `
<h1 class="page-title">โปรไฟล์ของฉัน</h1>
<div class="grid md:grid-cols-2 gap-6">
  <div class="card p-6">
    <div class="sec-title">ข้อมูลส่วนตัว</div>
    <p class="mt-3 text-sm">ชื่อผู้ใช้: <b class="text-white">{{.User.Username}}</b> · สิทธิ์: <span class="tag">{{.User.Role}}</span></p>
    <form method="POST" action="/profile" class="mt-4 space-y-4">
      <input type="hidden" name="csrf_token" value="{{.CSRF}}">
      <div><label>Bio / ช่องทางติดต่อ (เช่น Discord, LINE)</label><textarea class="inp" rows="4" maxlength="200" name="bio">{{.Data}}</textarea></div>
      <button class="btn btn-green">บันทึกโปรไฟล์</button>
      <a class="btn btn-ghost" href="/u/{{.User.ID}}">ดูหน้าร้านของฉัน</a>
    </form>
  </div>
  <div class="card p-6">
    <div class="sec-title">เปลี่ยนรหัสผ่าน</div>
    <form method="POST" action="/profile/password" class="mt-4 space-y-4">
      <input type="hidden" name="csrf_token" value="{{.CSRF}}">
      <div><label>รหัสผ่านเดิม</label><input class="inp" type="password" name="old" autocomplete="current-password" required></div>
      <div><label>รหัสผ่านใหม่ (8-72 ตัว)</label><input class="inp" type="password" name="new" minlength="8" maxlength="72" autocomplete="new-password" required></div>
      <div><label>ยืนยันรหัสผ่านใหม่</label><input class="inp" type="password" name="confirm" minlength="8" maxlength="72" autocomplete="new-password" required></div>
      <button class="btn">เปลี่ยนรหัสผ่าน</button>
    </form>
  </div>
</div>`,

	// ---------------- Admin Dashboard ----------------
	"admin": `
<h1 class="page-title">🛡 Admin Dashboard</h1>
<div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
  <div class="card p-4"><div class="text-xs muted mb-1">ผู้ใช้ทั้งหมด</div><div class="stat" style="color:#66c0f4">{{len .Data.Users}}</div></div>
  <div class="card p-4"><div class="text-xs muted mb-1">ไอเทมทั้งหมด</div><div class="stat" style="color:#a4d007">{{len .Data.Items}}</div></div>
  <div class="card p-4"><div class="text-xs muted mb-1">ข้อเสนอทั้งหมด</div><div class="stat" style="color:#ffb84d">{{.Data.OfferCount}}</div></div>
  <div class="card p-4"><div class="text-xs muted mb-1">รายการโปรดทั้งหมด</div><div class="stat" style="color:#c47bff">{{.Data.FavCount}}</div></div>
</div>

<div class="sec-title mb-3">ไอเทมทั้งหมดในระบบ</div>
<div class="card overflow-x-auto mb-8">
  <table>
    <thead><tr><th>#</th><th></th><th>ไอเทม</th><th>เกม</th><th>ราคา</th><th>สถานะ</th><th>ผู้ขาย</th><th></th></tr></thead>
    <tbody>
    {{range .Data.Items}}
      <tr>
        <td>{{.ID}}</td>
        <td>{{if .ImageID}}<img class="mini" src="/img/{{.ImageID}}" alt="">{{else}}<span class="mini flex items-center justify-center">🎮</span>{{end}}</td>
        <td><a class="link" href="/item/{{.ID}}">{{.Name}}</a></td>
        <td>{{.Game}}</td>
        <td>฿{{printf "%.2f" .Price}}</td>
        <td>{{if eq .Status "sold"}}<span style="color:#ff8a85">ขายแล้ว</span>{{else}}<span style="color:#a4d007">พร้อมขาย</span>{{end}}</td>
        <td><a class="link" href="/u/{{.OwnerID}}">{{.Owner.Username}}</a></td>
        <td class="text-right">
          <form method="POST" action="/admin/items/{{.ID}}/delete" onsubmit="return confirm('ลบไอเทมที่ผิดกฎนี้?')">
            <input type="hidden" name="csrf_token" value="{{$.CSRF}}">
            <button class="btn btn-danger btn-sm">ลบ</button>
          </form>
        </td>
      </tr>
    {{else}}
      <tr><td colspan="8" class="text-center muted py-10">ยังไม่มีไอเทมในระบบ</td></tr>
    {{end}}
    </tbody>
  </table>
</div>

<div class="sec-title mb-3">ผู้ใช้ทั้งหมด</div>
<div class="card overflow-x-auto">
  <table>
    <thead><tr><th>#</th><th>ชื่อผู้ใช้</th><th>สิทธิ์</th><th>สมัครเมื่อ</th><th></th></tr></thead>
    <tbody>
    {{range .Data.Users}}
      <tr>
        <td>{{.ID}}</td>
        <td><a class="link" href="/u/{{.ID}}">{{.Username}}</a></td>
        <td><span class="tag">{{.Role}}</span></td>
        <td class="muted text-sm">{{.CreatedAt.Format "02/01/2006 15:04"}}</td>
        <td class="text-right">
          {{if ne .Role "admin"}}
          <form method="POST" action="/admin/users/{{.ID}}/delete" onsubmit="return confirm('ลบผู้ใช้นี้พร้อมไอเทมและข้อเสนอทั้งหมดของเขา?')">
            <input type="hidden" name="csrf_token" value="{{$.CSRF}}">
            <button class="btn btn-danger btn-sm">ลบผู้ใช้</button>
          </form>
          {{end}}
        </td>
      </tr>
    {{end}}
    </tbody>
  </table>
</div>`,

	// ---------------- Login / Register / Error ----------------
	"login": `
<div class="max-w-md mx-auto card p-6">
  <h1 class="text-2xl font-semibold text-white">เข้าสู่ระบบ</h1>
  <form method="POST" action="/login" class="mt-5 space-y-4">
    <input type="hidden" name="csrf_token" value="{{.CSRF}}">
    <div><label>ชื่อผู้ใช้</label><input class="inp" name="username" autocomplete="username" required></div>
    <div><label>รหัสผ่าน</label><input class="inp" type="password" name="password" autocomplete="current-password" required></div>
    <button class="btn w-full">เข้าสู่ระบบ</button>
  </form>
  <p class="mt-4 text-sm muted">ยังไม่มีบัญชี? <a class="link underline" href="/register">สมัครสมาชิก</a></p>
</div>`,

	"register": `
<div class="max-w-md mx-auto card p-6">
  <h1 class="text-2xl font-semibold text-white">สมัครสมาชิก</h1>
  <form method="POST" action="/register" class="mt-5 space-y-4">
    <input type="hidden" name="csrf_token" value="{{.CSRF}}">
    <div><label>ชื่อผู้ใช้ (a-z, 0-9, _ ยาว 3-20)</label><input class="inp" name="username" value="{{.Data}}" autocomplete="username" required></div>
    <div><label>รหัสผ่าน (อย่างน้อย 8 ตัว)</label><input class="inp" type="password" name="password" minlength="8" maxlength="72" autocomplete="new-password" required></div>
    <div><label>ยืนยันรหัสผ่าน</label><input class="inp" type="password" name="confirm" minlength="8" maxlength="72" autocomplete="new-password" required></div>
    <button class="btn btn-green w-full">สมัครสมาชิก</button>
  </form>
  <p class="mt-4 text-sm muted">มีบัญชีแล้ว? <a class="link underline" href="/login">เข้าสู่ระบบ</a></p>
</div>`,

	"error": `
<div class="max-w-md mx-auto card p-8 text-center">
  <div class="text-5xl">⚠️</div>
  <h1 class="mt-3 text-xl font-semibold text-white">{{.Title}}</h1>
  <p class="mt-2 muted">{{.Data}}</p>
  <a href="/" class="btn mt-6">กลับหน้าร้านค้า</a>
</div>`,
}
