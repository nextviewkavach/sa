// main.go
package main

import (
	"bytes" // Import bytes package for HTML buffer
	"encoding/json"
	"errors" // Import errors package
	"fmt"
	"html/template" // Import html/template for safer HTML generation
	"log"           // Needed for http.ErrServerClosed
	"net/http"
	"net/smtp"
	"os"
	"os/signal"
	"path"
	"sort" // Import sort package for sorting the summary
	"strconv"
	"strings"
	"syscall"
	"time"

	// External dependencies (ensure these are installed via `go get` or `go mod tidy`)
	"github.com/blevesearch/bleve/v2"
	jwtware "github.com/gofiber/contrib/jwt"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/adaptor"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/golang-jwt/jwt/v5" // Using v5
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	promhttp "github.com/prometheus/client_golang/prometheus/promhttp"
	bolt "go.etcd.io/bbolt"
	// bcrypt removed as requested - PASSWORDS WILL BE STORED IN PLAIN TEXT (INSECURE)
)

// --- Constants ---
// Configuration (Hardcoded - 🚨 NOT RECOMMENDED FOR PRODUCTION 🚨)
const (
	Port                 = "8080"
	DatabasePath         = "data/db/sales.db"
	BlevePath            = "index.bleve"
	JWTSecret            = "Goat@2570"                 // 🚨 INSECURE: Hardcoded JWT Secret
	TokenExpiryHours     = 72                          // Token expiry in hours
	AdminUsername        = "admin"                     // Default admin username for seeding
	AdminDefaultPassword = "Goat@2570"                 // 🚨 INSECURE: Plain text password
	AdminDefaultEmail    = "support@nextviewkavach.in" // Default admin email
	SMTPServer           = "smtp.hostinger.com:587"    // SMTP server address and port
	SMTPUser             = "report@nextviewkavach.in"  // SMTP username
	SMTPPass             = "Goat@2570"                 // 🚨 INSECURE: Hardcoded SMTP password
	FromEmail            = "report@nextviewkavach.in"  // Default FROM email address
	CORSOrigin           = "*"                         // CORS allowed origins (use specific origins for prod)
)

// BoltDB Bucket Names
const (
	bUsers         = "users"
	bUsernames     = "usernames"
	bUserPasswords = "user_passwords" // <-- BUCKET FOR SEPARATE PASSWORDS
	bClients       = "clients"
	bVisits        = "visits"
	bProducts      = "products"
	bOrders        = "orders"
	bOrderItems    = "order_items" // Note: Items are currently embedded in Order JSON
	bPWResets      = "pwresets"
)

// Report Timeframes
const (
	reportDaily  = 24 * time.Hour
	reportWeekly = 7 * 24 * time.Hour
)

// --- Global Variables ---
var (
	db                  *bolt.DB
	idx                 bleve.Index // Calculated value
	tokenExpiryDuration = time.Duration(TokenExpiryHours) * time.Hour
	istLocation         *time.Location // Will hold IST time zone
)

// --- Structs / Models ---
// User struct - Password field is used temporarily but not stored in main user JSON
type User struct {
	ID        int       `json:"id"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	Password  string    `json:"-"` // Plain text password (json:"-" means NOT exposed/stored in this JSON)
	IsAdmin   bool      `json:"isAdmin"`
	CreatedAt time.Time `json:"createdAt"`
	// Add: Name, Phone, IsActive, Role string `json:"role"` etc.
}

type Client struct {
	ID            int       `json:"id"`
	Name          string    `json:"name"`
	ContactPerson string    `json:"contactPerson"`
	Email         string    `json:"email"`
	Phone         string    `json:"phone"`
	Address       string    `json:"address"`
	CreatedBy     int       `json:"createdBy"` // User ID of salesperson/admin
	CreatedAt     time.Time `json:"createdAt"`
	UpdatedAt     time.Time `json:"updatedAt"`
	// Add: Industry, Status, etc.
}

type Product struct {
	ID          int       `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Price       float64   `json:"price"` // Use float64 for price
	SKU         string    `json:"sku"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
	// Add: Category, Stock, etc.
}

type Order struct {
	ID        int         `json:"id"`
	ClientID  int         `json:"clientId"`
	OrderDate time.Time   `json:"orderDate"`
	Status    string      `json:"status"` // e.g., pending, processing, completed, cancelled
	Total     float64     `json:"total"`
	CreatedBy int         `json:"createdBy"`
	CreatedAt time.Time   `json:"createdAt"`
	UpdatedAt time.Time   `json:"updatedAt"`
	Items     []OrderItem `json:"items"` // Embed order items
	// ClientName string `json:"-"` // No longer needed here, fetched in summary
}

type OrderItem struct {
	ProductID    int     `json:"productId"`
	Quantity     int     `json:"quantity"`
	PriceAtOrder float64 `json:"priceAtOrder"` // Price when the order was placed
	// Add: ProductName, SKU for convenience? (can be added to response, not necessarily stored)
}

// UpdateOrderRequest defines fields allowed for update
type UpdateOrderRequest struct {
	Status string `json:"status"` // Example: only allow status update
	// Potentially add other fields like Items if needed
}

type Visit struct {
	ID        int       `json:"id"`
	ClientID  int       `json:"clientId"`
	UserID    int       `json:"userId"`    // User who made the visit
	VisitDate time.Time `json:"visitDate"` // Will be set to IST automatically
	Notes     string    `json:"notes"`
	CreatedAt time.Time `json:"createdAt"` // Auto-populated timestamp
	// ClientName string `json:"-"` // No longer needed here, fetched in summary
	// UserName   string `json:"-"` // No longer needed here, fetched in summary
}

// UpdateVisitRequest defines fields allowed for update
type UpdateVisitRequest struct {
	Notes string `json:"notes"` // Example: only allow notes update
}

// JWT Claims struct
type Claims struct {
	UserID  int  `json:"userId"`
	IsAdmin bool `json:"isAdmin"`
	jwt.RegisteredClaims
}

// --- Request/Response Structs ---
type LoginCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type CreateUserRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
	IsAdmin  bool   `json:"isAdmin"`
}

// Request struct for creating an order
type CreateOrderRequest struct {
	ClientID int                `json:"clientId"`
	Items    []OrderItemRequest `json:"items"`
	// Status string `json:"status"` // Optional: Allow setting initial status? Default to "pending"
}

// Request struct for items within CreateOrderRequest
type OrderItemRequest struct {
	ProductID int `json:"productId"`
	Quantity  int `json:"quantity"`
}

type ChangePasswordRequest struct {
	OldPassword string `json:"oldPassword"` // Needed for self-change
	NewPassword string `json:"newPassword"`
}

// --- Helper Functions ---

func itob(i int) []byte {
	return []byte(strconv.Itoa(i))
}

// Fetches client details by ID within a transaction
func getClientDetails(tx *bolt.Tx, clientID int) (Client, error) {
	var client Client
	clientsBucket := tx.Bucket([]byte(bClients))
	if clientsBucket == nil {
		return client, fmt.Errorf("bucket %s not found", bClients)
	}
	clientData := clientsBucket.Get(itob(clientID))
	if clientData == nil {
		return client, fmt.Errorf("client ID %d not found", clientID)
	}
	if err := json.Unmarshal(clientData, &client); err != nil {
		return client, fmt.Errorf("error reading client ID %d data: %w", clientID, err)
	}
	return client, nil
}

// sendEmail sends an email using configured SMTP settings
func sendEmail(to []string, subj, body string) error { // Return error
	if len(to) == 0 {
		log.Println("WARN: No recipients provided for email. Skipping.")
		return nil // Not an error, just nothing to do
	}
	// Using hardcoded constants directly
	if SMTPServer == "" || SMTPUser == "" || SMTPPass == "" {
		log.Println("WARN: SMTP settings not fully configured (using hardcoded values). Skipping email.")
		return fmt.Errorf("SMTP settings not configured") // Return an error
	}

	// Clean recipient list (remove duplicates, empty strings)
	validRecipients := []string{}
	seen := make(map[string]bool)
	for _, email := range to {
		trimmed := strings.TrimSpace(email)
		if trimmed != "" && !seen[trimmed] {
			// Basic check - ideally validate email format properly
			if strings.Contains(trimmed, "@") {
				validRecipients = append(validRecipients, trimmed)
				seen[trimmed] = true
			} else {
				log.Printf("WARN: Skipping invalid recipient email format: %s", email)
			}
		}
	}

	if len(validRecipients) == 0 {
		log.Println("WARN: No valid recipients after cleaning. Skipping email.")
		return nil
	}

	// ADDED Importance header for high priority
	msg := []byte(fmt.Sprintf(
		"From: %s\r\nTo: %s\r\nSubject: %s\r\nImportance: High\r\nMIME-Version: 1.0;\r\nContent-Type: text/html; charset=\"UTF-8\";\r\n\r\n%s",
		FromEmail, strings.Join(validRecipients, ","), subj, body))

	host := strings.Split(SMTPServer, ":")[0]
	auth := smtp.PlainAuth("", SMTPUser, SMTPPass, host) // 🚨 Using hardcoded credentials

	err := smtp.SendMail(SMTPServer, auth, FromEmail, validRecipients, msg) // 🚨 Using hardcoded credentials
	if err != nil {
		log.Printf("ERROR: sendEmail failed: %v", err)
		return fmt.Errorf("failed to send email: %w", err) // Return wrapped error
	}

	log.Printf("INFO: Email sent successfully to %s", strings.Join(validRecipients, ","))
	return nil // Success
}

// --- Reporting Functions ---
type ClientActivitySummary struct {
	ClientID          int
	ClientName        string
	ClientEmail       string
	ClientPhone       string
	IsNew             bool      // Was the client created during this period?
	HadVisit          bool      // Did the client have any visits during this period?
	VisitCount        int       // How many visits?
	HadOrder          bool      // Did the client have any orders during this period?
	OrderCount        int       // How many orders?
	TotalOrderValue   float64   // Total value of orders in this period
	FirstActivityTime time.Time // To help with sorting
}
type ReportData struct {
	Period                string
	StartDate             time.Time
	EndDate               time.Time
	ClientSummaries       []ClientActivitySummary // List of client activity summaries
	TotalReportOrderValue float64                 // Add this field for the grand total order value
	DataGenerationError   string                  // To capture errors during data fetching
}

func getReportRecipientsEmails(db *bolt.DB) ([]string, error) {
	var emails []string
	err := db.View(func(tx *bolt.Tx) error {
		usersBucket := tx.Bucket([]byte(bUsers))
		if usersBucket == nil {
			return fmt.Errorf("users bucket not found")
		}

		cursor := usersBucket.Cursor()
		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			var user User
			if err := json.Unmarshal(v, &user); err != nil {
				log.Printf("WARN: Failed to unmarshal user data for key %s in getReportRecipientsEmails: %v", string(k), err)
				continue
			}
			if user.Email != "" {
				emails = append(emails, user.Email)
			}
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to fetch user emails: %w", err)
	}
	if len(emails) == 0 {
		log.Println("WARN: No users found with email addresses for reporting.")
	}
	return emails, nil
}

func generateReportData(db *bolt.DB, duration time.Duration) ReportData {
	now := time.Now().In(istLocation) // Use IST
	startTime := now.Add(-duration)
	report := ReportData{
		StartDate:             startTime,
		EndDate:               now,
		ClientSummaries:       make([]ClientActivitySummary, 0), // Initialize slice
		TotalReportOrderValue: 0.0,                              // Initialize the new total field
	}

	if duration == reportDaily {
		report.Period = "Daily"
	} else if duration == reportWeekly {
		report.Period = "Weekly"
	} else {
		report.Period = fmt.Sprintf("Custom (%v)", duration)
	}

	activityMap := make(map[int]*ClientActivitySummary) // Use pointer to modify in map

	err := db.View(func(tx *bolt.Tx) error {
		// Pass 1: New Clients
		clientsBucket := tx.Bucket([]byte(bClients))
		if clientsBucket == nil {
			return fmt.Errorf("bucket %s not found", bClients)
		}
		cursorClients := clientsBucket.Cursor()
		for k, v := cursorClients.First(); k != nil; k, v = cursorClients.Next() {
			var client Client
			if err := json.Unmarshal(v, &client); err == nil {
				createdAtIST := client.CreatedAt.In(istLocation)
				// Check if client was created within the report period
				if createdAtIST.After(startTime) && !createdAtIST.After(now) {
					if _, exists := activityMap[client.ID]; !exists {
						activityMap[client.ID] = &ClientActivitySummary{
							ClientID:          client.ID,
							ClientName:        client.Name,
							ClientEmail:       client.Email,
							ClientPhone:       client.Phone,
							FirstActivityTime: createdAtIST,
						}
					}
					activityMap[client.ID].IsNew = true
					// Update FirstActivityTime if this client creation is earlier than other activities
					if createdAtIST.Before(activityMap[client.ID].FirstActivityTime) {
						activityMap[client.ID].FirstActivityTime = createdAtIST
					}
				}
			} else {
				log.Printf("WARN: Failed to unmarshal client %s in report data pass 1: %v", string(k), err)
			}
		}

		// Pass 2: Visits
		visitsBucket := tx.Bucket([]byte(bVisits))
		if visitsBucket != nil {
			cursorVisits := visitsBucket.Cursor()
			for k, v := cursorVisits.First(); k != nil; k, v = cursorVisits.Next() {
				var visit Visit
				if err := json.Unmarshal(v, &visit); err == nil {
					visitDateIST := visit.VisitDate.In(istLocation)
					if visitDateIST.After(startTime) && !visitDateIST.After(now) {
						if _, exists := activityMap[visit.ClientID]; !exists {
							clientDetails, err := getClientDetails(tx, visit.ClientID)
							if err != nil {
								log.Printf("WARN: Failed to get details for client %d referenced by visit %s: %v", visit.ClientID, string(k), err)
								activityMap[visit.ClientID] = &ClientActivitySummary{ClientID: visit.ClientID, ClientName: fmt.Sprintf("Client ID %d (Error)", visit.ClientID), FirstActivityTime: visitDateIST}
							} else {
								activityMap[visit.ClientID] = &ClientActivitySummary{ClientID: clientDetails.ID, ClientName: clientDetails.Name, ClientEmail: clientDetails.Email, ClientPhone: clientDetails.Phone, FirstActivityTime: visitDateIST}
							}
						}
						summary := activityMap[visit.ClientID]
						summary.HadVisit = true
						summary.VisitCount++
						if visitDateIST.Before(summary.FirstActivityTime) {
							summary.FirstActivityTime = visitDateIST
						}
					}
				} else {
					log.Printf("WARN: Failed to unmarshal visit %s in report data pass 2: %v", string(k), err)
				}
			}
		} else {
			log.Printf("WARN: Bucket %s not found, skipping visit data.", bVisits)
		}

		// Pass 3: Orders
		ordersBucket := tx.Bucket([]byte(bOrders))
		if ordersBucket != nil {
			cursorOrders := ordersBucket.Cursor()
			for k, v := cursorOrders.First(); k != nil; k, v = cursorOrders.Next() {
				var order Order
				if err := json.Unmarshal(v, &order); err == nil {
					orderDateIST := order.OrderDate.In(istLocation)
					if orderDateIST.After(startTime) && !orderDateIST.After(now) {
						if _, exists := activityMap[order.ClientID]; !exists {
							clientDetails, err := getClientDetails(tx, order.ClientID)
							if err != nil {
								log.Printf("WARN: Failed to get details for client %d referenced by order %s: %v", order.ClientID, string(k), err)
								activityMap[order.ClientID] = &ClientActivitySummary{ClientID: order.ClientID, ClientName: fmt.Sprintf("Client ID %d (Error)", order.ClientID), FirstActivityTime: orderDateIST}
							} else {
								activityMap[order.ClientID] = &ClientActivitySummary{ClientID: clientDetails.ID, ClientName: clientDetails.Name, ClientEmail: clientDetails.Email, ClientPhone: clientDetails.Phone, FirstActivityTime: orderDateIST}
							}
						}
						summary := activityMap[order.ClientID]
						summary.HadOrder = true
						summary.OrderCount++
						summary.TotalOrderValue += order.Total
						if orderDateIST.Before(summary.FirstActivityTime) {
							summary.FirstActivityTime = orderDateIST
						}
					}
				} else {
					log.Printf("WARN: Failed to unmarshal order %s in report data pass 3: %v", string(k), err)
				}
			}
		} else {
			log.Printf("WARN: Bucket %s not found, skipping order data.", bOrders)
		}
		return nil
	})

	if err != nil {
		log.Printf("ERROR: Failed generating client activity summary report data: %v", err)
		report.DataGenerationError = err.Error()
		return report
	}

	summaries := make([]ClientActivitySummary, 0, len(activityMap))
	for _, summary := range activityMap {
		summaries = append(summaries, *summary)
		report.TotalReportOrderValue += summary.TotalOrderValue
	}

	sort.Slice(summaries, func(i, j int) bool {
		if !summaries[i].FirstActivityTime.Equal(summaries[j].FirstActivityTime) {
			return summaries[i].FirstActivityTime.Before(summaries[j].FirstActivityTime)
		}
		return summaries[i].ClientID < summaries[j].ClientID
	})

	report.ClientSummaries = summaries
	return report
}

func generateReportHTML(data ReportData) (string, error) {
	companyName := "NextView Technologies India Pvt. Ltd"
	logoURL := "https://www.nexttechgroup.com/wp-content/uploads/2019/04/next-view-logo.png"
	poweredBy := "Powered By Kavach team"
	tmpl := `...` // Template content omitted for brevity - assume it's the same as previous
	t, err := template.New("report").Parse(tmpl)
	if err != nil {
		return "", fmt.Errorf("failed to parse report template: %w", err)
	}
	templateData := struct {
		ReportData
		CompanyName string
		LogoURL     string
		PoweredBy   string
	}{
		ReportData:  data,
		CompanyName: companyName,
		LogoURL:     logoURL,
		PoweredBy:   poweredBy,
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, templateData); err != nil {
		return "", fmt.Errorf("failed to execute report template: %w", err)
	}
	return buf.String(), nil
}

// --- Middleware ---

func NewJWTMiddleware() fiber.Handler {
	return jwtware.New(jwtware.Config{
		SigningKey: jwtware.SigningKey{Key: []byte(JWTSecret)},
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			log.Printf("JWT Error: %v", err)
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
		},
	})
}

func authRequired(c *fiber.Ctx) error {
	if c.Locals("user") == nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized (token missing or invalid)"})
	}
	return c.Next()
}

func adminOnly(c *fiber.Ctx) error {
	if !isCurrentUserAdmin(c) {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Admin privileges required"})
	}
	return c.Next()
}

func isCurrentUserAdmin(c *fiber.Ctx) bool {
	userToken := c.Locals("user")
	if userToken == nil {
		return false
	}
	token, ok := userToken.(*jwt.Token)
	if !ok {
		return false
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return false
	}
	isAdmin, ok := claims["isAdmin"].(bool)
	return ok && isAdmin
}

func getCurrentUserID(c *fiber.Ctx) (int, error) {
	userToken := c.Locals("user")
	if userToken == nil {
		return 0, fmt.Errorf("JWT token not found")
	}
	token, ok := userToken.(*jwt.Token)
	if !ok {
		return 0, fmt.Errorf("invalid JWT token type")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return 0, fmt.Errorf("invalid JWT claims type")
	}
	userIDFloat, ok := claims["userId"].(float64)
	if !ok {
		userIDInt, okInt := claims["userId"].(int)
		if !okInt {
			return 0, fmt.Errorf("userId claim missing or invalid type")
		}
		return userIDInt, nil
	}
	return int(userIDFloat), nil
}

// --- API Handlers: Authentication and Basic ---

func healthzHandler(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{"status": "ok", "timestamp": time.Now().Unix()})
}

func metricsHandler(c *fiber.Ctx) error {
	return adaptor.HTTPHandler(promhttp.Handler())(c)
}

// POST /token
func loginHandler(c *fiber.Ctx) error {
	var credentials LoginCredentials
	if err := c.BodyParser(&credentials); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request body"})
	}
	if credentials.Username == "" || credentials.Password == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Username and password required"})
	}

	var user User
	var userFound bool
	var storedPassword string // 🚨 STORED AS PLAIN TEXT

	err := db.View(func(tx *bolt.Tx) error {
		usernamesBucket := tx.Bucket([]byte(bUsernames))
		usersBucket := tx.Bucket([]byte(bUsers))
		passwordsBucket := tx.Bucket([]byte(bUserPasswords))
		if usernamesBucket == nil || usersBucket == nil || passwordsBucket == nil {
			log.Println("ERROR: Required buckets not found during login")
			return fmt.Errorf("internal configuration error")
		}
		userIDBytes := usernamesBucket.Get([]byte(credentials.Username))
		if userIDBytes == nil {
			return nil // User not found by username
		}
		userData := usersBucket.Get(userIDBytes)
		if userData == nil {
			log.Printf("ERROR: User data not found for username '%s' (ID: %s) despite username existing!", credentials.Username, string(userIDBytes))
			return fmt.Errorf("user data inconsistency")
		}
		if err := json.Unmarshal(userData, &user); err != nil {
			log.Printf("ERROR: Failed to parse user data for username '%s': %v", credentials.Username, err)
			return fmt.Errorf("failed to parse user data")
		}
		passwordBytes := passwordsBucket.Get(userIDBytes)
		if passwordBytes == nil {
			log.Printf("WARN: User '%s' (ID: %d) found but password entry missing in '%s' bucket!", user.Username, user.ID, bUserPasswords)
			return nil // Password missing
		}
		storedPassword = string(passwordBytes) // 🚨 READ PLAIN TEXT
		userFound = true
		return nil
	})

	if err != nil {
		log.Printf("ERROR: Database error during login for user '%s': %v", credentials.Username, err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Internal server error"})
	}
	if !userFound {
		log.Printf("INFO: Login failed: User '%s' not found or password entry missing", credentials.Username)
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid credentials"})
	}

	// 🚨🚨 INSECURE: Direct string comparison for password 🚨🚨
	if storedPassword != credentials.Password {
		log.Printf("INFO: Password mismatch for user '%s'", credentials.Username)
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid credentials"})
	}

	// Password matches (plain text)
	claims := &Claims{
		UserID:  user.ID,
		IsAdmin: user.IsAdmin,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(tokenExpiryDuration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   strconv.Itoa(user.ID),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(JWTSecret)) // 🚨 Use external secret
	if err != nil {
		log.Printf("ERROR: Token generation failed for user '%s': %v", user.Username, err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to generate token"})
	}

	log.Printf("INFO: Login successful for user '%s' (ID: %d)", user.Username, user.ID)
	return c.JSON(fiber.Map{
		"token": tokenString,
		"user": fiber.Map{
			"id":       user.ID,
			"username": user.Username,
			"email":    user.Email,
			"isAdmin":  user.IsAdmin,
		},
	})
}

// POST /send-test-email
func sendTestEmailHandler(c *fiber.Ctx) error {
	go sendEmail([]string{AdminDefaultEmail}, "Test Email", "This is a test email from the CRM.")
	return c.JSON(fiber.Map{"status": "test email dispatch initiated"})
}

// --- Manual Report Triggers ---
func sendReportHandler(c *fiber.Ctx) error {
	log.Println("INFO: Manual Client Activity Summary report generation triggered via API (Daily period).")
	reportData := generateReportData(db, reportDaily)
	html, err := generateReportHTML(reportData)
	if err != nil {
		log.Printf("ERROR: Failed to generate manual summary report HTML: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to generate report content"})
	}
	recipients, err := getReportRecipientsEmails(db)
	if err != nil {
		log.Printf("ERROR: Failed to get recipients for manual summary report: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to get report recipients"})
	}
	if len(recipients) == 0 {
		return c.JSON(fiber.Map{"status": "summary report generation attempted, but no recipients found"})
	}
	subject := fmt.Sprintf("%s Client Activity Report (%s)", reportData.Period, reportData.EndDate.Format("Jan 2, 2006"))
	go sendEmail(recipients, subject, html) // Error handling inside sendEmail
	return c.JSON(fiber.Map{"status": fmt.Sprintf("summary report dispatch initiated for %d recipients", len(recipients))})
}

func sendDailyReportManualHandler(c *fiber.Ctx) error {
	log.Println("INFO: Manual daily Client Activity Summary report generation triggered.")
	reportData := generateReportData(db, reportDaily)
	html, err := generateReportHTML(reportData)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to generate report content"})
	}
	recipients, err := getReportRecipientsEmails(db)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to get report recipients"})
	}
	if len(recipients) == 0 {
		return c.JSON(fiber.Map{"status": "manual daily summary report attempted, but no recipients found"})
	}
	subject := fmt.Sprintf("Manual Daily Client Activity Report (%s)", reportData.EndDate.Format("Jan 2, 2006"))
	go sendEmail(recipients, subject, html)
	return c.JSON(fiber.Map{"status": fmt.Sprintf("manual daily summary report dispatch initiated for %d recipients", len(recipients))})
}

func sendWeeklyReportManualHandler(c *fiber.Ctx) error {
	log.Println("INFO: Manual weekly Client Activity Summary report generation triggered.")
	reportData := generateReportData(db, reportWeekly)
	html, err := generateReportHTML(reportData)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to generate report content"})
	}
	recipients, err := getReportRecipientsEmails(db)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to get report recipients"})
	}
	if len(recipients) == 0 {
		return c.JSON(fiber.Map{"status": "manual weekly summary report attempted, but no recipients found"})
	}
	subject := fmt.Sprintf("Manual Weekly Client Activity Report (Week ending %s)", reportData.EndDate.Format("Jan 2, 2006"))
	go sendEmail(recipients, subject, html)
	return c.JSON(fiber.Map{"status": fmt.Sprintf("manual weekly summary report dispatch initiated for %d recipients", len(recipients))})
}

// --- API Handlers: Users ---

// POST /api/users (Admin Only)
func createUserHandler(c *fiber.Ctx) error {
	req := new(CreateUserRequest)
	if err := c.BodyParser(req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request body"})
	}
	if req.Username == "" || req.Password == "" || req.Email == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Username, email, and password are required"})
	}
	// 🚨🚨 WARNING: Add password complexity checks here! 🚨🚨

	var newUser User
	creationErr := db.Update(func(tx *bolt.Tx) error {
		usersBucket := tx.Bucket([]byte(bUsers))
		usernamesBucket := tx.Bucket([]byte(bUsernames))
		passwordsBucket := tx.Bucket([]byte(bUserPasswords))
		if usersBucket == nil || usernamesBucket == nil || passwordsBucket == nil {
			return fmt.Errorf("internal configuration error")
		}
		if usernamesBucket.Get([]byte(req.Username)) != nil {
			return fiber.NewError(fiber.StatusConflict, fmt.Sprintf("username '%s' already exists", req.Username))
		}
		id, _ := usersBucket.NextSequence()
		newUserID := int(id)

		newUser = User{
			ID:        newUserID,
			Username:  req.Username,
			Email:     req.Email,
			IsAdmin:   req.IsAdmin,
			CreatedAt: time.Now(),
		}
		userData, err := json.Marshal(newUser)
		if err != nil {
			return fmt.Errorf("failed to prepare user data")
		}
		if err := usersBucket.Put(itob(newUser.ID), userData); err != nil {
			return fmt.Errorf("failed to save new user")
		}
		if err := usernamesBucket.Put([]byte(newUser.Username), itob(newUser.ID)); err != nil {
			// Attempt rollback? Difficult with BoltDB... Log and potentially return error
			log.Printf("CRITICAL: Failed to save username mapping for user %d, but user data saved!", newUser.ID)
			return fmt.Errorf("failed to save username mapping")
		}

		// 🚨🚨 INSECURE: Storing plain text password 🚨🚨
		if err := passwordsBucket.Put(itob(newUser.ID), []byte(req.Password)); err != nil {
			log.Printf("CRITICAL: Failed to save password for user %d, but user data saved!", newUser.ID)
			return fmt.Errorf("failed to save user password")
		}
		// TODO: Index user in Bleve
		return nil
	})

	if creationErr != nil {
		var fiberErr *fiber.Error
		if errors.As(creationErr, &fiberErr) {
			return c.Status(fiberErr.Code).JSON(fiber.Map{"error": fiberErr.Message})
		}
		log.Printf("ERROR: Failed to commit user creation transaction for '%s': %v", req.Username, creationErr)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create user"})
	}
	log.Printf("INFO: Admin created user '%s' (ID: %d)", newUser.Username, newUser.ID)
	// Return user info without password
	responseUser := fiber.Map{
		"id":        newUser.ID,
		"username":  newUser.Username,
		"email":     newUser.Email,
		"isAdmin":   newUser.IsAdmin,
		"createdAt": newUser.CreatedAt,
	}
	return c.Status(fiber.StatusCreated).JSON(responseUser)
}

// GET /api/users (Admin Only)
func getUsersHandler(c *fiber.Ctx) error {
	var users []fiber.Map // Return simplified user info
	fetchErr := db.View(func(tx *bolt.Tx) error {
		usersBucket := tx.Bucket([]byte(bUsers))
		if usersBucket == nil {
			return fmt.Errorf("users bucket not found")
		}
		cursor := usersBucket.Cursor()
		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			var user User
			if err := json.Unmarshal(v, &user); err != nil {
				log.Printf("WARN: Failed to unmarshal user data for key %s: %v", string(k), err)
				continue
			}
			// Exclude password
			users = append(users, fiber.Map{
				"id":        user.ID,
				"username":  user.Username,
				"email":     user.Email,
				"isAdmin":   user.IsAdmin,
				"createdAt": user.CreatedAt,
			})
		}
		return nil
	})
	if fetchErr != nil {
		log.Printf("ERROR: Failed to fetch users: %v", fetchErr)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to retrieve users"})
	}
	return c.JSON(users)
}

// GET /api/users/:id (Admin or Self)
func getUserHandler(c *fiber.Ctx) error {
	targetUserID, err := strconv.Atoi(c.Params("id"))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid user ID parameter"})
	}
	currentUserID, err := getCurrentUserID(c)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Could not identify current user"})
	}
	isAdmin := isCurrentUserAdmin(c)
	if !isAdmin && currentUserID != targetUserID {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Forbidden: Cannot access other user's data"})
	}

	var user User
	fetchErr := db.View(func(tx *bolt.Tx) error {
		usersBucket := tx.Bucket([]byte(bUsers))
		if usersBucket == nil {
			return fmt.Errorf("users bucket not found")
		}
		userData := usersBucket.Get(itob(targetUserID))
		if userData == nil {
			return fiber.ErrNotFound
		}
		if err := json.Unmarshal(userData, &user); err != nil {
			return fmt.Errorf("failed to parse user data")
		}
		return nil
	})

	if fetchErr != nil {
		if errors.Is(fetchErr, fiber.ErrNotFound) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
		}
		log.Printf("ERROR: Failed to fetch user %d: %v", targetUserID, fetchErr)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to retrieve user"})
	}
	// Return safe fields
	return c.JSON(fiber.Map{
		"id":        user.ID,
		"username":  user.Username,
		"email":     user.Email,
		"isAdmin":   user.IsAdmin,
		"createdAt": user.CreatedAt,
	})
}

// PUT /api/users/:id (Admin or Self)
func updateUserHandler(c *fiber.Ctx) error {
	targetUserID, err := strconv.Atoi(c.Params("id"))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid user ID parameter"})
	}
	currentUserID, err := getCurrentUserID(c)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Could not identify current user"})
	}
	isAdmin := isCurrentUserAdmin(c)
	if !isAdmin && currentUserID != targetUserID {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Forbidden: Cannot update other user's data"})
	}

	// Parse only allowed fields for update (e.g., email, maybe isAdmin if current user is admin)
	type UpdateUserRequest struct {
		Email   *string `json:"email"`   // Use pointers to detect if field was provided
		IsAdmin *bool   `json:"isAdmin"` // Only changeable by admin
	}
	req := new(UpdateUserRequest)
	if err := c.BodyParser(req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request body"})
	}

	var updatedUser User
	updateErr := db.Update(func(tx *bolt.Tx) error {
		usersBucket := tx.Bucket([]byte(bUsers))
		if usersBucket == nil {
			return fmt.Errorf("users bucket not found")
		}
		userData := usersBucket.Get(itob(targetUserID))
		if userData == nil {
			return fiber.ErrNotFound
		}
		if err := json.Unmarshal(userData, &updatedUser); err != nil {
			return fmt.Errorf("failed to parse existing user data")
		}

		// Apply changes
		if req.Email != nil {
			updatedUser.Email = *req.Email // Validate email format?
		}
		if isAdmin && req.IsAdmin != nil {
			// Prevent admin from removing their own admin status if they are the only admin? Add checks.
			if targetUserID == 1 && !*req.IsAdmin { // Example: Don't let user ID 1 lose admin
				return fmt.Errorf("cannot remove admin status from the default admin user")
			}
			updatedUser.IsAdmin = *req.IsAdmin
		} else if req.IsAdmin != nil && !isAdmin {
			// Non-admin trying to change admin status
			return fmt.Errorf("forbidden: cannot change admin status")
		}

		newUserData, err := json.Marshal(updatedUser)
		if err != nil {
			return fmt.Errorf("failed to prepare updated user data")
		}
		if err := usersBucket.Put(itob(targetUserID), newUserData); err != nil {
			return fmt.Errorf("failed to save updated user data")
		}
		return nil
	})

	if updateErr != nil {
		if errors.Is(updateErr, fiber.ErrNotFound) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
		}
		log.Printf("ERROR: Failed to update user %d: %v", targetUserID, updateErr)
		// Return specific errors if needed (like forbidden)
		if strings.Contains(updateErr.Error(), "forbidden") {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": updateErr.Error()})
		}
		if strings.Contains(updateErr.Error(), "cannot remove admin status") {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": updateErr.Error()})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update user"})
	}

	// Return updated safe fields
	return c.JSON(fiber.Map{
		"id":        updatedUser.ID,
		"username":  updatedUser.Username,
		"email":     updatedUser.Email,
		"isAdmin":   updatedUser.IsAdmin,
		"createdAt": updatedUser.CreatedAt,
	})
}

// DELETE /api/users/:id (Admin Only)
func deleteUserHandler(c *fiber.Ctx) error {
	targetUserID, err := strconv.Atoi(c.Params("id"))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid user ID parameter"})
	}
	if targetUserID == 1 { // Assuming ID 1 is the primary admin
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Cannot delete the default admin user"})
	}

	var username string
	deleteErr := db.Update(func(tx *bolt.Tx) error {
		usersBucket := tx.Bucket([]byte(bUsers))
		usernamesBucket := tx.Bucket([]byte(bUsernames))
		passwordsBucket := tx.Bucket([]byte(bUserPasswords))
		if usersBucket == nil || usernamesBucket == nil || passwordsBucket == nil {
			return fmt.Errorf("required buckets not found")
		}

		// Get username before deleting user data
		userData := usersBucket.Get(itob(targetUserID))
		if userData == nil {
			return fiber.ErrNotFound // User doesn't exist
		}
		var user User
		if err := json.Unmarshal(userData, &user); err == nil {
			username = user.Username
		} // Ignore error if unmarshal fails, proceed with delete if key exists

		// Delete user data
		if err := usersBucket.Delete(itob(targetUserID)); err != nil {
			return fmt.Errorf("failed to delete user data: %w", err)
		}
		// Delete password
		if err := passwordsBucket.Delete(itob(targetUserID)); err != nil {
			// Log error but don't necessarily fail the whole operation if password was already missing
			log.Printf("WARN: Failed to delete password for user ID %d (may have been missing): %v", targetUserID, err)
		}
		// Delete username mapping (if username was found)
		if username != "" {
			if err := usernamesBucket.Delete([]byte(username)); err != nil {
				log.Printf("WARN: Failed to delete username mapping '%s' for user ID %d: %v", username, targetUserID, err)
			}
		}
		return nil
	})

	if deleteErr != nil {
		if errors.Is(deleteErr, fiber.ErrNotFound) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
		}
		log.Printf("ERROR: Failed to delete user %d: %v", targetUserID, deleteErr)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to delete user"})
	}

	log.Printf("INFO: Admin deleted user ID %d (Username: '%s')", targetUserID, username)
	// TODO: Delete associated records? (Orders, Visits created by this user?) - Requires careful consideration
	return c.SendStatus(fiber.StatusNoContent)
}

// PUT /api/users/me/password (Self only)
func changeMyPasswordHandler(c *fiber.Ctx) error {
	currentUserID, err := getCurrentUserID(c)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Could not identify current user"})
	}

	req := new(ChangePasswordRequest)
	if err := c.BodyParser(req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request body"})
	}
	if req.OldPassword == "" || req.NewPassword == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Old password and new password are required"})
	}
	if req.OldPassword == req.NewPassword {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "New password cannot be the same as the old password"})
	}
	// 🚨🚨 WARNING: Add password complexity checks for req.NewPassword here! 🚨🚨

	updateErr := db.Update(func(tx *bolt.Tx) error {
		passwordsBucket := tx.Bucket([]byte(bUserPasswords))
		if passwordsBucket == nil {
			return fmt.Errorf("passwords bucket not found")
		}
		userIDBytes := itob(currentUserID)
		storedPasswordBytes := passwordsBucket.Get(userIDBytes)
		if storedPasswordBytes == nil {
			log.Printf("ERROR: Password record not found for currently logged-in user %d", currentUserID)
			return fiber.NewError(fiber.StatusInternalServerError, "Password record missing") // Should not happen if logged in
		}

		// 🚨🚨 INSECURE: Plain text comparison 🚨🚨
		if string(storedPasswordBytes) != req.OldPassword {
			return fiber.NewError(fiber.StatusUnauthorized, "Incorrect old password")
		}

		// 🚨🚨 INSECURE: Storing plain text password 🚨🚨
		if err := passwordsBucket.Put(userIDBytes, []byte(req.NewPassword)); err != nil {
			return fmt.Errorf("failed to save new password: %w", err)
		}
		return nil
	})

	if updateErr != nil {
		var fiberErr *fiber.Error
		if errors.As(updateErr, &fiberErr) {
			return c.Status(fiberErr.Code).JSON(fiber.Map{"error": fiberErr.Message})
		}
		log.Printf("ERROR: Failed to change password for user %d: %v", currentUserID, updateErr)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to change password"})
	}

	log.Printf("INFO: User %d changed their password successfully.", currentUserID)
	return c.SendStatus(fiber.StatusNoContent)
}

// PUT /api/users/:id/password (Admin Only)
func changeUserPasswordHandler(c *fiber.Ctx) error {
	targetUserID, err := strconv.Atoi(c.Params("id"))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid user ID parameter"})
	}

	// Only need NewPassword from request for admin change
	var req struct {
		NewPassword string `json:"newPassword"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request body"})
	}
	if req.NewPassword == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "New password is required"})
	}
	// 🚨🚨 WARNING: Add password complexity checks for req.NewPassword here! 🚨🚨

	updateErr := db.Update(func(tx *bolt.Tx) error {
		passwordsBucket := tx.Bucket([]byte(bUserPasswords))
		usersBucket := tx.Bucket([]byte(bUsers)) // Check if user exists
		if passwordsBucket == nil || usersBucket == nil {
			return fmt.Errorf("required buckets not found")
		}
		userIDBytes := itob(targetUserID)

		// Check if the target user actually exists
		if usersBucket.Get(userIDBytes) == nil {
			return fiber.ErrNotFound // Target user doesn't exist
		}

		// 🚨🚨 INSECURE: Storing plain text password 🚨🚨
		if err := passwordsBucket.Put(userIDBytes, []byte(req.NewPassword)); err != nil {
			return fmt.Errorf("failed to save new password for user %d: %w", targetUserID, err)
		}
		return nil
	})

	if updateErr != nil {
		if errors.Is(updateErr, fiber.ErrNotFound) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
		}
		log.Printf("ERROR: Admin failed to change password for user %d: %v", targetUserID, updateErr)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to change user password"})
	}

	adminUserID, _ := getCurrentUserID(c) // Ignore error, just for logging
	log.Printf("INFO: Admin (ID: %d) changed password for user %d.", adminUserID, targetUserID)
	return c.SendStatus(fiber.StatusNoContent)
}

// --- API Handlers: Clients ---

// POST /api/clients
func createClientHandler(c *fiber.Ctx) error {
	req := new(Client)
	if err := c.BodyParser(req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request body"})
	}
	if req.Name == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Client name is required"})
	}
	currentUserID, err := getCurrentUserID(c)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Could not identify current user"})
	}

	var newClient Client
	creationErr := db.Update(func(tx *bolt.Tx) error {
		clientsBucket := tx.Bucket([]byte(bClients))
		if clientsBucket == nil {
			return fmt.Errorf("clients bucket not found")
		}
		id, _ := clientsBucket.NextSequence()
		newClientID := int(id)
		now := time.Now()
		newClient = Client{
			ID:            newClientID,
			Name:          req.Name,
			ContactPerson: req.ContactPerson,
			Email:         req.Email,
			Phone:         req.Phone,
			Address:       req.Address,
			CreatedBy:     currentUserID,
			CreatedAt:     now,
			UpdatedAt:     now,
		}
		clientData, err := json.Marshal(newClient)
		if err != nil {
			return fmt.Errorf("failed to prepare client data: %w", err)
		}
		if err := clientsBucket.Put(itob(newClient.ID), clientData); err != nil {
			return fmt.Errorf("failed to save new client: %w", err)
		}
		// TODO: Index client in Bleve
		return nil
	})

	if creationErr != nil {
		log.Printf("ERROR: Failed to commit client creation transaction for '%s': %v", req.Name, creationErr)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create client"})
	}
	log.Printf("INFO: User %d created client '%s' (ID: %d)", currentUserID, newClient.Name, newClient.ID)
	return c.Status(fiber.StatusCreated).JSON(newClient)
}

// GET /api/clients
func getClientsHandler(c *fiber.Ctx) error {
	searchQuery := c.Query("search") // Get search query parameter

	var clients []Client
	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bClients))
		if b == nil {
			return fmt.Errorf("bucket %s not found", bClients)
		}
		cursor := b.Cursor()
		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			var client Client
			if err := json.Unmarshal(v, &client); err != nil {
				log.Printf("WARN: Failed to unmarshal client data for key %s: %v", string(k), err)
				continue
			}
			// Filter by search query if provided (case-insensitive name search)
			if searchQuery == "" || strings.Contains(strings.ToLower(client.Name), strings.ToLower(searchQuery)) {
				clients = append(clients, client)
			}
		}
		return nil
	})
	if err != nil {
		log.Printf("ERROR: Failed to get clients: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to retrieve clients"})
	}
	return c.JSON(clients)
}

// GET /api/clients/:id
func getClientHandler(c *fiber.Ctx) error {
	clientID, err := strconv.Atoi(c.Params("id"))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid client ID"})
	}
	var client Client
	err = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bClients))
		if b == nil {
			return fmt.Errorf("bucket %s not found", bClients)
		}
		v := b.Get(itob(clientID))
		if v == nil {
			return fiber.ErrNotFound
		}
		if err := json.Unmarshal(v, &client); err != nil {
			return fmt.Errorf("failed to parse client data")
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, fiber.ErrNotFound) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Client not found"})
		}
		log.Printf("ERROR: Failed to get client %d: %v", clientID, err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to retrieve client"})
	}
	return c.JSON(client)
}

// PUT /api/clients/:id
func updateClientHandler(c *fiber.Ctx) error {
	clientID, err := strconv.Atoi(c.Params("id"))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid client ID"})
	}
	currentUserID, err := getCurrentUserID(c)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Could not identify current user"})
	}
	isAdmin := isCurrentUserAdmin(c)

	req := new(Client) // Parse the whole client structure for update
	if err := c.BodyParser(req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request body"})
	}
	if req.Name == "" { // Basic validation
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Client name cannot be empty"})
	}

	var updatedClient Client
	updateErr := db.Update(func(tx *bolt.Tx) error {
		clientsBucket := tx.Bucket([]byte(bClients))
		if clientsBucket == nil {
			return fmt.Errorf("clients bucket not found")
		}
		clientData := clientsBucket.Get(itob(clientID))
		if clientData == nil {
			return fiber.ErrNotFound
		}
		var existingClient Client
		if err := json.Unmarshal(clientData, &existingClient); err != nil {
			return fmt.Errorf("failed to parse existing client data")
		}

		// Permission Check: Allow update only if admin or the original creator
		if !isAdmin && existingClient.CreatedBy != currentUserID {
			return fiber.NewError(fiber.StatusForbidden, "Forbidden: Cannot update client created by another user")
		}

		// Update fields from request, keep original ID, CreatedBy, CreatedAt
		updatedClient = Client{
			ID:            existingClient.ID,
			Name:          req.Name, // Update name
			ContactPerson: req.ContactPerson,
			Email:         req.Email,
			Phone:         req.Phone,
			Address:       req.Address,
			CreatedBy:     existingClient.CreatedBy, // Keep original creator
			CreatedAt:     existingClient.CreatedAt, // Keep original creation time
			UpdatedAt:     time.Now(),               // Set update time
		}

		newClientData, err := json.Marshal(updatedClient)
		if err != nil {
			return fmt.Errorf("failed to prepare updated client data: %w", err)
		}
		if err := clientsBucket.Put(itob(clientID), newClientData); err != nil {
			return fmt.Errorf("failed to save updated client data: %w", err)
		}
		// TODO: Update Bleve index
		return nil
	})

	if updateErr != nil {
		var fiberErr *fiber.Error
		if errors.As(updateErr, &fiberErr) {
			return c.Status(fiberErr.Code).JSON(fiber.Map{"error": fiberErr.Message})
		}
		log.Printf("ERROR: Failed to update client %d: %v", clientID, updateErr)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update client"})
	}
	log.Printf("INFO: Client %d updated by user %d", clientID, currentUserID)
	return c.JSON(updatedClient)
}

// DELETE /api/clients/:id (Admin Only)
func deleteClientHandler(c *fiber.Ctx) error {
	clientID, err := strconv.Atoi(c.Params("id"))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid client ID"})
	}

	deleteErr := db.Update(func(tx *bolt.Tx) error {
		clientsBucket := tx.Bucket([]byte(bClients))
		if clientsBucket == nil {
			return fmt.Errorf("clients bucket not found")
		}
		// Check if client exists before deleting
		if clientsBucket.Get(itob(clientID)) == nil {
			return fiber.ErrNotFound
		}
		if err := clientsBucket.Delete(itob(clientID)); err != nil {
			return fmt.Errorf("failed to delete client data: %w", err)
		}
		// TODO: Delete from Bleve index
		// TODO: Consider deleting associated Visits/Orders? Or orphan them?
		return nil
	})

	if deleteErr != nil {
		if errors.Is(deleteErr, fiber.ErrNotFound) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Client not found"})
		}
		log.Printf("ERROR: Failed to delete client %d: %v", clientID, deleteErr)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to delete client"})
	}

	adminUserID, _ := getCurrentUserID(c)
	log.Printf("INFO: Client %d deleted by admin %d", clientID, adminUserID)
	return c.SendStatus(fiber.StatusNoContent)
}

// --- API Handlers: Products ---

// POST /api/products (Admin Only)
func createProductHandler(c *fiber.Ctx) error {
	req := new(Product)
	if err := c.BodyParser(req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request body"})
	}
	if req.Name == "" || req.Price <= 0 || req.SKU == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Product name, positive price, and SKU are required"})
	}

	var newProduct Product
	creationErr := db.Update(func(tx *bolt.Tx) error {
		productsBucket := tx.Bucket([]byte(bProducts))
		if productsBucket == nil {
			return fmt.Errorf("products bucket not found")
		}
		// TODO: Check SKU uniqueness more robustly if needed
		id, _ := productsBucket.NextSequence()
		newProductID := int(id)
		now := time.Now()
		newProduct = Product{
			ID:          newProductID,
			Name:        req.Name,
			Description: req.Description,
			Price:       req.Price,
			SKU:         req.SKU,
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		productData, err := json.Marshal(newProduct)
		if err != nil {
			return fmt.Errorf("failed to prepare product data: %w", err)
		}
		if err := productsBucket.Put(itob(newProduct.ID), productData); err != nil {
			return fmt.Errorf("failed to save new product: %w", err)
		}
		// TODO: Index product in Bleve
		return nil
	})
	if creationErr != nil {
		log.Printf("ERROR: Failed to commit product creation transaction for '%s': %v", req.Name, creationErr)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create product"})
	}
	log.Printf("INFO: Admin created product '%s' (ID: %d)", newProduct.Name, newProduct.ID)
	return c.Status(fiber.StatusCreated).JSON(newProduct)
}

// GET /api/products
func getProductsHandler(c *fiber.Ctx) error {
	var products []Product
	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bProducts))
		if b == nil {
			// If bucket doesn't exist, return empty list, not error
			log.Println("INFO: Products bucket not found, returning empty list.")
			return nil
		}
		cursor := b.Cursor()
		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			var prod Product
			if err := json.Unmarshal(v, &prod); err != nil {
				log.Printf("WARN: Failed to unmarshal product data key %s: %v", string(k), err)
				continue
			}
			products = append(products, prod)
		}
		return nil
	})
	if err != nil {
		// This should ideally not be hit if View func returns nil on missing bucket
		log.Printf("ERROR: Failed to get products: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to retrieve products"})
	}
	return c.JSON(products)
}

// GET /api/products/:id
func getProductHandler(c *fiber.Ctx) error {
	productID, err := strconv.Atoi(c.Params("id"))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid product ID"})
	}
	var product Product
	err = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bProducts))
		if b == nil {
			return fiber.ErrNotFound // Treat missing bucket as product not found
		}
		v := b.Get(itob(productID))
		if v == nil {
			return fiber.ErrNotFound
		}
		if err := json.Unmarshal(v, &product); err != nil {
			return fmt.Errorf("failed to parse product data")
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, fiber.ErrNotFound) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Product not found"})
		}
		log.Printf("ERROR: Failed to get product %d: %v", productID, err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to retrieve product"})
	}
	return c.JSON(product)
}

// PUT /api/products/:id (Admin Only)
func updateProductHandler(c *fiber.Ctx) error {
	productID, err := strconv.Atoi(c.Params("id"))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid product ID"})
	}

	req := new(Product) // Parse full product for update
	if err := c.BodyParser(req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request body"})
	}
	if req.Name == "" || req.Price <= 0 || req.SKU == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Product name, positive price, and SKU are required"})
	}

	var updatedProduct Product
	updateErr := db.Update(func(tx *bolt.Tx) error {
		productsBucket := tx.Bucket([]byte(bProducts))
		if productsBucket == nil {
			return fmt.Errorf("products bucket not found")
		}
		productData := productsBucket.Get(itob(productID))
		if productData == nil {
			return fiber.ErrNotFound
		}
		var existingProduct Product
		if err := json.Unmarshal(productData, &existingProduct); err != nil {
			return fmt.Errorf("failed to parse existing product data")
		}

		// Update fields, keep original ID and CreatedAt
		updatedProduct = Product{
			ID:          existingProduct.ID,
			Name:        req.Name,
			Description: req.Description,
			Price:       req.Price,
			SKU:         req.SKU,
			CreatedAt:   existingProduct.CreatedAt,
			UpdatedAt:   time.Now(),
		}

		newProductData, err := json.Marshal(updatedProduct)
		if err != nil {
			return fmt.Errorf("failed to prepare updated product data: %w", err)
		}
		if err := productsBucket.Put(itob(productID), newProductData); err != nil {
			return fmt.Errorf("failed to save updated product data: %w", err)
		}
		// TODO: Update Bleve index
		return nil
	})

	if updateErr != nil {
		if errors.Is(updateErr, fiber.ErrNotFound) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Product not found"})
		}
		log.Printf("ERROR: Failed to update product %d: %v", productID, updateErr)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update product"})
	}
	log.Printf("INFO: Product %d updated by admin", productID)
	return c.JSON(updatedProduct)
}

// DELETE /api/products/:id (Admin Only)
func deleteProductHandler(c *fiber.Ctx) error {
	productID, err := strconv.Atoi(c.Params("id"))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid product ID"})
	}

	deleteErr := db.Update(func(tx *bolt.Tx) error {
		productsBucket := tx.Bucket([]byte(bProducts))
		if productsBucket == nil {
			return fmt.Errorf("products bucket not found")
		}
		if productsBucket.Get(itob(productID)) == nil {
			return fiber.ErrNotFound // Product doesn't exist
		}
		if err := productsBucket.Delete(itob(productID)); err != nil {
			return fmt.Errorf("failed to delete product data: %w", err)
		}
		// TODO: Delete from Bleve index
		// TODO: Check if product is in any Orders? Prevent deletion or handle?
		return nil
	})

	if deleteErr != nil {
		if errors.Is(deleteErr, fiber.ErrNotFound) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Product not found"})
		}
		log.Printf("ERROR: Failed to delete product %d: %v", productID, deleteErr)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to delete product"})
	}

	adminUserID, _ := getCurrentUserID(c)
	log.Printf("INFO: Product %d deleted by admin %d", productID, adminUserID)
	return c.SendStatus(fiber.StatusNoContent)
}

// --- API Handlers: Orders --- (Implementations added/updated)

// POST /api/orders
func createOrderHandler(c *fiber.Ctx) error {
	req := new(CreateOrderRequest)
	if err := c.BodyParser(req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request body"})
	}
	if req.ClientID <= 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Client ID is required"})
	}
	if len(req.Items) == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "At least one order item is required"})
	}
	for i, item := range req.Items {
		if item.ProductID <= 0 {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": fmt.Sprintf("Item %d: Product ID is required", i+1)})
		}
		if item.Quantity <= 0 {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": fmt.Sprintf("Item %d (Product %d): Quantity must be positive", i+1, item.ProductID)})
		}
	}
	currentUserID, err := getCurrentUserID(c)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Could not identify current user"})
	}

	var newOrder Order
	creationErr := db.Update(func(tx *bolt.Tx) error {
		ordersBucket := tx.Bucket([]byte(bOrders))
		clientsBucket := tx.Bucket([]byte(bClients))
		productsBucket := tx.Bucket([]byte(bProducts))
		if ordersBucket == nil || clientsBucket == nil || productsBucket == nil {
			return fmt.Errorf("internal configuration error: missing buckets")
		}
		if clientsBucket.Get(itob(req.ClientID)) == nil {
			return fiber.NewError(fiber.StatusBadRequest, fmt.Sprintf("client with ID %d not found", req.ClientID))
		}

		orderItems := make([]OrderItem, 0, len(req.Items))
		total := 0.0
		now := time.Now()
		for _, reqItem := range req.Items {
			productData := productsBucket.Get(itob(reqItem.ProductID))
			if productData == nil {
				return fiber.NewError(fiber.StatusBadRequest, fmt.Sprintf("product with ID %d not found", reqItem.ProductID))
			}
			var product Product
			if err := json.Unmarshal(productData, &product); err != nil {
				return fmt.Errorf("failed to validate product %d: %w", reqItem.ProductID, err)
			}
			item := OrderItem{ProductID: reqItem.ProductID, Quantity: reqItem.Quantity, PriceAtOrder: product.Price}
			orderItems = append(orderItems, item)
			total += float64(item.Quantity) * item.PriceAtOrder
		}

		id, _ := ordersBucket.NextSequence()
		newOrderID := int(id)
		newOrder = Order{
			ID:        newOrderID,
			ClientID:  req.ClientID,
			OrderDate: time.Now().In(istLocation), // Use IST
			Status:    "pending",                  // Default status
			Total:     total,
			CreatedBy: currentUserID,
			CreatedAt: now,
			UpdatedAt: now,
			Items:     orderItems,
		}
		orderData, err := json.Marshal(newOrder)
		if err != nil {
			return fmt.Errorf("failed to prepare order data: %w", err)
		}
		if err := ordersBucket.Put(itob(newOrder.ID), orderData); err != nil {
			return fmt.Errorf("failed to save new order: %w", err)
		}
		// TODO: Index order in Bleve
		return nil
	})

	if creationErr != nil {
		var fiberErr *fiber.Error
		if errors.As(creationErr, &fiberErr) {
			return c.Status(fiberErr.Code).JSON(fiber.Map{"error": fiberErr.Message})
		}
		log.Printf("ERROR: Failed to commit order creation transaction for client %d: %v", req.ClientID, creationErr)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create order"})
	}
	log.Printf("INFO: User %d created order %d for client %d", currentUserID, newOrder.ID, newOrder.ClientID)
	return c.Status(fiber.StatusCreated).JSON(newOrder)
}

// GET /api/orders
func getOrdersHandler(c *fiber.Ctx) error {
	currentUserID, err := getCurrentUserID(c)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Could not identify current user"})
	}
	isAdmin := isCurrentUserAdmin(c)

	var orders []Order
	fetchErr := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bOrders))
		if b == nil {
			log.Println("INFO: Orders bucket not found, returning empty list.")
			return nil
		}
		cursor := b.Cursor()
		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			var order Order
			if err := json.Unmarshal(v, &order); err != nil {
				log.Printf("WARN: Failed to unmarshal order data key %s: %v", string(k), err)
				continue
			}
			// Filter: Admins see all, users see only their own
			if isAdmin || order.CreatedBy == currentUserID {
				orders = append(orders, order)
			}
		}
		return nil
	})

	if fetchErr != nil {
		log.Printf("ERROR: Failed to get orders: %v", fetchErr)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to retrieve orders"})
	}
	return c.JSON(orders)
}

// GET /api/orders/:id
func getOrderHandler(c *fiber.Ctx) error {
	orderID, err := strconv.Atoi(c.Params("id"))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid order ID"})
	}
	currentUserID, err := getCurrentUserID(c)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Could not identify current user"})
	}
	isAdmin := isCurrentUserAdmin(c)

	var order Order
	fetchErr := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bOrders))
		if b == nil {
			return fiber.ErrNotFound // Treat missing bucket as order not found
		}
		v := b.Get(itob(orderID))
		if v == nil {
			return fiber.ErrNotFound
		}
		if err := json.Unmarshal(v, &order); err != nil {
			return fmt.Errorf("failed to parse order data")
		}
		// Permission Check
		if !isAdmin && order.CreatedBy != currentUserID {
			return fiber.ErrForbidden
		}
		return nil
	})

	if fetchErr != nil {
		if errors.Is(fetchErr, fiber.ErrNotFound) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Order not found"})
		}
		if errors.Is(fetchErr, fiber.ErrForbidden) {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Forbidden: Cannot access this order"})
		}
		log.Printf("ERROR: Failed to get order %d: %v", orderID, fetchErr)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to retrieve order"})
	}
	return c.JSON(order)
}

// PUT /api/orders/:id
func updateOrderHandler(c *fiber.Ctx) error {
	orderID, err := strconv.Atoi(c.Params("id"))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid order ID"})
	}
	currentUserID, err := getCurrentUserID(c)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Could not identify current user"})
	}
	isAdmin := isCurrentUserAdmin(c)

	req := new(UpdateOrderRequest) // Use specific update request struct
	if err := c.BodyParser(req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request body"})
	}
	// Validate status if needed (e.g., ensure it's one of pending, processing, etc.)
	allowedStatuses := map[string]bool{"pending": true, "processing": true, "completed": true, "cancelled": true}
	if req.Status != "" && !allowedStatuses[req.Status] {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid order status"})
	}

	var updatedOrder Order
	updateErr := db.Update(func(tx *bolt.Tx) error {
		ordersBucket := tx.Bucket([]byte(bOrders))
		if ordersBucket == nil {
			return fmt.Errorf("orders bucket not found")
		}
		orderData := ordersBucket.Get(itob(orderID))
		if orderData == nil {
			return fiber.ErrNotFound
		}
		var existingOrder Order
		if err := json.Unmarshal(orderData, &existingOrder); err != nil {
			return fmt.Errorf("failed to parse existing order data")
		}

		// Permission Check: Allow update only if admin or the original creator
		if !isAdmin && existingOrder.CreatedBy != currentUserID {
			return fiber.NewError(fiber.StatusForbidden, "Forbidden: Cannot update order created by another user")
		}

		// Apply updates (currently only status)
		updatedOrder = existingOrder // Copy existing order
		if req.Status != "" {
			updatedOrder.Status = req.Status
		}
		updatedOrder.UpdatedAt = time.Now() // Update timestamp

		newOrderData, err := json.Marshal(updatedOrder)
		if err != nil {
			return fmt.Errorf("failed to prepare updated order data: %w", err)
		}
		if err := ordersBucket.Put(itob(orderID), newOrderData); err != nil {
			return fmt.Errorf("failed to save updated order data: %w", err)
		}
		// TODO: Update Bleve index if status changed
		return nil
	})

	if updateErr != nil {
		var fiberErr *fiber.Error
		if errors.As(updateErr, &fiberErr) {
			return c.Status(fiberErr.Code).JSON(fiber.Map{"error": fiberErr.Message})
		}
		log.Printf("ERROR: Failed to update order %d: %v", orderID, updateErr)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update order"})
	}
	log.Printf("INFO: Order %d updated by user %d", orderID, currentUserID)
	return c.JSON(updatedOrder)
}

// DELETE /api/orders/:id (Admin Only)
func deleteOrderHandler(c *fiber.Ctx) error {
	orderID, err := strconv.Atoi(c.Params("id"))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid order ID"})
	}

	deleteErr := db.Update(func(tx *bolt.Tx) error {
		ordersBucket := tx.Bucket([]byte(bOrders))
		if ordersBucket == nil {
			return fmt.Errorf("orders bucket not found")
		}
		if ordersBucket.Get(itob(orderID)) == nil {
			return fiber.ErrNotFound // Order doesn't exist
		}
		if err := ordersBucket.Delete(itob(orderID)); err != nil {
			return fmt.Errorf("failed to delete order data: %w", err)
		}
		// TODO: Delete from Bleve index
		return nil
	})

	if deleteErr != nil {
		if errors.Is(deleteErr, fiber.ErrNotFound) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Order not found"})
		}
		log.Printf("ERROR: Failed to delete order %d: %v", orderID, deleteErr)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to delete order"})
	}

	adminUserID, _ := getCurrentUserID(c)
	log.Printf("INFO: Order %d deleted by admin %d", orderID, adminUserID)
	return c.SendStatus(fiber.StatusNoContent)
}

// --- API Handlers: Visits --- (Implementations added/updated)

// POST /api/visits
func createVisitHandler(c *fiber.Ctx) error {
	req := new(Visit) // Use Visit struct directly for request body
	if err := c.BodyParser(req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request body"})
	}
	if req.ClientID <= 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Client ID is required"})
	}
	// Notes can be optional or required based on needs
	// if req.Notes == "" {
	//     return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Visit notes are required"})
	// }

	currentUserID, err := getCurrentUserID(c)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Could not identify current user"})
	}

	var newVisit Visit
	creationErr := db.Update(func(tx *bolt.Tx) error {
		visitsBucket := tx.Bucket([]byte(bVisits))
		clientsBucket := tx.Bucket([]byte(bClients))
		if visitsBucket == nil || clientsBucket == nil {
			return fmt.Errorf("internal configuration error: missing buckets")
		}

		// Verify the client exists
		if clientsBucket.Get(itob(req.ClientID)) == nil {
			return fiber.NewError(fiber.StatusBadRequest, fmt.Sprintf("client with ID %d not found", req.ClientID))
		}

		id, _ := visitsBucket.NextSequence()
		newVisitID := int(id)
		nowIST := time.Now().In(istLocation) // Fetch current time in IST

		newVisit = Visit{
			ID:        newVisitID,
			ClientID:  req.ClientID,
			UserID:    currentUserID, // Logged in user made the visit
			VisitDate: nowIST,        // Set VisitDate to current IST when record is created
			Notes:     req.Notes,
			CreatedAt: time.Now(), // Keep CreatedAt for record creation timestamp
		}

		visitData, err := json.Marshal(newVisit)
		if err != nil {
			return fmt.Errorf("failed to prepare visit data: %w", err)
		}
		if err := visitsBucket.Put(itob(newVisit.ID), visitData); err != nil {
			return fmt.Errorf("failed to save new visit: %w", err)
		}
		// TODO: Index visit in Bleve
		return nil
	})

	if creationErr != nil {
		var fiberErr *fiber.Error
		if errors.As(creationErr, &fiberErr) {
			return c.Status(fiberErr.Code).JSON(fiber.Map{"error": fiberErr.Message})
		}
		log.Printf("ERROR: Failed to commit visit creation transaction for client %d by user %d: %v", req.ClientID, currentUserID, creationErr)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create visit record"})
	}

	log.Printf("INFO: User %d logged visit %d for client %d at %s (IST)", currentUserID, newVisit.ID, newVisit.ClientID, newVisit.VisitDate.Format(time.RFC3339))
	return c.Status(fiber.StatusCreated).JSON(newVisit)
}

// GET /api/visits
func getVisitsHandler(c *fiber.Ctx) error {
	currentUserID, err := getCurrentUserID(c)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Could not identify current user"})
	}
	isAdmin := isCurrentUserAdmin(c)

	var visits []Visit
	fetchErr := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bVisits))
		if b == nil {
			log.Println("INFO: Visits bucket not found, returning empty list.")
			return nil
		}
		cursor := b.Cursor()
		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			var visit Visit
			if err := json.Unmarshal(v, &visit); err != nil {
				log.Printf("WARN: Failed to unmarshal visit data key %s: %v", string(k), err)
				continue
			}
			// Filter: Admins see all, users see only their own
			if isAdmin || visit.UserID == currentUserID {
				visits = append(visits, visit)
			}
		}
		return nil
	})

	if fetchErr != nil {
		log.Printf("ERROR: Failed to get visits: %v", fetchErr)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to retrieve visits"})
	}
	return c.JSON(visits)
}

// PUT /api/visits/:id
func updateVisitHandler(c *fiber.Ctx) error {
	visitID, err := strconv.Atoi(c.Params("id"))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid visit ID"})
	}
	currentUserID, err := getCurrentUserID(c)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Could not identify current user"})
	}
	isAdmin := isCurrentUserAdmin(c)

	req := new(UpdateVisitRequest) // Use specific update request struct
	if err := c.BodyParser(req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request body"})
	}
	// Add validation for notes if needed (e.g., max length)

	var updatedVisit Visit
	updateErr := db.Update(func(tx *bolt.Tx) error {
		visitsBucket := tx.Bucket([]byte(bVisits))
		if visitsBucket == nil {
			return fmt.Errorf("visits bucket not found")
		}
		visitData := visitsBucket.Get(itob(visitID))
		if visitData == nil {
			return fiber.ErrNotFound
		}
		var existingVisit Visit
		if err := json.Unmarshal(visitData, &existingVisit); err != nil {
			return fmt.Errorf("failed to parse existing visit data")
		}

		// Permission Check: Allow update only if admin or the original creator
		if !isAdmin && existingVisit.UserID != currentUserID {
			return fiber.NewError(fiber.StatusForbidden, "Forbidden: Cannot update visit logged by another user")
		}

		// Apply updates (currently only notes)
		updatedVisit = existingVisit // Copy existing visit
		updatedVisit.Notes = req.Notes
		// Note: Should VisitDate be updatable? Probably not automatically. Add if required.
		// updatedVisit.UpdatedAt = time.Now() // Add UpdatedAt field to Visit struct if needed

		newVisitData, err := json.Marshal(updatedVisit)
		if err != nil {
			return fmt.Errorf("failed to prepare updated visit data: %w", err)
		}
		if err := visitsBucket.Put(itob(visitID), newVisitData); err != nil {
			return fmt.Errorf("failed to save updated visit data: %w", err)
		}
		// TODO: Update Bleve index if notes changed
		return nil
	})

	if updateErr != nil {
		var fiberErr *fiber.Error
		if errors.As(updateErr, &fiberErr) {
			return c.Status(fiberErr.Code).JSON(fiber.Map{"error": fiberErr.Message})
		}
		log.Printf("ERROR: Failed to update visit %d: %v", visitID, updateErr)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update visit"})
	}
	log.Printf("INFO: Visit %d updated by user %d", visitID, currentUserID)
	return c.JSON(updatedVisit)
}

// DELETE /api/visits/:id (Admin Only)
func deleteVisitHandler(c *fiber.Ctx) error {
	visitID, err := strconv.Atoi(c.Params("id"))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid visit ID"})
	}

	deleteErr := db.Update(func(tx *bolt.Tx) error {
		visitsBucket := tx.Bucket([]byte(bVisits))
		if visitsBucket == nil {
			return fmt.Errorf("visits bucket not found")
		}
		if visitsBucket.Get(itob(visitID)) == nil {
			return fiber.ErrNotFound // Visit doesn't exist
		}
		if err := visitsBucket.Delete(itob(visitID)); err != nil {
			return fmt.Errorf("failed to delete visit data: %w", err)
		}
		// TODO: Delete from Bleve index
		return nil
	})

	if deleteErr != nil {
		if errors.Is(deleteErr, fiber.ErrNotFound) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Visit not found"})
		}
		log.Printf("ERROR: Failed to delete visit %d: %v", visitID, deleteErr)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to delete visit"})
	}

	adminUserID, _ := getCurrentUserID(c)
	log.Printf("INFO: Visit %d deleted by admin %d", visitID, adminUserID)
	return c.SendStatus(fiber.StatusNoContent)
}

// --- API Handlers: Search ---

// GET /api/search
func searchHandler(c *fiber.Ctx) error {
	log.Println("TODO: Implement searchHandler using Bleve index `idx`")
	_ = c // Avoid unused variable error
	return c.Status(fiber.StatusNotImplemented).JSON(fiber.Map{"message": "Handler not implemented yet"})
}

// --- NEW: Master API Handler ---
// PUT /api/master/:bucket/:key (Admin Only)
func masterUpdateHandler(c *fiber.Ctx) error {
	bucketName := c.Params("bucket")
	key := c.Params("key")
	rawData := c.Body() // Get raw body bytes

	if bucketName == "" || key == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Bucket name and key are required in URL path"})
	}
	if len(rawData) == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Request body cannot be empty"})
	}

	// Basic JSON validation before writing
	if !json.Valid(rawData) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Request body must be valid JSON"})
	}

	// 🚨 DANGER ZONE: This allows overwriting anything!
	log.Printf("WARN: Master API attempting update: Bucket=%s, Key=%s", bucketName, key)
	updateErr := db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketName))
		if bucket == nil {
			// Optionally create the bucket if it doesn't exist? Or return error?
			// _, err := tx.CreateBucketIfNotExists([]byte(bucketName))
			// if err != nil { return fmt.Errorf("failed to create bucket '%s': %w", bucketName, err) }
			// bucket = tx.Bucket([]byte(bucketName))
			return fiber.NewError(fiber.StatusNotFound, fmt.Sprintf("Bucket '%s' not found", bucketName))
		}
		if err := bucket.Put([]byte(key), rawData); err != nil {
			return fmt.Errorf("failed to put data into bucket '%s' for key '%s': %w", bucketName, key, err)
		}
		return nil
	})

	if updateErr != nil {
		var fiberErr *fiber.Error
		if errors.As(updateErr, &fiberErr) {
			return c.Status(fiberErr.Code).JSON(fiber.Map{"error": fiberErr.Message})
		}
		log.Printf("ERROR: Master API update failed for Bucket=%s, Key=%s: %v", bucketName, key, updateErr)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Master update failed"})
	}

	adminUserID, _ := getCurrentUserID(c)
	log.Printf("INFO: Master API: Admin %d successfully updated Bucket=%s, Key=%s", adminUserID, bucketName, key)
	return c.JSON(fiber.Map{"status": "ok", "message": fmt.Sprintf("Successfully updated key '%s' in bucket '%s'", key, bucketName)})
}

// --- Background Jobs ---
func startReportJobs() {
	log.Println("INFO: Starting background Client Activity Summary report jobs...")
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for now := range ticker.C {
		nowIST := now.In(istLocation)
		wd, h, m := nowIST.Weekday(), nowIST.Hour(), nowIST.Minute()
		var reportDuration time.Duration
		var reportSubject string
		if wd >= time.Monday && wd <= time.Friday && h == 19 && m == 30 {
			reportDuration = reportDaily
			reportSubject = fmt.Sprintf("Daily Client Activity Report (%s)", nowIST.Format("Jan 2, 2006"))
		} else if wd == time.Saturday && h == 20 && m == 0 {
			reportDuration = reportWeekly
			reportSubject = fmt.Sprintf("Weekly Client Activity Report (Week ending %s)", nowIST.Format("Jan 2, 2006"))
		} else {
			continue
		}
		log.Printf("INFO: Triggering %s generation...", reportSubject)
		reportData := generateReportData(db, reportDuration)
		html, err := generateReportHTML(reportData)
		if err != nil {
			log.Printf("ERROR: Failed to generate %s HTML: %v", reportSubject, err)
			continue
		}
		recipients, err := getReportRecipientsEmails(db)
		if err != nil {
			log.Printf("ERROR: Failed to get recipients for %s: %v", reportSubject, err)
			continue
		}
		if len(recipients) > 0 {
			go sendEmail(recipients, reportSubject, html)
		} else {
			log.Printf("WARN: No recipients found for %s.", reportSubject)
		}
	}
}

// --- Database Initialization and Seeding ---

func initializeDB(dbPath string) (*bolt.DB, error) {
	log.Printf("INFO: Initializing database at %s", dbPath)
	if err := os.MkdirAll(path.Dir(dbPath), 0750); err != nil {
		return nil, fmt.Errorf("failed to create database directory '%s': %w", path.Dir(dbPath), err)
	}
	dbConn, err := bolt.Open(dbPath, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("failed to open database '%s': %w", dbPath, err)
	}
	err = dbConn.Update(func(tx *bolt.Tx) error {
		requiredBuckets := []string{bUsers, bUsernames, bUserPasswords, bClients, bVisits, bProducts, bOrders, bOrderItems, bPWResets}
		for _, bucketName := range requiredBuckets {
			if _, err := tx.CreateBucketIfNotExists([]byte(bucketName)); err != nil {
				return fmt.Errorf("failed to create bucket '%s': %w", bucketName, err)
			}
		}
		return nil
	})
	if err != nil {
		dbConn.Close() // Close connection if bucket creation fails
		return nil, fmt.Errorf("failed to initialize buckets: %w", err)
	}
	log.Println("INFO: Database initialized successfully.")
	return dbConn, nil
}

// Seed admin user with PLAIN TEXT password (INSECURE)
func seedAdminUser(db *bolt.DB) error {
	if AdminDefaultPassword == "" {
		log.Println("WARN: Skipping admin seeding: AdminDefaultPassword constant is empty.")
		return nil
	}
	err := db.Update(func(tx *bolt.Tx) error {
		usersBucket := tx.Bucket([]byte(bUsers))
		usernamesBucket := tx.Bucket([]byte(bUsernames))
		passwordsBucket := tx.Bucket([]byte(bUserPasswords))
		if usersBucket == nil || usernamesBucket == nil || passwordsBucket == nil {
			return fmt.Errorf("required buckets not found during seeding")
		}
		// Check if admin username already exists
		if usernamesBucket.Get([]byte(AdminUsername)) != nil {
			log.Printf("INFO: User '%s' already exists. Skipping seeding.", AdminUsername)
			// Optionally check if password needs seeding/resetting even if user exists
			return nil
		}

		log.Printf("INFO: Seeding user '%s'...", AdminUsername)
		id, _ := usersBucket.NextSequence()
		adminUserID := int(id)
		adminUser := User{
			ID:        adminUserID,
			Username:  AdminUsername,
			Email:     AdminDefaultEmail,
			IsAdmin:   true,
			CreatedAt: time.Now(),
		}
		userData, err := json.Marshal(adminUser)
		if err != nil {
			return fmt.Errorf("failed to marshal admin user data: %w", err)
		}
		if err := usersBucket.Put(itob(adminUserID), userData); err != nil {
			return fmt.Errorf("failed to save admin user data: %w", err)
		}
		if err := usernamesBucket.Put([]byte(adminUser.Username), itob(adminUserID)); err != nil {
			return fmt.Errorf("failed to save admin username mapping: %w", err)
		}
		// 🚨🚨 INSECURE: Storing plain text password 🚨🚨
		if err := passwordsBucket.Put(itob(adminUserID), []byte(AdminDefaultPassword)); err != nil {
			return fmt.Errorf("failed to save admin user password: %w", err)
		}
		log.Printf("INFO: 🔧 Seeded admin user: %s (ID: %d) with PLAIN TEXT password.", adminUser.Username, adminUserID)
		return nil
	})
	if err != nil {
		return fmt.Errorf("admin seeding transaction failed: %w", err)
	}
	return nil
}

func initializeBleve(indexPath string) (bleve.Index, error) {
	log.Printf("INFO: Initializing Bleve index at %s", indexPath)
	index, err := bleve.Open(indexPath)
	if errors.Is(err, bleve.ErrorIndexPathDoesNotExist) {
		log.Printf("INFO: Creating new Bleve index at '%s'...", indexPath)
		mapping := bleve.NewIndexMapping() // TODO: Define actual mapping
		index, err = bleve.New(indexPath, mapping)
		if err != nil {
			return nil, fmt.Errorf("failed to create new bleve index: %w", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("failed to open existing bleve index '%s': %w", indexPath, err)
	} else {
		log.Println("INFO: Opened existing Bleve index.")
	}
	return index, nil
}

// --- Main Application ---

func main() {
	log.Println("INFO: Application starting...")

	var err error
	istLocation, err = time.LoadLocation("Asia/Kolkata")
	if err != nil {
		log.Fatalf("FATAL: Failed to load IST location: %v", err)
	}
	log.Printf("INFO: Loaded time zone: %s", istLocation.String())

	db, err = initializeDB(DatabasePath)
	if err != nil {
		log.Fatalf("FATAL: Database initialization failed: %v", err)
	}
	defer func() {
		log.Println("INFO: Closing database connection...")
		if err := db.Close(); err != nil {
			log.Printf("ERROR: Failed to close database cleanly: %v", err)
		}
	}()

	if err := seedAdminUser(db); err != nil {
		log.Printf("ERROR: Admin user seeding failed: %v", err)
		// Continue running even if seeding fails? Or Fatal?
	}

	idx, err = initializeBleve(BlevePath)
	if err != nil {
		log.Fatalf("FATAL: Bleve search index initialization failed: %v", err)
	}
	defer func() {
		log.Println("INFO: Closing Bleve index...")
		if err := idx.Close(); err != nil {
			log.Printf("ERROR: Failed to close Bleve index cleanly: %v", err)
		}
	}()

	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			code := fiber.StatusInternalServerError
			message := "Internal Server Error"
			var e *fiber.Error
			if errors.As(err, &e) {
				code = e.Code
				message = e.Message
			} else {
				// Log non-fiber errors
				log.Printf("ERROR: [%s] %s - Unhandled Error: %v", c.Method(), c.Path(), err)
			}
			// Avoid sending detailed internal errors to client
			return c.Status(code).JSON(fiber.Map{"error": message})
		},
	})

	app.Use(recover.New())
	app.Use(cors.New(cors.Config{AllowOrigins: CORSOrigin, AllowHeaders: "Origin, Content-Type, Accept, Authorization", AllowMethods: "GET, POST, PUT, DELETE, OPTIONS"}))
	app.Use(logger.New(logger.Config{Format: "[${time}] ${ip}:${port} ${status} - ${method} ${path} (${latency})\n", TimeFormat: "2006/01/02 15:04:05", TimeZone: istLocation.String()}))

	httpRequestsTotal := promauto.NewCounterVec(prometheus.CounterOpts{Name: "http_requests_total", Help: "Total number of HTTP requests."}, []string{"method", "path", "status_code"})
	app.Use(func(c *fiber.Ctx) error {
		err := c.Next() // Execute route handler first
		statusCode := c.Response().StatusCode()
		// Determine status code even if error occurred
		if err != nil {
			var e *fiber.Error
			if errors.As(err, &e) {
				statusCode = e.Code
			} else {
				// If it wasn't a fiber error but c.Next() returned one, assume 500
				if statusCode < 400 { // Avoid overriding specific error codes set before Next()
					statusCode = fiber.StatusInternalServerError
				}
			}
		}
		routePath := "unknown"
		if r := c.Route(); r != nil {
			routePath = r.Path
		}
		httpRequestsTotal.WithLabelValues(c.Method(), routePath, strconv.Itoa(statusCode)).Inc()
		return err // Return the original error
	})
	app.Get("/metrics", metricsHandler)

	// --- Public Routes ---
	app.Get("/healthz", healthzHandler)
	app.Post("/token", loginHandler)
	app.Post("/send-test-email", sendTestEmailHandler)
	app.Post("/send-report", sendReportHandler)
	app.Post("/send-daily-report-manual", sendDailyReportManualHandler)
	app.Post("/send-weekly-report-manual", sendWeeklyReportManualHandler)

	// --- API Routes (Require Authentication) ---
	jwtMiddleware := NewJWTMiddleware()
	api := app.Group("/api", jwtMiddleware, authRequired)

	// User Management
	usersAPI := api.Group("/users")
	usersAPI.Post("/", adminOnly, createUserHandler)
	usersAPI.Get("/", adminOnly, getUsersHandler)
	usersAPI.Get("/:id", getUserHandler)
	usersAPI.Put("/:id", updateUserHandler)                             // Combined admin/self update logic
	usersAPI.Delete("/:id", adminOnly, deleteUserHandler)               // Admin only delete
	usersAPI.Put("/me/password", changeMyPasswordHandler)               // Self password change
	usersAPI.Put("/:id/password", adminOnly, changeUserPasswordHandler) // Admin changes other user password

	// Client Management
	clientsAPI := api.Group("/clients")
	clientsAPI.Post("/", createClientHandler)
	clientsAPI.Get("/", getClientsHandler) // Includes search query handling
	clientsAPI.Get("/:id", getClientHandler)
	clientsAPI.Put("/:id", updateClientHandler)               // Combined admin/self update logic
	clientsAPI.Delete("/:id", adminOnly, deleteClientHandler) // Admin only delete

	// Product Management (Allow GET for all authenticated users)
	productsAPI := api.Group("/products")
	productsAPI.Post("/", adminOnly, createProductHandler)
	productsAPI.Get("/", getProductsHandler)   // Authenticated users can GET list
	productsAPI.Get("/:id", getProductHandler) // Authenticated users can GET single
	productsAPI.Put("/:id", adminOnly, updateProductHandler)
	productsAPI.Delete("/:id", adminOnly, deleteProductHandler)

	// Order Management
	ordersAPI := api.Group("/orders")
	ordersAPI.Post("/", createOrderHandler)
	ordersAPI.Get("/", getOrdersHandler)                    // GET list implemented (filtered by user/admin)
	ordersAPI.Get("/:id", getOrderHandler)                  // GET single implemented (filtered by user/admin)
	ordersAPI.Put("/:id", updateOrderHandler)               // PUT implemented (filtered by user/admin, limited fields)
	ordersAPI.Delete("/:id", adminOnly, deleteOrderHandler) // DELETE implemented (admin only)

	// Visit Management
	visitsAPI := api.Group("/visits")
	visitsAPI.Post("/", createVisitHandler)
	visitsAPI.Get("/", getVisitsHandler)                    // GET list implemented (filtered by user/admin)
	visitsAPI.Put("/:id", updateVisitHandler)               // PUT implemented (filtered by user/admin, limited fields)
	visitsAPI.Delete("/:id", adminOnly, deleteVisitHandler) // DELETE implemented (admin only)

	// Search (Placeholder)
	api.Get("/search", searchHandler)

	// --- NEW: Master API ---
	// 🚨🚨 DANGER: Allows admin to overwrite any key in any bucket! USE WITH EXTREME CAUTION! 🚨🚨
	masterAPI := api.Group("/master", adminOnly) // Ensure only admins can access
	masterAPI.Put("/:bucket/:key", masterUpdateHandler)

	// --- Static File Server ---
	app.Static("/", "./static")       // Serve index.html from root? Or specific path?
	app.Static("/static", "./static") // Serve files from ./static folder

	// --- Start Background Jobs ---
	go startReportJobs()

	// --- Start Server and Handle Shutdown ---
	interruptChan := make(chan os.Signal, 1)
	signal.Notify(interruptChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-interruptChan
		log.Printf("INFO: Received signal: %s. Starting graceful shutdown...", sig)
		if err := app.Shutdown(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("WARN: Server shutdown failed: %v", err)
		} else {
			log.Println("INFO: Server gracefully shut down.")
		}
	}()

	listenAddr := ":" + Port
	log.Printf("INFO: Starting server, listening on %s", listenAddr)
	if err := app.Listen(listenAddr); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("ERROR: Server listener failed: %v", err)
	}

	log.Println("INFO: Application shutdown complete.")
}
