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
	// bcrypt should be added for password hashing!
	// "golang.org/x/crypto/bcrypt"
)

// --- Configuration Constants ---
// 🚨 WARNING: Move sensitive values (Passwords, Secrets) out of code! Use Env Vars or Config Files. 🚨
const (
	Port                 = "8080"
	DatabasePath         = "data/db/sales.db"          // Should be configurable
	BlevePath            = "index.bleve"               // Should be configurable
	JWTSecret            = "Goat@2570"                 // 🚨 INSECURE: Move to Env Var/Config
	TokenExpiryHours     = 72                          // Token expiry in hours
	AdminUsername        = "admin"                     // Default admin username for seeding
	AdminDefaultPassword = "Goat@2570"                 // 🚨 INSECURE: Plain text password - Use Hashing! Move default out/handle differently.
	AdminDefaultEmail    = "support@nextviewkavach.in" // Default admin email
	SMTPServer           = "smtp.hostinger.com:587"    // 🚨 Move to Env Var/Config
	SMTPUser             = "report@nextviewkavach.in"  // 🚨 Move to Env Var/Config
	SMTPPass             = "Goat@2570"                 // 🚨 INSECURE: Move to Env Var/Config
	FromEmail            = "report@nextviewkavach.in"  // Default FROM email address - Move to Env Var/Config?
	ReportAdminCCEmail   = "support@nextviewkavach.in" // 🚨 Email address(es) to CC on USER reports - Move to Env Var/Config
	CORSOrigin           = "*"                         // CORS allowed origins (use specific origins for prod) - Move to Env Var/Config?
)

// BoltDB Bucket Names
const (
	bUsers         = "users"
	bUsernames     = "usernames"
	bUserPasswords = "user_passwords" // <-- 🚨 BUCKET FOR PLAIN TEXT PASSWORDS (INSECURE) - Remove when using hashing
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
// User struct - Password field is used temporarily but not stored in main user JSON if hashed
type User struct {
	ID        int       `json:"id"`
	Username  string    `json:"username"` // Used for report subject personalization
	Email     string    `json:"email"`
	Password  string    `json:"-"`       // 🚨 Plain text password (json:"-" means NOT exposed/stored in this JSON) - Replace with PasswordHash string `json:"-"`
	IsAdmin   bool      `json:"isAdmin"` // Needed to identify admins for summary report
	CreatedAt time.Time `json:"createdAt"`
	// Add: Name string `json:"name"`, Phone string `json:"phone"`, IsActive bool `json:"isActive"`, Role string `json:"role"` etc.
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
	CreatedBy int         `json:"createdBy"` // User ID who created the order
	CreatedAt time.Time   `json:"createdAt"`
	UpdatedAt time.Time   `json:"updatedAt"`
	Items     []OrderItem `json:"items"` // Embed order items
}

type OrderItem struct {
	ProductID    int     `json:"productId"`
	Quantity     int     `json:"quantity"`
	PriceAtOrder float64 `json:"priceAtOrder"` // Price when the order was placed
}

// UpdateOrderRequest defines fields allowed for update
type UpdateOrderRequest struct {
	Status string `json:"status"` // Example: only allow status update
}

type Visit struct {
	ID        int       `json:"id"`
	ClientID  int       `json:"clientId"`
	UserID    int       `json:"userId"`    // User who made the visit
	VisitDate time.Time `json:"visitDate"` // Will be set to IST automatically
	Notes     string    `json:"notes"`
	CreatedAt time.Time `json:"createdAt"` // Auto-populated timestamp
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
	Password string `json:"password"` // 🚨 Should be compared against hash
}

type CreateUserRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"` // 🚨 Should be hashed before storing
	IsAdmin  bool   `json:"isAdmin"`
}

type CreateOrderRequest struct {
	ClientID int                `json:"clientId"`
	Items    []OrderItemRequest `json:"items"`
}

type OrderItemRequest struct {
	ProductID int `json:"productId"`
	Quantity  int `json:"quantity"`
}

type ChangePasswordRequest struct {
	OldPassword string `json:"oldPassword"` // Needed for self-change
	NewPassword string `json:"newPassword"` // 🚨 Should be hashed before storing if admin sets it
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
		// If called during report generation, maybe return a placeholder instead of error?
		return client, fmt.Errorf("bucket %s not found", bClients)
	}
	clientData := clientsBucket.Get(itob(clientID))
	if clientData == nil {
		// Return a placeholder or specific error if client not found
		return Client{ID: clientID, Name: fmt.Sprintf("Client ID %d (Not Found)", clientID)}, fmt.Errorf("client ID %d not found", clientID)
	}
	if err := json.Unmarshal(clientData, &client); err != nil {
		// Return placeholder or error
		return Client{ID: clientID, Name: fmt.Sprintf("Client ID %d (Error Reading)", clientID)}, fmt.Errorf("error reading client ID %d data: %w", clientID, err)
	}
	return client, nil
}

// sendEmail sends an email using configured SMTP settings, now with CC support
func sendEmail(to []string, cc []string, subj, body string) error { // Added cc parameter
	if len(to) == 0 {
		log.Println("WARN: No primary recipients provided for email. Skipping.")
		return nil // Not an error, just nothing to do
	}
	// Using hardcoded constants directly - 🚨 MOVE TO CONFIG
	if SMTPServer == "" || SMTPUser == "" || SMTPPass == "" {
		log.Println("WARN: SMTP settings not fully configured (using hardcoded values). Skipping email.")
		return fmt.Errorf("SMTP settings not configured") // Return an error
	}

	// Clean primary recipient list (remove duplicates, empty strings)
	validRecipients := []string{}
	seenTo := make(map[string]bool)
	for _, email := range to {
		trimmed := strings.TrimSpace(email)
		if trimmed != "" && !seenTo[trimmed] {
			if strings.Contains(trimmed, "@") { // Basic check
				validRecipients = append(validRecipients, trimmed)
				seenTo[trimmed] = true
			} else {
				log.Printf("WARN: Skipping invalid recipient email format (To): %s", email)
			}
		}
	}

	// Clean CC recipient list
	validCCCipients := []string{}
	seenCC := make(map[string]bool)
	for _, email := range cc {
		trimmed := strings.TrimSpace(email)
		// Avoid CC'ing someone already in the To list or duplicate CCs
		if trimmed != "" && !seenTo[trimmed] && !seenCC[trimmed] {
			if strings.Contains(trimmed, "@") { // Basic check
				validCCCipients = append(validCCCipients, trimmed)
				seenCC[trimmed] = true
			} else {
				log.Printf("WARN: Skipping invalid recipient email format (CC): %s", email)
			}
		}
	}

	if len(validRecipients) == 0 {
		log.Println("WARN: No valid primary recipients after cleaning. Skipping email.")
		return nil
	}

	// Construct headers with conditional CC
	headers := fmt.Sprintf(
		"From: %s\r\nTo: %s\r\n",
		FromEmail, strings.Join(validRecipients, ","),
	)
	if len(validCCCipients) > 0 {
		headers += fmt.Sprintf("Cc: %s\r\n", strings.Join(validCCCipients, ",")) // Add CC header
	}
	headers += fmt.Sprintf("Subject: %s\r\nImportance: High\r\nMIME-Version: 1.0;\r\nContent-Type: text/html; charset=\"UTF-8\";\r\n\r\n", subj)

	msg := []byte(headers + body)

	host := strings.Split(SMTPServer, ":")[0]
	auth := smtp.PlainAuth("", SMTPUser, SMTPPass, host) // 🚨 Using hardcoded credentials

	// Combine To and CC for the SendMail recipient list
	allRecipientsForSendMail := append([]string{}, validRecipients...)
	allRecipientsForSendMail = append(allRecipientsForSendMail, validCCCipients...)

	err := smtp.SendMail(SMTPServer, auth, FromEmail, allRecipientsForSendMail, msg) // Use combined list
	if err != nil {
		log.Printf("ERROR: sendEmail failed (To: %s, CC: %s): %v", strings.Join(validRecipients, ","), strings.Join(validCCCipients, ","), err)
		return fmt.Errorf("failed to send email: %w", err) // Return wrapped error
	}

	log.Printf("INFO: Email sent successfully (To: %s, CC: %s)", strings.Join(validRecipients, ","), strings.Join(validCCCipients, ","))
	return nil // Success
}

// --- Reporting Functions ---
type ClientActivitySummary struct {
	ClientID        int
	ClientName      string
	ClientEmail     string
	ClientPhone     string
	IsNew           bool    // Was the client created during this period?
	HadVisit        bool    // Did the client have any visits during this period?
	VisitCount      int     // How many visits?
	HadOrder        bool    // Did the client have any orders during this period?
	OrderCount      int     // How many orders?
	TotalOrderValue float64 // Total value of orders in this period
	// Potentially add fields for "Created By User" or "Visited By User" if needed in summary rows
}
type ReportData struct {
	Period                string
	StartDate             time.Time
	EndDate               time.Time
	ClientSummaries       []ClientActivitySummary // List of client activity summaries
	TotalReportOrderValue float64                 // Grand total order value for the report (user-specific or admin-summary)
	DataGenerationError   string                  // To capture errors during data fetching
}

// getReportRecipients fetches user details (ID, Username, Email, IsAdmin) for report sending
func getReportRecipients(db *bolt.DB) ([]User, error) {
	var users []User
	err := db.View(func(tx *bolt.Tx) error {
		usersBucket := tx.Bucket([]byte(bUsers))
		if usersBucket == nil {
			return fmt.Errorf("users bucket not found")
		}

		cursor := usersBucket.Cursor()
		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			var user User
			if err := json.Unmarshal(v, &user); err != nil {
				log.Printf("WARN: Failed to unmarshal user data for key %s in getReportRecipients: %v", string(k), err)
				continue
			}
			// Include user if they have an email (add other conditions like IsActive if needed)
			if user.Email != "" {
				// Include IsAdmin flag needed for admin report filtering
				users = append(users, User{
					ID:       user.ID,
					Username: user.Username, // Needed for subject
					Email:    user.Email,    // Needed for To: field
					IsAdmin:  user.IsAdmin,  // Needed to identify admins
				})
			}
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to fetch report recipients: %w", err)
	}
	if len(users) == 0 {
		log.Println("WARN: No users found with email addresses for reporting.")
	}
	return users, nil
}

// generateUserReportData generates activity summary data FILTERED FOR A SPECIFIC USER.
func generateUserReportData(db *bolt.DB, userID int, duration time.Duration) ReportData {
	now := time.Now().In(istLocation) // Use IST
	startTime := now.Add(-duration)
	report := ReportData{
		StartDate:             startTime,
		EndDate:               now,
		ClientSummaries:       make([]ClientActivitySummary, 0),
		TotalReportOrderValue: 0.0,
	}

	activityMap := make(map[int]*ClientActivitySummary) // Map client ID to its summary

	err := db.View(func(tx *bolt.Tx) error {
		clientsBucket := tx.Bucket([]byte(bClients))
		visitsBucket := tx.Bucket([]byte(bVisits))
		ordersBucket := tx.Bucket([]byte(bOrders))

		// --- Process Visits (for this user) ---
		if visitsBucket != nil {
			cursorVisits := visitsBucket.Cursor()
			for k, v := cursorVisits.First(); k != nil; k, v = cursorVisits.Next() {
				var visit Visit
				if err := json.Unmarshal(v, &visit); err == nil {
					// *** FILTER: Only include if visited by the target user ***
					if visit.UserID != userID {
						continue
					}
					visitDateIST := visit.VisitDate.In(istLocation)
					if visitDateIST.After(startTime) && !visitDateIST.After(now) {
						if _, exists := activityMap[visit.ClientID]; !exists {
							clientDetails, _ := getClientDetails(tx, visit.ClientID) // Ignore error for simplicity here, getClientDetails returns placeholder on error
							activityMap[visit.ClientID] = &ClientActivitySummary{
								ClientID:    clientDetails.ID,
								ClientName:  clientDetails.Name,
								ClientEmail: clientDetails.Email,
								ClientPhone: clientDetails.Phone,
							}
						}
						summary := activityMap[visit.ClientID]
						summary.HadVisit = true
						summary.VisitCount++
					}
				} else {
					log.Printf("WARN: Failed to unmarshal visit %s in user report data: %v", string(k), err)
				}
			}
		} else {
			log.Printf("WARN: Bucket %s not found for user report, skipping visit data.", bVisits)
		}

		// --- Process Orders (created by this user) ---
		if ordersBucket != nil {
			cursorOrders := ordersBucket.Cursor()
			for k, v := cursorOrders.First(); k != nil; k, v = cursorOrders.Next() {
				var order Order
				if err := json.Unmarshal(v, &order); err == nil {
					// *** FILTER: Only include if created by the target user ***
					if order.CreatedBy != userID {
						continue
					}
					orderDateIST := order.OrderDate.In(istLocation)
					if orderDateIST.After(startTime) && !orderDateIST.After(now) {
						if _, exists := activityMap[order.ClientID]; !exists {
							clientDetails, _ := getClientDetails(tx, order.ClientID) // Ignore error
							activityMap[order.ClientID] = &ClientActivitySummary{
								ClientID:    clientDetails.ID,
								ClientName:  clientDetails.Name,
								ClientEmail: clientDetails.Email,
								ClientPhone: clientDetails.Phone,
							}
						}
						summary := activityMap[order.ClientID]
						summary.HadOrder = true
						summary.OrderCount++
						summary.TotalOrderValue += order.Total
					}
				} else {
					log.Printf("WARN: Failed to unmarshal order %s in user report data: %v", string(k), err)
				}
			}
		} else {
			log.Printf("WARN: Bucket %s not found for user report, skipping order data.", bOrders)
		}

		// --- Process New Clients (created by this user) ---
		// Decide if "new" means created by this user OR first activity (visit/order) by this user
		// This example assumes "created by this user"
		if clientsBucket != nil {
			cursorClients := clientsBucket.Cursor()
			for k, v := cursorClients.First(); k != nil; k, v = cursorClients.Next() {
				var client Client
				if err := json.Unmarshal(v, &client); err == nil {
					// *** FILTER: Only include if created by the target user ***
					if client.CreatedBy != userID {
						continue
					}
					createdAtIST := client.CreatedAt.In(istLocation)
					if createdAtIST.After(startTime) && !createdAtIST.After(now) {
						// Add to map if not already there from visit/order
						if _, exists := activityMap[client.ID]; !exists {
							activityMap[client.ID] = &ClientActivitySummary{
								ClientID:    client.ID,
								ClientName:  client.Name,
								ClientEmail: client.Email,
								ClientPhone: client.Phone,
							}
						}
						activityMap[client.ID].IsNew = true // Mark as new within this period *by this user*
					}
				} else {
					log.Printf("WARN: Failed to unmarshal client %s in user report new client check: %v", string(k), err)
				}
			}
		} else {
			log.Printf("WARN: Bucket %s not found for user report, skipping new client check.", bClients)
		}

		return nil
	})

	if err != nil {
		log.Printf("ERROR: Failed generating user %d activity summary report data: %v", userID, err)
		report.DataGenerationError = err.Error()
		// Return partial report or empty? Returning potentially partial data.
	}

	// Convert map to slice and calculate total value for this user
	summaries := make([]ClientActivitySummary, 0, len(activityMap))
	userTotalValue := 0.0
	for _, summary := range activityMap {
		summaries = append(summaries, *summary)
		userTotalValue += summary.TotalOrderValue
	}
	report.TotalReportOrderValue = userTotalValue // Set user-specific total

	// Sort summaries (e.g., by client name or ID)
	sort.Slice(summaries, func(i, j int) bool {
		return summaries[i].ClientID < summaries[j].ClientID // Simple sort by ID
	})

	report.ClientSummaries = summaries
	return report
}

// generateAdminSummaryReportData generates activity summary data for ALL users combined.
func generateAdminSummaryReportData(db *bolt.DB, duration time.Duration) ReportData {
	now := time.Now().In(istLocation) // Use IST
	startTime := now.Add(-duration)
	report := ReportData{
		StartDate:             startTime,
		EndDate:               now,
		ClientSummaries:       make([]ClientActivitySummary, 0),
		TotalReportOrderValue: 0.0, // Initialize grand total
	}

	activityMap := make(map[int]*ClientActivitySummary) // Map client ID to its summary

	err := db.View(func(tx *bolt.Tx) error {
		clientsBucket := tx.Bucket([]byte(bClients))
		visitsBucket := tx.Bucket([]byte(bVisits))
		ordersBucket := tx.Bucket([]byte(bOrders))

		// --- Process ALL Visits ---
		if visitsBucket != nil {
			cursorVisits := visitsBucket.Cursor()
			for k, v := cursorVisits.First(); k != nil; k, v = cursorVisits.Next() {
				var visit Visit
				if err := json.Unmarshal(v, &visit); err == nil {
					// NO USER FILTER HERE
					visitDateIST := visit.VisitDate.In(istLocation)
					if visitDateIST.After(startTime) && !visitDateIST.After(now) {
						if _, exists := activityMap[visit.ClientID]; !exists {
							clientDetails, _ := getClientDetails(tx, visit.ClientID) // Ignore error
							activityMap[visit.ClientID] = &ClientActivitySummary{
								ClientID:    clientDetails.ID,
								ClientName:  clientDetails.Name,
								ClientEmail: clientDetails.Email,
								ClientPhone: clientDetails.Phone,
							}
						}
						summary := activityMap[visit.ClientID]
						summary.HadVisit = true
						summary.VisitCount++
					}
				} else {
					log.Printf("WARN: Failed to unmarshal visit %s in admin summary data: %v", string(k), err)
				}
			}
		} else {
			log.Printf("WARN: Bucket %s not found for admin summary, skipping visit data.", bVisits)
		}

		// --- Process ALL Orders ---
		if ordersBucket != nil {
			cursorOrders := ordersBucket.Cursor()
			for k, v := cursorOrders.First(); k != nil; k, v = cursorOrders.Next() {
				var order Order
				if err := json.Unmarshal(v, &order); err == nil {
					// NO USER FILTER HERE
					orderDateIST := order.OrderDate.In(istLocation)
					if orderDateIST.After(startTime) && !orderDateIST.After(now) {
						if _, exists := activityMap[order.ClientID]; !exists {
							clientDetails, _ := getClientDetails(tx, order.ClientID) // Ignore error
							activityMap[order.ClientID] = &ClientActivitySummary{
								ClientID:    clientDetails.ID,
								ClientName:  clientDetails.Name,
								ClientEmail: clientDetails.Email,
								ClientPhone: clientDetails.Phone,
							}
						}
						summary := activityMap[order.ClientID]
						summary.HadOrder = true
						summary.OrderCount++
						summary.TotalOrderValue += order.Total
					}
				} else {
					log.Printf("WARN: Failed to unmarshal order %s in admin summary data: %v", string(k), err)
				}
			}
		} else {
			log.Printf("WARN: Bucket %s not found for admin summary, skipping order data.", bOrders)
		}

		// --- Process ALL New Clients ---
		if clientsBucket != nil {
			cursorClients := clientsBucket.Cursor()
			for k, v := cursorClients.First(); k != nil; k, v = cursorClients.Next() {
				var client Client
				if err := json.Unmarshal(v, &client); err == nil {
					// NO USER FILTER HERE
					createdAtIST := client.CreatedAt.In(istLocation)
					if createdAtIST.After(startTime) && !createdAtIST.After(now) {
						if _, exists := activityMap[client.ID]; !exists {
							activityMap[client.ID] = &ClientActivitySummary{
								ClientID:    client.ID,
								ClientName:  client.Name,
								ClientEmail: client.Email,
								ClientPhone: client.Phone,
							}
						}
						activityMap[client.ID].IsNew = true // Mark as new within this period
					}
				} else {
					log.Printf("WARN: Failed to unmarshal client %s in admin summary new client check: %v", string(k), err)
				}
			}
		} else {
			log.Printf("WARN: Bucket %s not found for admin summary, skipping new client check.", bClients)
		}
		return nil
	})

	if err != nil {
		log.Printf("ERROR: Failed generating admin summary report data: %v", err)
		report.DataGenerationError = err.Error()
	}

	// Convert map to slice and calculate grand total value
	summaries := make([]ClientActivitySummary, 0, len(activityMap))
	grandTotalValue := 0.0
	for _, summary := range activityMap {
		summaries = append(summaries, *summary)
		grandTotalValue += summary.TotalOrderValue
	}
	report.TotalReportOrderValue = grandTotalValue // Set grand total

	// Sort summaries (e.g., by client name or ID)
	sort.Slice(summaries, func(i, j int) bool {
		// Sort by highest value first, then by Client ID
		if summaries[i].TotalOrderValue != summaries[j].TotalOrderValue {
			return summaries[i].TotalOrderValue > summaries[j].TotalOrderValue
		}
		return summaries[i].ClientID < summaries[j].ClientID
	})

	report.ClientSummaries = summaries
	return report
}

func generateReportHTML(data ReportData) (string, error) {
	companyName := "NextView Technologies India Pvt. Ltd"
	logoURL := "https://www.nexttechgroup.com/wp-content/uploads/2019/04/next-view-logo.png"

	// Using the same template for both user and admin reports.
	// Consider creating a separate template for the admin summary if needed.
	tmpl := `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>{{.Period}} Client Activity Report</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: Arial, sans-serif; color: #333; margin: 0; padding: 20px; background-color: #f9f9f9;">
    <table width="100%" style="max-width: 800px; margin: 0 auto 20px auto; background-color: #ffffff; border-radius: 8px; padding: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
        <tr>
            <td style="display: flex; align-items: center; border-bottom: 1px solid #eee; padding-bottom: 15px;">
                <img src="` + logoURL + `" alt="Company Logo" style="height: 50px; margin-right: 20px;">
                <h2 style="margin: 0; color: #1a73e8;">` + companyName + `</h2>
            </td>
        </tr>
         <tr>
            <td style="padding-top: 15px;">
                <h3>{{.Period}} Client Activity Report</h3>
                <p style="color: #5f6368;"><strong>Period:</strong> {{.StartDate.Format "02 Jan 2006"}} - {{.EndDate.Format "02 Jan 2006"}}</p>
                {{if .DataGenerationError}}<p style="color: red;"><strong>Warning:</strong> Error during data generation: {{.DataGenerationError}}</p>{{end}}
            </td>
        </tr>
    </table>

    <table width="100%" cellpadding="0" cellspacing="0" style="max-width: 800px; margin: auto; border-collapse: separate; border-spacing: 0; font-size: 14px; background-color: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
        <thead>
            <tr style="background-color: #1a73e8; color: #ffffff; text-align: left;">
                <th style="padding: 12px 15px;">Client ID</th>
                <th style="padding: 12px 15px;">Name</th>
                <th style="padding: 12px 15px;">Email</th>
                <th style="padding: 12px 15px;">Phone</th>
                <th style="padding: 12px 15px;">New?</th>
                <th style="padding: 12px 15px;">Visits</th>
                <th style="padding: 12px 15px;">Orders</th>
                <th style="padding: 12px 15px; text-align: right;">₹ Value</th>
            </tr>
        </thead>
        <tbody>
            {{if not .ClientSummaries}}
            <tr>
                <td colspan="8" style="padding: 20px; text-align: center; color: #5f6368; border-top: 1px solid #eee;">No client activity recorded for this period.</td>
            </tr>
            {{else}}
                {{range .ClientSummaries}}
                <tr style="border-bottom: 1px solid #eee;">
                    <td style="padding: 12px 15px;">{{.ClientID}}</td>
                    <td style="padding: 12px 15px;">{{.ClientName}}</td>
                    <td style="padding: 12px 15px;">{{if .ClientEmail}}{{.ClientEmail}}{{else}}-{{end}}</td>
                    <td style="padding: 12px 15px;">{{if .ClientPhone}}{{.ClientPhone}}{{else}}-{{end}}</td>
                    <td style="padding: 12px 15px; text-align: center;">{{if .IsNew}}✔️{{else}}❌{{end}}</td>
                    <td style="padding: 12px 15px; text-align: center;">{{.VisitCount}}</td>
                    <td style="padding: 12px 15px; text-align: center;">{{.OrderCount}}</td>
                    <td style="padding: 12px 15px; text-align: right;">₹{{printf "%.2f" .TotalOrderValue}}</td>
                </tr>
                {{end}}
            {{end}}
        </tbody>
        {{if .ClientSummaries}}
        <tfoot>
            <tr style="background-color: #f5f5f5;">
                <td colspan="7" style="padding: 12px 15px; text-align: right; font-weight: bold;">Total Value:</td>
                <td style="padding: 12px 15px; text-align: right; font-weight: bold;">₹{{printf "%.2f" .TotalReportOrderValue}}</td>
            </tr>
        </tfoot>
        {{end}}
    </table>

    <table width="100%" style="max-width: 800px; margin: 40px auto 0;">
        <tr>
            <td style="font-size: 12px; color: #5f6368; text-align: center;">
                This is an auto-generated report. Please do not reply directly to this email.
                 <br>Powered By Kavach Team &copy; {{.EndDate.Year}}
            </td>
        </tr>
    </table>

</body>
</html>`

	t, err := template.New("report").Parse(tmpl)
	if err != nil {
		return "", fmt.Errorf("failed to parse report template: %w", err)
	}

	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute report template: %w", err)
	}

	return buf.String(), nil
}

// --- Middleware ---

func NewJWTMiddleware() fiber.Handler {
	return jwtware.New(jwtware.Config{
		SigningKey: jwtware.SigningKey{Key: []byte(JWTSecret)}, // 🚨 Use external secret
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			log.Printf("JWT Middleware Error: %v", err) // Log the actual error

			// --- Simplified Error Checking ---
			// Directly check for known error values using errors.Is
			// This avoids needing the specific jwt.ValidationError type which caused compile errors.

			if errors.Is(err, jwt.ErrTokenExpired) {
				log.Println("JWT Error Reason: Token Expired")
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized: Token expired"})
			}

			if errors.Is(err, jwt.ErrTokenNotValidYet) {
				log.Println("JWT Error Reason: Token Not Valid Yet")
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized: Token not yet valid"})
			}

			if errors.Is(err, jwt.ErrTokenMalformed) {
				log.Println("JWT Error Reason: Token Malformed")
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized: Malformed token"})
			}

			// Add other checks for exported error values from the jwt package if needed
			// e.g., errors.Is(err, jwt.ErrSignatureInvalid) if that's exported and relevant

			// --- Generic Fallback ---
			// If the error wasn't one of the specific known values above,
			// return a generic unauthorized error.
			log.Println("JWT Error Reason: Unspecified validation error or middleware issue")
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized: Invalid token"})
		},
	})
}

func authRequired(c *fiber.Ctx) error {
	// The JWT middleware already performs the check and sets c.Locals("user") or returns error
	// This middleware might be redundant if JWT middleware's ErrorHandler covers all cases.
	// If kept, ensure it handles cases where JWT middleware might allow passage but user data isn't right.
	if c.Locals("user") == nil {
		// This might indicate a configuration issue if JWT middleware didn't error out
		log.Println("WARN: authRequired middleware triggered but c.Locals('user') is nil")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized (middleware issue)"})
	}
	// You could add extra checks here if needed, e.g., check if user is active in DB
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
		log.Printf("WARN: isCurrentUserAdmin: c.Locals('user') is not *jwt.Token type: %T", userToken)
		return false
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		log.Printf("WARN: isCurrentUserAdmin: token.Claims is not jwt.MapClaims type: %T", token.Claims)
		return false
	}
	isAdmin, ok := claims["isAdmin"].(bool)
	if !ok {
		log.Printf("WARN: isCurrentUserAdmin: isAdmin claim missing or not a bool: %v", claims["isAdmin"])
		return false
	}
	return isAdmin
}

func getCurrentUserID(c *fiber.Ctx) (int, error) {
	userToken := c.Locals("user")
	if userToken == nil {
		return 0, errors.New("authorization token not found in context") // More specific error
	}
	token, ok := userToken.(*jwt.Token)
	if !ok {
		log.Printf("WARN: getCurrentUserID: c.Locals('user') is not *jwt.Token type: %T", userToken)
		return 0, errors.New("invalid token type in context")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		log.Printf("WARN: getCurrentUserID: token.Claims is not jwt.MapClaims type: %T", token.Claims)
		return 0, errors.New("invalid claims type in token")
	}
	// JWT standard uses float64 for numeric claims when unmarshaling into interface{}
	userIDFloat, ok := claims["userId"].(float64)
	if !ok {
		// Fallback check if it was somehow marshaled as int (less common)
		userIDInt, okInt := claims["userId"].(int)
		if !okInt {
			log.Printf("WARN: getCurrentUserID: userId claim missing or not a number: %v", claims["userId"])
			return 0, errors.New("userId claim missing or invalid type")
		}
		return userIDInt, nil
	}
	// Check for potential truncation if float has decimal part
	if userIDFloat != float64(int(userIDFloat)) {
		log.Printf("WARN: getCurrentUserID: userId claim has non-integer value: %f", userIDFloat)
		return 0, errors.New("userId claim has non-integer value")
	}
	return int(userIDFloat), nil
}

// --- API Handlers: Authentication and Basic ---

func healthzHandler(c *fiber.Ctx) error {
	// Add DB ping check?
	// err := db.View(func(tx *bolt.Tx) error { return nil }) // Simple check
	// if err != nil { ... return 503 ...}
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
		passwordsBucket := tx.Bucket([]byte(bUserPasswords)) // 🚨 Reading plain text password bucket
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
		// --- 🚨 Read Plain Text Password ---
		passwordBytes := passwordsBucket.Get(userIDBytes)
		if passwordBytes == nil {
			log.Printf("WARN: User '%s' (ID: %d) found but password entry missing in '%s' bucket!", user.Username, user.ID, bUserPasswords)
			return nil // Treat as mismatch if password record missing
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

	// --- 🚨🚨 INSECURE: Direct string comparison for password 🚨🚨 ---
	// Replace this with bcrypt.CompareHashAndPassword
	if storedPassword != credentials.Password {
		log.Printf("INFO: Password mismatch for user '%s'", credentials.Username)
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid credentials"})
	}
	// --- End Insecure Comparison ---

	// Password matches (plain text) - Proceed with token generation
	claims := &Claims{
		UserID:  user.ID,
		IsAdmin: user.IsAdmin,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(tokenExpiryDuration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now().Add(-1 * time.Minute)), // Allow for slight clock skew
			Subject:   strconv.Itoa(user.ID),
			Issuer:    "YourAppName",             // Optional: Add issuer claim
			Audience:  []string{"YourAppClient"}, // Optional: Add audience claim
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(JWTSecret)) // 🚨 Use external secret
	if err != nil {
		log.Printf("ERROR: Token generation failed for user '%s': %v", user.Username, err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to generate token"})
	}

	log.Printf("INFO: Login successful for user '%s' (ID: %d)", user.Username, user.ID)
	// Return user info (excluding password/hash) along with token
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
// func sendTestEmailHandler(c *fiber.Ctx) error {
// 	// Consider getting target email from request body? Or use admin default?
// 	targetEmail := AdminDefaultEmail
// 	log.Printf("INFO: Initiating test email send to %s", targetEmail)
// 	go func() {
// 		err := sendEmail([]string{targetEmail}, nil, "Test Email from CRM", "This is a test email sent via the API endpoint.")
// 		if err != nil {
// 			log.Printf("ERROR: Test email failed: %v", err)
// 		}
// 	}()
// 	return c.JSON(fiber.Map{"status": "test email dispatch initiated", "recipient": targetEmail})
// }

// --- Manual Report Triggers (Keep or remove? These trigger global reports) ---
// func sendReportHandler(c *fiber.Ctx) error {
// 	log.Println("INFO: Manual GLOBAL Client Activity Summary report generation triggered via API (Daily period).")
// 	// NOTE: This uses the ADMIN summary function now
// 	reportData := generateAdminSummaryReportData(db, reportDaily)
// 	reportData.Period = "Manual Daily Summary"

// 	html, err := generateReportHTML(reportData)
// 	if err != nil {
// 		log.Printf("ERROR: Failed to generate manual summary report HTML: %v", err)
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to generate report content"})
// 	}

// 	// Send only to admins? Or to a specific email from request?
// 	recipients, err := getReportRecipients(db) // Gets all users
// 	if err != nil {
// 		// ... error handling ...
// 	}
// 	adminEmails := []string{}
// 	for _, u := range recipients {
// 		if u.IsAdmin {
// 			adminEmails = append(adminEmails, u.Email)
// 		}
// 	}

// 	if len(adminEmails) == 0 {
// 		return c.JSON(fiber.Map{"status": "manual summary report generation attempted, but no admin recipients found"})
// 	}

// 	subject := fmt.Sprintf("%s (%s)", reportData.Period, reportData.EndDate.Format("Jan 2, 2006"))
// 	go sendEmail(adminEmails, nil, subject, html) // Send To admins, no CC

// 	return c.JSON(fiber.Map{"status": fmt.Sprintf("manual summary report dispatch initiated for %d admin recipients", len(adminEmails))})
// }

// --- API Handlers: Users ---

// POST /api/users (Admin Only)
func createUserHandler(c *fiber.Ctx) error {
	req := new(CreateUserRequest)
	if err := c.BodyParser(req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request body"})
	}
	// Basic validation
	if req.Username == "" || req.Password == "" || req.Email == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Username, email, and password are required"})
	}
	// 🚨🚨 WARNING: Add password complexity checks here! 🚨🚨
	// Validate email format
	if !strings.Contains(req.Email, "@") { // Simple check
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid email format"})
	}

	// --- 🚨🚨 Hashing Step (Replace Plain Text Storage) ---
	// hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	// if err != nil {
	//    log.Printf("ERROR: Failed to hash password for user '%s': %v", req.Username, err)
	// 	  return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to process password"})
	// }
	// --- End Hashing Step ---

	var newUser User
	creationErr := db.Update(func(tx *bolt.Tx) error {
		usersBucket := tx.Bucket([]byte(bUsers))
		usernamesBucket := tx.Bucket([]byte(bUsernames))
		passwordsBucket := tx.Bucket([]byte(bUserPasswords)) // 🚨 Target plain text bucket
		if usersBucket == nil || usernamesBucket == nil || passwordsBucket == nil {
			return fmt.Errorf("internal configuration error: missing user/password buckets")
		}
		// Check username uniqueness
		if usernamesBucket.Get([]byte(req.Username)) != nil {
			return fiber.NewError(fiber.StatusConflict, fmt.Sprintf("username '%s' already exists", req.Username))
		}
		// Check email uniqueness? Requires another index bucket (email -> userID)

		id, _ := usersBucket.NextSequence()
		newUserID := int(id)

		newUser = User{
			ID:        newUserID,
			Username:  req.Username,
			Email:     req.Email,
			IsAdmin:   req.IsAdmin, // Ensure only admins can set IsAdmin=true if needed
			CreatedAt: time.Now(),
			// PasswordHash: string(hashedPassword), // Store hash instead of plain text
		}
		// Store user data (excluding password)
		userData, err := json.Marshal(newUser)
		if err != nil {
			return fmt.Errorf("failed to marshal user data for '%s': %w", req.Username, err)
		}
		if err := usersBucket.Put(itob(newUser.ID), userData); err != nil {
			return fmt.Errorf("failed to save user data for '%s': %w", req.Username, err)
		}

		// Store username mapping
		if err := usernamesBucket.Put([]byte(newUser.Username), itob(newUser.ID)); err != nil {
			// Attempt rollback? Difficult with BoltDB... Log and potentially return error
			log.Printf("CRITICAL: Failed to save username mapping for user %d, but user data saved!", newUser.ID)
			return fmt.Errorf("failed to save username mapping for '%s'", newUser.Username)
		}

		// --- 🚨🚨 INSECURE: Storing plain text password 🚨🚨 ---
		if err := passwordsBucket.Put(itob(newUser.ID), []byte(req.Password)); err != nil {
			log.Printf("CRITICAL: Failed to save plain text password for user %d!", newUser.ID)
			// Consider rollback / cleanup if possible
			return fmt.Errorf("failed to save user password for '%s'", newUser.Username)
		}
		// --- End Insecure Storage ---

		// TODO: Index user in Bleve?
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

	log.Printf("INFO: Admin created user '%s' (ID: %d) - 🚨 WITH PLAIN TEXT PASSWORD 🚨", newUser.Username, newUser.ID)

	// Return user info without password/hash
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
	var users []fiber.Map // Return simplified user info (no password/hash)
	fetchErr := db.View(func(tx *bolt.Tx) error {
		usersBucket := tx.Bucket([]byte(bUsers))
		if usersBucket == nil {
			log.Println("WARN: Users bucket not found in getUsersHandler.")
			return nil // Return empty list if bucket missing
		}
		cursor := usersBucket.Cursor()
		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			var user User
			if err := json.Unmarshal(v, &user); err != nil {
				log.Printf("WARN: Failed to unmarshal user data for key %s in getUsersHandler: %v", string(k), err)
				continue // Skip corrupted user data
			}
			// Exclude password/hash
			users = append(users, fiber.Map{
				"id":        user.ID,
				"username":  user.Username,
				"email":     user.Email,
				"isAdmin":   user.IsAdmin,
				"createdAt": user.CreatedAt,
				// Add other safe fields like Name, IsActive if they exist
			})
		}
		return nil
	})
	if fetchErr != nil {
		// This should only happen for DB-level errors now, not missing bucket
		log.Printf("ERROR: Failed to fetch users: %v", fetchErr)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to retrieve users"})
	}
	return c.JSON(users)
}

// GET /api/users/:id (Admin or Self)
func getUserHandler(c *fiber.Ctx) error {
	targetUserID, err := strconv.Atoi(c.Params("id"))
	if err != nil || targetUserID <= 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid user ID parameter"})
	}

	currentUserID, err := getCurrentUserID(c)
	if err != nil {
		// Error already logged in getCurrentUserID if needed
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Could not identify current user"})
	}
	isAdmin := isCurrentUserAdmin(c)

	// Check permission
	if !isAdmin && currentUserID != targetUserID {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Forbidden: Cannot access other user's data"})
	}

	var user User
	fetchErr := db.View(func(tx *bolt.Tx) error {
		usersBucket := tx.Bucket([]byte(bUsers))
		if usersBucket == nil {
			// This is an internal error if the bucket is missing
			log.Println("ERROR: Users bucket not found in getUserHandler")
			return fmt.Errorf("internal configuration error")
		}
		userData := usersBucket.Get(itob(targetUserID))
		if userData == nil {
			return fiber.ErrNotFound // Use Fiber's standard error
		}
		if err := json.Unmarshal(userData, &user); err != nil {
			log.Printf("ERROR: Failed to parse user data for ID %d: %v", targetUserID, err)
			return fmt.Errorf("failed to parse user data")
		}
		return nil
	})

	if fetchErr != nil {
		if errors.Is(fetchErr, fiber.ErrNotFound) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
		}
		// Handle specific internal errors if needed
		log.Printf("ERROR: Failed to fetch user %d: %v", targetUserID, fetchErr)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to retrieve user"})
	}

	// Return safe fields (no password/hash)
	return c.JSON(fiber.Map{
		"id":        user.ID,
		"username":  user.Username,
		"email":     user.Email,
		"isAdmin":   user.IsAdmin,
		"createdAt": user.CreatedAt,
		// Add other safe fields
	})
}

// PUT /api/users/:id (Admin or Self)
func updateUserHandler(c *fiber.Ctx) error {
	targetUserID, err := strconv.Atoi(c.Params("id"))
	if err != nil || targetUserID <= 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid user ID parameter"})
	}
	currentUserID, err := getCurrentUserID(c)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Could not identify current user"})
	}
	isAdmin := isCurrentUserAdmin(c)

	// Permission check: Non-admins cannot update other users
	if !isAdmin && currentUserID != targetUserID {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Forbidden: Cannot update other user's data"})
	}

	// Define fields allowed for update
	// Use pointers to detect if field was provided in the JSON request
	type UpdateUserRequest struct {
		Email    *string `json:"email"`    // Can be updated by self or admin
		IsAdmin  *bool   `json:"isAdmin"`  // Can only be changed by admin
		Username *string `json:"username"` // Allow username change? Requires careful handling of uniqueness/mapping
		// Add other fields like Name, Phone, IsActive *bool `json:"isActive"`?
	}
	req := new(UpdateUserRequest)
	if err := c.BodyParser(req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request body"})
	}

	// Perform update in transaction
	var updatedUser User // To store the final updated user data
	updateErr := db.Update(func(tx *bolt.Tx) error {
		usersBucket := tx.Bucket([]byte(bUsers))
		usernamesBucket := tx.Bucket([]byte(bUsernames)) // Needed if username changes
		if usersBucket == nil || usernamesBucket == nil {
			return fmt.Errorf("internal configuration error: missing user buckets")
		}

		// Get existing user data
		userData := usersBucket.Get(itob(targetUserID))
		if userData == nil {
			return fiber.ErrNotFound
		}
		var existingUser User
		if err := json.Unmarshal(userData, &existingUser); err != nil {
			return fmt.Errorf("failed to parse existing user data for ID %d", targetUserID)
		}

		// Apply changes
		updatedUser = existingUser // Start with existing data

		// Update Email
		if req.Email != nil {
			// Validate email format?
			if !strings.Contains(*req.Email, "@") {
				return fiber.NewError(fiber.StatusBadRequest, "Invalid email format provided")
			}
			// Check email uniqueness if required (needs index)
			updatedUser.Email = *req.Email
		}

		// Update IsAdmin (only allowed by admin)
		if req.IsAdmin != nil {
			if !isAdmin {
				// Non-admin trying to change admin status (even for themselves)
				return fiber.NewError(fiber.StatusForbidden, "Forbidden: Cannot change admin status")
			}
			// Admin changing status
			if targetUserID == 1 && !*req.IsAdmin { // Example: Prevent removing admin from default user ID 1
				// Use a more robust check, maybe count active admins?
				return fiber.NewError(fiber.StatusBadRequest, "Cannot remove admin status from the primary admin user")
			}
			updatedUser.IsAdmin = *req.IsAdmin
		}

		// Update Username (if allowed) - Requires updating username mapping
		if req.Username != nil && *req.Username != existingUser.Username {
			if *req.Username == "" {
				return fiber.NewError(fiber.StatusBadRequest, "Username cannot be empty")
			}
			// Check if new username already exists
			if usernamesBucket.Get([]byte(*req.Username)) != nil {
				return fiber.NewError(fiber.StatusConflict, fmt.Sprintf("Username '%s' is already taken", *req.Username))
			}
			// Update mapping: delete old, put new
			if err := usernamesBucket.Delete([]byte(existingUser.Username)); err != nil {
				// Log error, but might proceed if non-critical? Or fail?
				log.Printf("WARN: Failed to delete old username mapping '%s' for user %d during update: %v", existingUser.Username, targetUserID, err)
				return fmt.Errorf("failed to update username mapping (delete step)")
			}
			if err := usernamesBucket.Put([]byte(*req.Username), itob(targetUserID)); err != nil {
				log.Printf("ERROR: Failed to put new username mapping '%s' for user %d during update: %v", *req.Username, targetUserID, err)
				// Attempt to restore old mapping? Difficult. Fail the transaction.
				return fmt.Errorf("failed to update username mapping (put step)")
			}
			updatedUser.Username = *req.Username // Update username in user struct
		}

		// Marshal final updated user data (excluding password)
		newUserData, err := json.Marshal(updatedUser)
		if err != nil {
			return fmt.Errorf("failed to prepare updated user data for ID %d: %w", targetUserID, err)
		}
		// Save updated user data
		if err := usersBucket.Put(itob(targetUserID), newUserData); err != nil {
			return fmt.Errorf("failed to save updated user data for ID %d: %w", targetUserID, err)
		}

		// TODO: Update Bleve index?
		return nil
	})

	// Handle transaction result
	if updateErr != nil {
		var fiberErr *fiber.Error
		if errors.As(updateErr, &fiberErr) {
			// Return specific HTTP errors (NotFound, Forbidden, Conflict, BadRequest)
			return c.Status(fiberErr.Code).JSON(fiber.Map{"error": fiberErr.Message})
		}
		// Log internal errors
		log.Printf("ERROR: Failed to update user %d: %v", targetUserID, updateErr)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update user"})
	}

	log.Printf("INFO: User %d updated successfully by user %d.", targetUserID, currentUserID)

	// Return updated safe fields
	return c.JSON(fiber.Map{
		"id":        updatedUser.ID,
		"username":  updatedUser.Username,
		"email":     updatedUser.Email,
		"isAdmin":   updatedUser.IsAdmin,
		"createdAt": updatedUser.CreatedAt,
		// Add other updated safe fields
	})
}

// DELETE /api/users/:id (Admin Only)
func deleteUserHandler(c *fiber.Ctx) error {
	targetUserID, err := strconv.Atoi(c.Params("id"))
	if err != nil || targetUserID <= 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid user ID parameter"})
	}

	// Prevent deleting primary admin (e.g., ID 1)
	if targetUserID == 1 { // Use a more robust check if ID 1 isn't guaranteed to be the admin
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Cannot delete the primary admin user"})
	}

	adminUserID, _ := getCurrentUserID(c) // For logging

	var deletedUsername string // To store username for logging/mapping deletion
	deleteErr := db.Update(func(tx *bolt.Tx) error {
		usersBucket := tx.Bucket([]byte(bUsers))
		usernamesBucket := tx.Bucket([]byte(bUsernames))
		passwordsBucket := tx.Bucket([]byte(bUserPasswords)) // 🚨 Plain text password bucket
		if usersBucket == nil || usernamesBucket == nil || passwordsBucket == nil {
			return fmt.Errorf("internal configuration error: missing user/password buckets")
		}

		// Get username before deleting user data (for mapping cleanup)
		userData := usersBucket.Get(itob(targetUserID))
		if userData == nil {
			return fiber.ErrNotFound // User doesn't exist
		}
		var user User
		if err := json.Unmarshal(userData, &user); err == nil {
			deletedUsername = user.Username
		} // Ignore error if unmarshal fails, proceed with delete if key exists

		// Delete user data from main bucket
		if err := usersBucket.Delete(itob(targetUserID)); err != nil {
			// This indicates a DB error, not just missing user
			return fmt.Errorf("failed to delete user data for ID %d: %w", targetUserID, err)
		}

		// Delete password record
		if err := passwordsBucket.Delete(itob(targetUserID)); err != nil {
			// Log error but don't necessarily fail the whole operation if password was already missing
			log.Printf("WARN: Failed to delete password record for user ID %d during user deletion (may have been missing): %v", targetUserID, err)
		}

		// Delete username mapping (if username was retrieved)
		if deletedUsername != "" {
			if err := usernamesBucket.Delete([]byte(deletedUsername)); err != nil {
				// Log error, but proceed with deletion of user record itself
				log.Printf("WARN: Failed to delete username mapping '%s' for user ID %d during user deletion: %v", deletedUsername, targetUserID, err)
			}
		}

		// TODO: Delete associated records? (Orders, Visits created by this user?) - Requires careful consideration!
		// This could involve iterating through orders/visits, checking CreatedBy, and deleting/reassigning. Very complex.
		// Consider marking user as inactive instead of deleting?

		// TODO: Delete from Bleve index
		return nil
	})

	if deleteErr != nil {
		if errors.Is(deleteErr, fiber.ErrNotFound) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
		}
		log.Printf("ERROR: Failed to delete user %d: %v", targetUserID, deleteErr)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to delete user"})
	}

	log.Printf("INFO: Admin (ID: %d) deleted user ID %d (Username: '%s')", adminUserID, targetUserID, deletedUsername)
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
	// Validation
	if req.OldPassword == "" || req.NewPassword == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Old password and new password are required"})
	}
	if req.OldPassword == req.NewPassword {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "New password cannot be the same as the old password"})
	}
	// 🚨🚨 WARNING: Add password complexity checks for req.NewPassword here! 🚨🚨

	updateErr := db.Update(func(tx *bolt.Tx) error {
		passwordsBucket := tx.Bucket([]byte(bUserPasswords)) // 🚨 Plain text bucket
		if passwordsBucket == nil {
			log.Printf("ERROR: Passwords bucket missing in changeMyPasswordHandler for user %d", currentUserID)
			return fmt.Errorf("internal configuration error: password storage missing")
		}
		userIDBytes := itob(currentUserID)

		// --- 🚨 Read and Compare Old Plain Text Password ---
		storedPasswordBytes := passwordsBucket.Get(userIDBytes)
		if storedPasswordBytes == nil {
			log.Printf("ERROR: Password record not found for currently logged-in user %d during password change", currentUserID)
			// This implies inconsistency, maybe user was deleted between login and now?
			return fiber.NewError(fiber.StatusInternalServerError, "Password record missing for current user")
		}
		// Replace with bcrypt.CompareHashAndPassword(storedPasswordBytes, []byte(req.OldPassword))
		if string(storedPasswordBytes) != req.OldPassword {
			return fiber.NewError(fiber.StatusUnauthorized, "Incorrect old password")
		}
		// --- End Old Password Check ---

		// --- 🚨 Hash and Store New Password ---
		// newHashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
		// if err != nil {
		//    log.Printf("ERROR: Failed to hash new password for user %d: %v", currentUserID, err)
		//    return fmt.Errorf("failed to process new password")
		// }
		// if err := passwordsBucket.Put(userIDBytes, newHashedPassword); err != nil { // Store hash
		//	  return fmt.Errorf("failed to save new password hash for user %d: %w", currentUserID, err)
		// }
		// --- End Hashing ---

		// --- 🚨🚨 INSECURE: Storing plain text password 🚨🚨 ---
		if err := passwordsBucket.Put(userIDBytes, []byte(req.NewPassword)); err != nil {
			return fmt.Errorf("failed to save new plain text password for user %d: %w", currentUserID, err)
		}
		// --- End Insecure Storage ---

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

	log.Printf("INFO: User %d changed their password successfully. 🚨 PASSWORD STORED IN PLAIN TEXT 🚨", currentUserID)
	return c.SendStatus(fiber.StatusNoContent)
}

// PUT /api/users/:id/password (Admin Only)
func changeUserPasswordHandler(c *fiber.Ctx) error {
	targetUserID, err := strconv.Atoi(c.Params("id"))
	if err != nil || targetUserID <= 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid user ID parameter"})
	}
	adminUserID, _ := getCurrentUserID(c) // For logging

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
		passwordsBucket := tx.Bucket([]byte(bUserPasswords)) // 🚨 Plain text bucket
		usersBucket := tx.Bucket([]byte(bUsers))             // Check if user exists
		if passwordsBucket == nil || usersBucket == nil {
			log.Println("ERROR: Missing user/password buckets in changeUserPasswordHandler")
			return fmt.Errorf("internal configuration error")
		}
		userIDBytes := itob(targetUserID)

		// Check if the target user actually exists
		if usersBucket.Get(userIDBytes) == nil {
			return fiber.ErrNotFound // Target user doesn't exist
		}

		// --- 🚨 Hash and Store New Password ---
		// newHashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
		// if err != nil {
		//    log.Printf("ERROR: Failed to hash new password for user %d by admin %d: %v", targetUserID, adminUserID, err)
		//    return fmt.Errorf("failed to process new password")
		// }
		// if err := passwordsBucket.Put(userIDBytes, newHashedPassword); err != nil { // Store hash
		//	  return fmt.Errorf("failed to save new password hash for user %d: %w", targetUserID, err)
		// }
		// --- End Hashing ---

		// --- 🚨🚨 INSECURE: Storing plain text password 🚨🚨 ---
		if err := passwordsBucket.Put(userIDBytes, []byte(req.NewPassword)); err != nil {
			return fmt.Errorf("failed to save new plain text password for user %d: %w", targetUserID, err)
		}
		// --- End Insecure Storage ---

		return nil
	})

	if updateErr != nil {
		if errors.Is(updateErr, fiber.ErrNotFound) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
		}
		log.Printf("ERROR: Admin (ID: %d) failed to change password for user %d: %v", adminUserID, targetUserID, updateErr)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to change user password"})
	}

	log.Printf("INFO: Admin (ID: %d) changed password for user %d. 🚨 PASSWORD STORED IN PLAIN TEXT 🚨", adminUserID, targetUserID)
	return c.SendStatus(fiber.StatusNoContent)
}

// --- API Handlers: Clients --- (Handlers remain largely the same)

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
			log.Println("ERROR: Clients bucket missing in createClientHandler")
			return fmt.Errorf("internal configuration error: clients bucket missing")
		}
		id, _ := clientsBucket.NextSequence()
		newClientID := int(id)
		now := time.Now()
		newClient = Client{
			ID:            newClientID,
			Name:          req.Name,
			ContactPerson: req.ContactPerson,
			Email:         req.Email, // Validate format?
			Phone:         req.Phone,
			Address:       req.Address,
			CreatedBy:     currentUserID,
			CreatedAt:     now,
			UpdatedAt:     now,
		}
		clientData, err := json.Marshal(newClient)
		if err != nil {
			return fmt.Errorf("failed to prepare client data for '%s': %w", req.Name, err)
		}
		if err := clientsBucket.Put(itob(newClient.ID), clientData); err != nil {
			return fmt.Errorf("failed to save new client '%s': %w", req.Name, err)
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
	// Add pagination? e.g., c.QueryInt("page", 1), c.QueryInt("limit", 20)

	var clients []Client
	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bClients))
		if b == nil {
			log.Println("INFO: Clients bucket not found, returning empty list.")
			return nil
		}
		cursor := b.Cursor()
		// Implement pagination logic here if added
		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			var client Client
			if err := json.Unmarshal(v, &client); err != nil {
				log.Printf("WARN: Failed to unmarshal client data for key %s: %v", string(k), err)
				continue
			}
			// Filter by search query if provided (case-insensitive search on name, contact, email?)
			match := true
			if searchQuery != "" {
				lq := strings.ToLower(searchQuery)
				match = strings.Contains(strings.ToLower(client.Name), lq) ||
					strings.Contains(strings.ToLower(client.ContactPerson), lq) ||
					strings.Contains(strings.ToLower(client.Email), lq)
			}

			if match {
				clients = append(clients, client)
			}
		}
		return nil
	})
	if err != nil {
		log.Printf("ERROR: Failed to get clients: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to retrieve clients"})
	}
	// Add pagination headers to response if implemented
	return c.JSON(clients)
}

// GET /api/clients/:id
func getClientHandler(c *fiber.Ctx) error {
	clientID, err := strconv.Atoi(c.Params("id"))
	if err != nil || clientID <= 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid client ID"})
	}
	var client Client
	err = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bClients))
		if b == nil {
			log.Println("ERROR: Clients bucket missing in getClientHandler")
			return fmt.Errorf("internal configuration error")
		}
		v := b.Get(itob(clientID))
		if v == nil {
			return fiber.ErrNotFound
		}
		if err := json.Unmarshal(v, &client); err != nil {
			log.Printf("ERROR: Failed to parse client data for ID %d: %v", clientID, err)
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
	if err != nil || clientID <= 0 {
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
			log.Println("ERROR: Clients bucket missing in updateClientHandler")
			return fmt.Errorf("internal configuration error")
		}
		clientData := clientsBucket.Get(itob(clientID))
		if clientData == nil {
			return fiber.ErrNotFound
		}
		var existingClient Client
		if err := json.Unmarshal(clientData, &existingClient); err != nil {
			return fmt.Errorf("failed to parse existing client data for ID %d", clientID)
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
			Email:         req.Email, // Validate?
			Phone:         req.Phone,
			Address:       req.Address,
			CreatedBy:     existingClient.CreatedBy, // Keep original creator
			CreatedAt:     existingClient.CreatedAt, // Keep original creation time
			UpdatedAt:     time.Now(),               // Set update time
		}

		newClientData, err := json.Marshal(updatedClient)
		if err != nil {
			return fmt.Errorf("failed to prepare updated client data for ID %d: %w", clientID, err)
		}
		if err := clientsBucket.Put(itob(clientID), newClientData); err != nil {
			return fmt.Errorf("failed to save updated client data for ID %d: %w", clientID, err)
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
	if err != nil || clientID <= 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid client ID"})
	}
	adminUserID, _ := getCurrentUserID(c) // For logging

	deleteErr := db.Update(func(tx *bolt.Tx) error {
		clientsBucket := tx.Bucket([]byte(bClients))
		if clientsBucket == nil {
			log.Println("ERROR: Clients bucket missing in deleteClientHandler")
			return fmt.Errorf("internal configuration error")
		}
		// Check if client exists before deleting
		clientData := clientsBucket.Get(itob(clientID))
		if clientData == nil {
			return fiber.ErrNotFound
		}

		// Consider implications: What happens to Orders/Visits linked to this client?
		// Option 1: Delete them too (cascading delete - complex, potentially dangerous)
		// Option 2: Orphan them (leave them pointing to a non-existent client ID)
		// Option 3: Prevent deletion if linked records exist
		// Current implementation: Orphan records (Option 2)

		if err := clientsBucket.Delete(itob(clientID)); err != nil {
			return fmt.Errorf("failed to delete client data for ID %d: %w", clientID, err)
		}
		// TODO: Delete from Bleve index
		return nil
	})

	if deleteErr != nil {
		if errors.Is(deleteErr, fiber.ErrNotFound) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Client not found"})
		}
		log.Printf("ERROR: Failed to delete client %d by admin %d: %v", clientID, adminUserID, deleteErr)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to delete client"})
	}

	log.Printf("INFO: Client %d deleted by admin %d", clientID, adminUserID)
	return c.SendStatus(fiber.StatusNoContent)
}

// --- API Handlers: Products --- (Handlers remain largely the same)

// POST /api/products (Admin Only)
func createProductHandler(c *fiber.Ctx) error {
	req := new(Product)
	if err := c.BodyParser(req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request body"})
	}
	if req.Name == "" || req.Price <= 0 || req.SKU == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Product name, positive price, and SKU are required"})
	}
	adminUserID, _ := getCurrentUserID(c) // For logging

	var newProduct Product
	creationErr := db.Update(func(tx *bolt.Tx) error {
		productsBucket := tx.Bucket([]byte(bProducts))
		if productsBucket == nil {
			log.Println("ERROR: Products bucket missing in createProductHandler")
			return fmt.Errorf("internal configuration error")
		}
		// TODO: Check SKU uniqueness more robustly if needed (requires an index bucket SKU -> productID)

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
			return fmt.Errorf("failed to prepare product data for '%s': %w", req.Name, err)
		}
		if err := productsBucket.Put(itob(newProduct.ID), productData); err != nil {
			return fmt.Errorf("failed to save new product '%s': %w", req.Name, err)
		}
		// TODO: Index product in Bleve
		return nil
	})
	if creationErr != nil {
		log.Printf("ERROR: Failed to commit product creation transaction for '%s' by admin %d: %v", req.Name, adminUserID, creationErr)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create product"})
	}
	log.Printf("INFO: Admin %d created product '%s' (ID: %d)", adminUserID, newProduct.Name, newProduct.ID)
	return c.Status(fiber.StatusCreated).JSON(newProduct)
}

// GET /api/products
func getProductsHandler(c *fiber.Ctx) error {
	// Add search/filter/pagination?
	var products []Product
	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bProducts))
		if b == nil {
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
		log.Printf("ERROR: Failed to get products: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to retrieve products"})
	}
	return c.JSON(products)
}

// GET /api/products/:id
func getProductHandler(c *fiber.Ctx) error {
	productID, err := strconv.Atoi(c.Params("id"))
	if err != nil || productID <= 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid product ID"})
	}
	var product Product
	err = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bProducts))
		if b == nil {
			log.Println("ERROR: Products bucket missing in getProductHandler")
			return fmt.Errorf("internal configuration error")
		}
		v := b.Get(itob(productID))
		if v == nil {
			return fiber.ErrNotFound
		}
		if err := json.Unmarshal(v, &product); err != nil {
			log.Printf("ERROR: Failed to parse product data for ID %d: %v", productID, err)
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
	if err != nil || productID <= 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid product ID"})
	}
	adminUserID, _ := getCurrentUserID(c) // For logging

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
			log.Println("ERROR: Products bucket missing in updateProductHandler")
			return fmt.Errorf("internal configuration error")
		}
		productData := productsBucket.Get(itob(productID))
		if productData == nil {
			return fiber.ErrNotFound
		}
		var existingProduct Product
		if err := json.Unmarshal(productData, &existingProduct); err != nil {
			return fmt.Errorf("failed to parse existing product data for ID %d", productID)
		}

		// TODO: Check if SKU is being changed and ensure new SKU is unique if required

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
			return fmt.Errorf("failed to prepare updated product data for ID %d: %w", productID, err)
		}
		if err := productsBucket.Put(itob(productID), newProductData); err != nil {
			return fmt.Errorf("failed to save updated product data for ID %d: %w", productID, err)
		}
		// TODO: Update Bleve index
		return nil
	})

	if updateErr != nil {
		if errors.Is(updateErr, fiber.ErrNotFound) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Product not found"})
		}
		// Handle SKU conflict error if implemented
		log.Printf("ERROR: Failed to update product %d by admin %d: %v", productID, adminUserID, updateErr)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update product"})
	}
	log.Printf("INFO: Product %d updated by admin %d", productID, adminUserID)
	return c.JSON(updatedProduct)
}

// DELETE /api/products/:id (Admin Only)
func deleteProductHandler(c *fiber.Ctx) error {
	productID, err := strconv.Atoi(c.Params("id"))
	if err != nil || productID <= 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid product ID"})
	}
	adminUserID, _ := getCurrentUserID(c) // For logging

	deleteErr := db.Update(func(tx *bolt.Tx) error {
		productsBucket := tx.Bucket([]byte(bProducts))
		if productsBucket == nil {
			log.Println("ERROR: Products bucket missing in deleteProductHandler")
			return fmt.Errorf("internal configuration error")
		}
		if productsBucket.Get(itob(productID)) == nil {
			return fiber.ErrNotFound // Product doesn't exist
		}

		// TODO: Check if product is in any Orders? Prevent deletion or handle?
		// Current: Allows deletion, potentially leaving orders with invalid ProductID

		if err := productsBucket.Delete(itob(productID)); err != nil {
			return fmt.Errorf("failed to delete product data for ID %d: %w", productID, err)
		}
		// TODO: Delete from Bleve index
		// TODO: Delete SKU mapping if index exists
		return nil
	})

	if deleteErr != nil {
		if errors.Is(deleteErr, fiber.ErrNotFound) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Product not found"})
		}
		log.Printf("ERROR: Failed to delete product %d by admin %d: %v", productID, adminUserID, deleteErr)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to delete product"})
	}

	log.Printf("INFO: Product %d deleted by admin %d", productID, adminUserID)
	return c.SendStatus(fiber.StatusNoContent)
}

// --- API Handlers: Orders ---

// POST /api/orders
func createOrderHandler(c *fiber.Ctx) error {
	req := new(CreateOrderRequest)
	if err := c.BodyParser(req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request body"})
	}
	// Validation
	if req.ClientID <= 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Valid Client ID is required"})
	}
	if len(req.Items) == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "At least one order item is required"})
	}
	for i, item := range req.Items {
		if item.ProductID <= 0 {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": fmt.Sprintf("Item %d: Valid Product ID is required", i+1)})
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
			log.Println("ERROR: Missing buckets in createOrderHandler (orders, clients, or products)")
			return fmt.Errorf("internal configuration error: missing required buckets")
		}
		// Verify client exists
		if clientsBucket.Get(itob(req.ClientID)) == nil {
			return fiber.NewError(fiber.StatusNotFound, fmt.Sprintf("client with ID %d not found", req.ClientID))
		}

		orderItems := make([]OrderItem, 0, len(req.Items))
		total := 0.0
		now := time.Now() // Use UTC for consistency? Or IST? Using local server time for now.

		// Validate products and calculate total
		for i, reqItem := range req.Items {
			productData := productsBucket.Get(itob(reqItem.ProductID))
			if productData == nil {
				return fiber.NewError(fiber.StatusBadRequest, fmt.Sprintf("item %d: product with ID %d not found", i+1, reqItem.ProductID))
			}
			var product Product
			if err := json.Unmarshal(productData, &product); err != nil {
				log.Printf("ERROR: Failed to validate product %d during order creation: %v", reqItem.ProductID, err)
				return fmt.Errorf("failed to validate product %d", reqItem.ProductID)
			}
			// Use current product price for PriceAtOrder
			item := OrderItem{
				ProductID:    reqItem.ProductID,
				Quantity:     reqItem.Quantity,
				PriceAtOrder: product.Price,
			}
			orderItems = append(orderItems, item)
			total += float64(item.Quantity) * item.PriceAtOrder
		}

		id, _ := ordersBucket.NextSequence()
		newOrderID := int(id)
		newOrder = Order{
			ID:        newOrderID,
			ClientID:  req.ClientID,
			OrderDate: time.Now().In(istLocation), // Record order date in IST
			Status:    "pending",                  // Default status
			Total:     total,
			CreatedBy: currentUserID,
			CreatedAt: now, // Record creation timestamp (local server time or UTC recommended)
			UpdatedAt: now,
			Items:     orderItems,
		}
		orderData, err := json.Marshal(newOrder)
		if err != nil {
			return fmt.Errorf("failed to prepare order data for client %d: %w", req.ClientID, err)
		}
		if err := ordersBucket.Put(itob(newOrder.ID), orderData); err != nil {
			return fmt.Errorf("failed to save new order for client %d: %w", req.ClientID, err)
		}
		// TODO: Index order in Bleve
		return nil
	})

	if creationErr != nil {
		var fiberErr *fiber.Error
		if errors.As(creationErr, &fiberErr) {
			return c.Status(fiberErr.Code).JSON(fiber.Map{"error": fiberErr.Message})
		}
		log.Printf("ERROR: Failed to commit order creation transaction for client %d by user %d: %v", req.ClientID, currentUserID, creationErr)
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

	// Add filters? By clientID, status, date range?
	// Add pagination?

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

			// Apply Filters (Example: by clientID if provided)
			// clientFilter, _ := strconv.Atoi(c.Query("clientId"))
			// if clientFilter > 0 && order.ClientID != clientFilter {
			//     continue
			// }
			// statusFilter := c.Query("status")
			// if statusFilter != "" && order.Status != statusFilter {
			//     continue
			// }

			// Permission Filter: Admins see all, users see only their own
			if isAdmin || order.CreatedBy == currentUserID {
				// Add client/product names for convenience in response? Requires lookup.
				orders = append(orders, order)
			}
		}
		// Sort orders? Default: by ID (BoltDB iteration order). Sort by date?
		// sort.Slice(orders, func(i, j int) bool { return orders[i].OrderDate.After(orders[j].OrderDate) }) // Newest first
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
	if err != nil || orderID <= 0 {
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
			log.Println("ERROR: Orders bucket missing in getOrderHandler")
			return fmt.Errorf("internal configuration error")
		}
		v := b.Get(itob(orderID))
		if v == nil {
			return fiber.ErrNotFound
		}
		if err := json.Unmarshal(v, &order); err != nil {
			log.Printf("ERROR: Failed to parse order data for ID %d: %v", orderID, err)
			return fmt.Errorf("failed to parse order data")
		}
		// Permission Check
		if !isAdmin && order.CreatedBy != currentUserID {
			return fiber.ErrForbidden // Use Fiber's error
		}
		// Enhance order data? Add Client Name? Product Names in Items? Requires more lookups.
		// client, _ := getClientDetails(tx, order.ClientID) // Example lookup
		// order.ClientName = client.Name // Add temporary field to response struct if needed
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
	return c.JSON(order) // Return enhanced struct if data was added
}

// PUT /api/orders/:id
func updateOrderHandler(c *fiber.Ctx) error {
	orderID, err := strconv.Atoi(c.Params("id"))
	if err != nil || orderID <= 0 {
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
	// Validate status value if provided
	allowedStatuses := map[string]bool{"pending": true, "processing": true, "completed": true, "cancelled": true}
	if req.Status != "" && !allowedStatuses[strings.ToLower(req.Status)] { // Case-insensitive check
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid order status value"})
	}

	var updatedOrder Order
	updateErr := db.Update(func(tx *bolt.Tx) error {
		ordersBucket := tx.Bucket([]byte(bOrders))
		if ordersBucket == nil {
			log.Println("ERROR: Orders bucket missing in updateOrderHandler")
			return fmt.Errorf("internal configuration error")
		}
		orderData := ordersBucket.Get(itob(orderID))
		if orderData == nil {
			return fiber.ErrNotFound
		}
		var existingOrder Order
		if err := json.Unmarshal(orderData, &existingOrder); err != nil {
			return fmt.Errorf("failed to parse existing order data for ID %d", orderID)
		}

		// Permission Check: Allow update only if admin or the original creator
		if !isAdmin && existingOrder.CreatedBy != currentUserID {
			return fiber.NewError(fiber.StatusForbidden, "Forbidden: Cannot update order created by another user")
		}

		// Apply updates (currently only status)
		// Should other fields be updatable? Items? ClientID? Requires more complex logic.
		updatedOrder = existingOrder // Copy existing order
		if req.Status != "" {
			updatedOrder.Status = strings.ToLower(req.Status) // Store lowercase status
		}
		updatedOrder.UpdatedAt = time.Now() // Update timestamp

		newOrderData, err := json.Marshal(updatedOrder)
		if err != nil {
			return fmt.Errorf("failed to prepare updated order data for ID %d: %w", orderID, err)
		}
		if err := ordersBucket.Put(itob(orderID), newOrderData); err != nil {
			return fmt.Errorf("failed to save updated order data for ID %d: %w", orderID, err)
		}
		// TODO: Update Bleve index if status changed or other indexed fields
		return nil
	})

	if updateErr != nil {
		var fiberErr *fiber.Error
		if errors.As(updateErr, &fiberErr) {
			return c.Status(fiberErr.Code).JSON(fiber.Map{"error": fiberErr.Message})
		}
		log.Printf("ERROR: Failed to update order %d by user %d: %v", orderID, currentUserID, updateErr)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update order"})
	}
	log.Printf("INFO: Order %d updated by user %d", orderID, currentUserID)
	return c.JSON(updatedOrder)
}

// DELETE /api/orders/:id (Admin Only)
func deleteOrderHandler(c *fiber.Ctx) error {
	orderID, err := strconv.Atoi(c.Params("id"))
	if err != nil || orderID <= 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid order ID"})
	}
	adminUserID, _ := getCurrentUserID(c) // For logging

	deleteErr := db.Update(func(tx *bolt.Tx) error {
		ordersBucket := tx.Bucket([]byte(bOrders))
		if ordersBucket == nil {
			log.Println("ERROR: Orders bucket missing in deleteOrderHandler")
			return fmt.Errorf("internal configuration error")
		}
		if ordersBucket.Get(itob(orderID)) == nil {
			return fiber.ErrNotFound // Order doesn't exist
		}

		// Consider implications: Does deleting an order affect stock levels? Trigger refunds?
		// Current implementation: Simple deletion.

		if err := ordersBucket.Delete(itob(orderID)); err != nil {
			return fmt.Errorf("failed to delete order data for ID %d: %w", orderID, err)
		}
		// TODO: Delete from Bleve index
		return nil
	})

	if deleteErr != nil {
		if errors.Is(deleteErr, fiber.ErrNotFound) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Order not found"})
		}
		log.Printf("ERROR: Failed to delete order %d by admin %d: %v", orderID, adminUserID, deleteErr)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to delete order"})
	}

	log.Printf("INFO: Order %d deleted by admin %d", orderID, adminUserID)
	return c.SendStatus(fiber.StatusNoContent)
}

// --- API Handlers: Visits ---

// POST /api/visits
func createVisitHandler(c *fiber.Ctx) error {
	req := new(Visit) // Use Visit struct directly for request body
	if err := c.BodyParser(req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request body"})
	}
	// Validation
	if req.ClientID <= 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Valid Client ID is required"})
	}
	// Notes can be optional or required based on needs
	if strings.TrimSpace(req.Notes) == "" {
		// return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Visit notes cannot be empty"})
	}

	currentUserID, err := getCurrentUserID(c)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Could not identify current user"})
	}

	var newVisit Visit
	creationErr := db.Update(func(tx *bolt.Tx) error {
		visitsBucket := tx.Bucket([]byte(bVisits))
		clientsBucket := tx.Bucket([]byte(bClients))
		if visitsBucket == nil || clientsBucket == nil {
			log.Println("ERROR: Missing buckets in createVisitHandler (visits or clients)")
			return fmt.Errorf("internal configuration error: missing required buckets")
		}

		// Verify the client exists
		if clientsBucket.Get(itob(req.ClientID)) == nil {
			return fiber.NewError(fiber.StatusNotFound, fmt.Sprintf("client with ID %d not found", req.ClientID))
		}

		id, _ := visitsBucket.NextSequence()
		newVisitID := int(id)
		now := time.Now()
		nowIST := now.In(istLocation) // Fetch current time in IST

		newVisit = Visit{
			ID:        newVisitID,
			ClientID:  req.ClientID,
			UserID:    currentUserID, // Logged in user made the visit
			VisitDate: nowIST,        // Set VisitDate to current IST when record is created
			Notes:     req.Notes,
			CreatedAt: now, // Keep CreatedAt for record creation timestamp (local server time or UTC recommended)
		}

		visitData, err := json.Marshal(newVisit)
		if err != nil {
			return fmt.Errorf("failed to prepare visit data for client %d: %w", req.ClientID, err)
		}
		if err := visitsBucket.Put(itob(newVisit.ID), visitData); err != nil {
			return fmt.Errorf("failed to save new visit for client %d: %w", req.ClientID, err)
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

	// Add filters? ClientID, UserID (for admins), Date range?
	// Add pagination?

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

			// Apply Filters (Example: clientID)
			// clientFilter, _ := strconv.Atoi(c.Query("clientId"))
			// if clientFilter > 0 && visit.ClientID != clientFilter {
			//     continue
			// }
			// Example: UserID filter for admins
			// userFilter, _ := strconv.Atoi(c.Query("userId"))
			// if isAdmin && userFilter > 0 && visit.UserID != userFilter {
			//     continue
			// }

			// Permission Filter: Admins see all, users see only their own
			if isAdmin || visit.UserID == currentUserID {
				// Add client/user names? Requires lookup.
				visits = append(visits, visit)
			}
		}
		// Sort visits? Default: ID order. Sort by date?
		// sort.Slice(visits, func(i, j int) bool { return visits[i].VisitDate.After(visits[j].VisitDate) }) // Newest first
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
	if err != nil || visitID <= 0 {
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
	// Add validation for notes if needed (e.g., max length, cannot be empty?)
	if strings.TrimSpace(req.Notes) == "" {
		// return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Visit notes cannot be empty"})
	}

	var updatedVisit Visit
	updateErr := db.Update(func(tx *bolt.Tx) error {
		visitsBucket := tx.Bucket([]byte(bVisits))
		if visitsBucket == nil {
			log.Println("ERROR: Visits bucket missing in updateVisitHandler")
			return fmt.Errorf("internal configuration error")
		}
		visitData := visitsBucket.Get(itob(visitID))
		if visitData == nil {
			return fiber.ErrNotFound
		}
		var existingVisit Visit
		if err := json.Unmarshal(visitData, &existingVisit); err != nil {
			return fmt.Errorf("failed to parse existing visit data for ID %d", visitID)
		}

		// Permission Check: Allow update only if admin or the original creator
		if !isAdmin && existingVisit.UserID != currentUserID {
			return fiber.NewError(fiber.StatusForbidden, "Forbidden: Cannot update visit logged by another user")
		}

		// Apply updates (currently only notes)
		updatedVisit = existingVisit // Copy existing visit
		updatedVisit.Notes = req.Notes
		// Note: Should VisitDate be updatable? Probably not automatically. Add if required.
		// Add UpdatedAt field? updatedVisit.UpdatedAt = time.Now()

		newVisitData, err := json.Marshal(updatedVisit)
		if err != nil {
			return fmt.Errorf("failed to prepare updated visit data for ID %d: %w", visitID, err)
		}
		if err := visitsBucket.Put(itob(visitID), newVisitData); err != nil {
			return fmt.Errorf("failed to save updated visit data for ID %d: %w", visitID, err)
		}
		// TODO: Update Bleve index if notes changed
		return nil
	})

	if updateErr != nil {
		var fiberErr *fiber.Error
		if errors.As(updateErr, &fiberErr) {
			return c.Status(fiberErr.Code).JSON(fiber.Map{"error": fiberErr.Message})
		}
		log.Printf("ERROR: Failed to update visit %d by user %d: %v", visitID, currentUserID, updateErr)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update visit"})
	}
	log.Printf("INFO: Visit %d updated by user %d", visitID, currentUserID)
	return c.JSON(updatedVisit)
}

// DELETE /api/visits/:id (Admin Only)
func deleteVisitHandler(c *fiber.Ctx) error {
	visitID, err := strconv.Atoi(c.Params("id"))
	if err != nil || visitID <= 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid visit ID"})
	}
	adminUserID, _ := getCurrentUserID(c) // For logging

	deleteErr := db.Update(func(tx *bolt.Tx) error {
		visitsBucket := tx.Bucket([]byte(bVisits))
		if visitsBucket == nil {
			log.Println("ERROR: Visits bucket missing in deleteVisitHandler")
			return fmt.Errorf("internal configuration error")
		}
		if visitsBucket.Get(itob(visitID)) == nil {
			return fiber.ErrNotFound // Visit doesn't exist
		}
		if err := visitsBucket.Delete(itob(visitID)); err != nil {
			return fmt.Errorf("failed to delete visit data for ID %d: %w", visitID, err)
		}
		// TODO: Delete from Bleve index
		return nil
	})

	if deleteErr != nil {
		if errors.Is(deleteErr, fiber.ErrNotFound) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Visit not found"})
		}
		log.Printf("ERROR: Failed to delete visit %d by admin %d: %v", visitID, adminUserID, deleteErr)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to delete visit"})
	}

	log.Printf("INFO: Visit %d deleted by admin %d", visitID, adminUserID)
	return c.SendStatus(fiber.StatusNoContent)
}

// --- API Handlers: Search ---

// GET /api/search
func searchHandler(c *fiber.Ctx) error {
	query := c.Query("q")
	if query == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Search query parameter 'q' is required"})
	}

	log.Printf("INFO: Performing search for query: %s", query)

	// TODO: Implement Bleve Search
	// 1. Create a Bleve query (e.g., NewMatchQuery, NewBooleanQuery)
	// 2. Define search request (size, fields, facets, highlighting)
	// 3. Perform search: idx.Search(searchRequest)
	// 4. Process results: searchResult.Hits
	// 5. Map results to appropriate response format (e.g., list of clients, products found)

	// Placeholder response
	searchRequest := bleve.NewSearchRequest(bleve.NewMatchQuery(query))
	searchRequest.Highlight = bleve.NewHighlight() // Enable highlighting
	searchRequest.Size = 10                        // Limit results

	searchResults, err := idx.Search(searchRequest)
	if err != nil {
		log.Printf("ERROR: Bleve search failed for query '%s': %v", query, err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Search failed"})
	}

	log.Printf("INFO: Search query '%s' returned %d hits in %s", query, searchResults.Total, searchResults.Took)

	// Need to map Bleve doc IDs back to actual data from BoltDB or include data in index
	// This part is complex and depends on how you index data.
	// For now, just returning the Bleve result structure.
	return c.JSON(searchResults)

	// return c.Status(fiber.StatusNotImplemented).JSON(fiber.Map{"message": "Search handler not fully implemented yet", "query": query})
}

// --- NEW: Master API Handler ---
// PUT /api/master/:bucket/:key (Admin Only)
func masterUpdateHandler(c *fiber.Ctx) error {
	bucketName := c.Params("bucket")
	key := c.Params("key")
	rawData := c.BodyRaw() // Get raw body bytes

	if bucketName == "" || key == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Bucket name and key are required in URL path"})
	}
	if len(rawData) == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Request body cannot be empty"})
	}

	// Basic JSON validation before writing? Or allow any raw data?
	// Allowing any raw data for now - EXTREME CAUTION
	// if !json.Valid(rawData) {
	// 	return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Request body must be valid JSON (if enforcing)"})
	// }

	// Prevent modification of critical buckets?
	protectedBuckets := map[string]bool{
		bUsers: true, bUsernames: true, bUserPasswords: true, // Protect user/auth data
	}
	if protectedBuckets[bucketName] {
		log.Printf("WARN: Master API blocked attempt to modify protected bucket: %s", bucketName)
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": fmt.Sprintf("Modification of bucket '%s' via master API is forbidden", bucketName)})
	}

	// 🚨 DANGER ZONE: Allows overwriting anything in non-protected buckets!
	log.Printf("WARN: Master API attempting update: Bucket=%s, Key=%s", bucketName, key)
	updateErr := db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketName))
		if bucket == nil {
			// Optionally create the bucket if it doesn't exist? Risky.
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
	log.Println("INFO: Starting background reporting jobs (User Specific + Admin Summary)...")

	// --- Configuration for Reporting ---
	// Retrieve Admin CC email (Ideally from config/env)
	adminCCEmail := ReportAdminCCEmail // Using constant - 🚨 MOVE TO CONFIG
	adminCCList := []string{}
	if adminCCEmail != "" {
		adminCCList = append(adminCCList, strings.TrimSpace(adminCCEmail))
		log.Printf("INFO: User reports will be CC'd to: %s", adminCCEmail)
	} else {
		log.Println("WARN: No Admin CC email configured for user reports.")
	}

	// Define report trigger times (Consider making these configurable via Env/Config)
	// Example: Run checks every minute
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for now := range ticker.C {
		nowIST := now.In(istLocation)
		wd, h, m := nowIST.Weekday(), nowIST.Hour(), nowIST.Minute()

		var reportDuration time.Duration
		var reportPeriodName string // e.g., "Daily", "Weekly"
		var shouldSend bool = false

		// --- Determine if it's time for Daily or Weekly reports ---
		isDailyTime := wd >= time.Monday && wd <= time.Friday && h == 19 && m == 30 // 7:30 PM Mon-Fri IST
		isWeeklyTime := wd == time.Saturday && h == 20 && m == 00                   // 8:00 PM Sat IST

		if isDailyTime {
			reportDuration = reportDaily
			reportPeriodName = "Daily"
			shouldSend = true
		} else if isWeeklyTime {
			reportDuration = reportWeekly
			reportPeriodName = "Weekly"
			shouldSend = true
		}

		// If not report time, continue to next tick
		if !shouldSend {
			continue
		}

		log.Printf("INFO: === Triggering %s Reports (%s) ===", reportPeriodName, nowIST.Format(time.RFC1123))

		// --- Get All Potential Recipients (including admins) ---
		allUsers, err := getReportRecipients(db)
		if err != nil {
			log.Printf("ERROR: Failed to get recipients for %s reports: %v", reportPeriodName, err)
			continue // Skip this cycle if we can't get recipients
		}
		if len(allUsers) == 0 {
			log.Printf("WARN: No users found with email addresses for %s reporting cycle.", reportPeriodName)
			continue // Skip if no one to send to
		}

		// Separate admins and regular users
		adminRecipients := []User{}
		regularUserRecipients := []User{}
		for _, u := range allUsers {
			if u.IsAdmin {
				adminRecipients = append(adminRecipients, u)
			}
			// Send individual reports to non-admins OR admins based on config?
			// Assuming here we send individual reports to ALL users (admins included)
			// AND a separate summary just to admins. Adjust logic if needed.
			if u.Email != "" { // Ensure email exists
				regularUserRecipients = append(regularUserRecipients, u)
			}
		}

		// --- 1. Send Individual Reports to Each User (with Admin CC) ---
		log.Printf("INFO: Processing individual %s reports for %d users...", reportPeriodName, len(regularUserRecipients))
		for _, user := range regularUserRecipients {
			// Use a local variable for the loop to avoid closure issues with goroutine
			currentUser := user

			// Launch goroutine for each user report generation and sending
			go func() {
				log.Printf("INFO: Generating %s report for user %d (%s)...", reportPeriodName, currentUser.ID, currentUser.Username)

				// Generate data specific to this user
				userReportData := generateUserReportData(db, currentUser.ID, reportDuration)
				userReportData.Period = reportPeriodName // Ensure period name is set

				// Optional: Skip sending if no activity found for the user
				if len(userReportData.ClientSummaries) == 0 && userReportData.DataGenerationError == "" {
					log.Printf("INFO: Skipping %s report for user %d (%s) - no activity found.", reportPeriodName, currentUser.ID, currentUser.Username)
					return // Exit this goroutine
				}

				html, err := generateReportHTML(userReportData)
				if err != nil {
					log.Printf("ERROR: Failed to generate %s report HTML for user %d (%s): %v", reportPeriodName, currentUser.ID, currentUser.Username, err)
					return // Exit this goroutine
				}

				// Create personalized subject
				subject := fmt.Sprintf("%s Report for %s (%s)",
					reportPeriodName,
					currentUser.Username,
					userReportData.EndDate.Format("Jan 2, 2006"),
				)

				// Send email individually: user in To, admin list in CC
				err = sendEmail([]string{currentUser.Email}, adminCCList, subject, html)
				if err != nil {
					// Log error from sendEmail (it already logs details internally)
					log.Printf("ERROR: Failed sending individual report email to %s (User: %d, Subject: %s)", currentUser.Email, currentUser.ID, subject)
				}
			}() // End of goroutine for individual user report
		}
		log.Printf("INFO: Dispatched individual %s report generation for %d users.", reportPeriodName, len(regularUserRecipients))

		// --- 2. Send Admin Summary Report (To Admins Only) ---
		if len(adminRecipients) > 0 {
			log.Printf("INFO: Generating Admin Summary %s report for %d admin(s)...", reportPeriodName, len(adminRecipients))

			// Launch in a goroutine so it doesn't block next cycle if slow
			go func() {
				adminSummaryData := generateAdminSummaryReportData(db, reportDuration)
				adminSummaryData.Period = fmt.Sprintf("%s Admin Summary", reportPeriodName)

				// Optional: Skip if no activity at all
				if len(adminSummaryData.ClientSummaries) == 0 && adminSummaryData.DataGenerationError == "" {
					log.Printf("INFO: Skipping %s Admin Summary report - no overall activity found.", reportPeriodName)
					return
				}

				html, err := generateReportHTML(adminSummaryData)
				if err != nil {
					log.Printf("ERROR: Failed to generate %s Admin Summary report HTML: %v", reportPeriodName, err)
					return
				}

				adminEmails := []string{}
				for _, admin := range adminRecipients {
					adminEmails = append(adminEmails, admin.Email)
				}

				subject := fmt.Sprintf("%s (%s)", adminSummaryData.Period, adminSummaryData.EndDate.Format("Jan 2, 2006"))

				// Send To Admins, no CC
				err = sendEmail(adminEmails, nil, subject, html)
				if err != nil {
					log.Printf("ERROR: Failed sending %s Admin Summary report to %s (Subject: %s)", reportPeriodName, strings.Join(adminEmails, ","), subject)
				}
			}() // End of goroutine for admin summary report

		} else {
			log.Printf("WARN: No admin users found with emails to send the %s Admin Summary report.", reportPeriodName)
		}
		log.Printf("INFO: === Completed %s Report Trigger Cycle ===", reportPeriodName)

	} // End of ticker loop
}

// --- Database Initialization and Seeding ---

func initializeDB(dbPath string) (*bolt.DB, error) {
	log.Printf("INFO: Initializing database at %s", dbPath)
	// Ensure directory exists
	dbDir := path.Dir(dbPath)
	if _, err := os.Stat(dbDir); os.IsNotExist(err) {
		log.Printf("INFO: Creating database directory: %s", dbDir)
		if err := os.MkdirAll(dbDir, 0750); err != nil { // Use 0750 for permissions
			return nil, fmt.Errorf("failed to create database directory '%s': %w", dbDir, err)
		}
	} else if err != nil {
		// Handle other potential errors from Stat (e.g., permission denied)
		return nil, fmt.Errorf("failed to check database directory '%s': %w", dbDir, err)
	}

	// Open database file
	dbConn, err := bolt.Open(dbPath, 0600, &bolt.Options{Timeout: 2 * time.Second}) // Slightly longer timeout
	if err != nil {
		return nil, fmt.Errorf("failed to open database '%s': %w", dbPath, err)
	}

	// Ensure all required buckets exist
	err = dbConn.Update(func(tx *bolt.Tx) error {
		requiredBuckets := []string{
			bUsers, bUsernames, bUserPasswords, // 🚨 bUserPasswords for plain text
			bClients, bVisits, bProducts, bOrders,
			// bOrderItems, // Not used as separate bucket currently
			bPWResets,
		}
		for _, bucketName := range requiredBuckets {
			_, err := tx.CreateBucketIfNotExists([]byte(bucketName))
			if err != nil {
				return fmt.Errorf("failed to create or access bucket '%s': %w", bucketName, err)
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
	if AdminDefaultPassword == "" || AdminUsername == "" { // Check both
		log.Println("WARN: Skipping admin seeding: AdminUsername or AdminDefaultPassword constant is empty.")
		return nil
	}

	err := db.Update(func(tx *bolt.Tx) error {
		usersBucket := tx.Bucket([]byte(bUsers))
		usernamesBucket := tx.Bucket([]byte(bUsernames))
		passwordsBucket := tx.Bucket([]byte(bUserPasswords)) // 🚨 Plain text bucket
		if usersBucket == nil || usernamesBucket == nil || passwordsBucket == nil {
			return fmt.Errorf("required buckets not found during admin seeding")
		}
		// Check if admin username already exists
		adminIdBytes := usernamesBucket.Get([]byte(AdminUsername))
		if adminIdBytes != nil {
			// Check if user data actually exists for that ID
			if usersBucket.Get(adminIdBytes) != nil {
				log.Printf("INFO: Admin user '%s' already exists. Skipping seeding.", AdminUsername)
				// Optionally: Update password if it doesn't match? Or force reset?
				// currentPassBytes := passwordsBucket.Get(adminIdBytes)
				// if string(currentPassBytes) != AdminDefaultPassword { ... update password ... }
				return nil // User exists, stop seeding
			} else {
				// Inconsistency: username mapping exists, but user data doesn't. Clean up?
				log.Printf("WARN: Found username mapping for '%s' but no user data. Attempting re-seed.", AdminUsername)
				// Delete inconsistent mapping before proceeding
				_ = usernamesBucket.Delete([]byte(AdminUsername))
			}
		}

		log.Printf("INFO: Seeding default admin user '%s'...", AdminUsername)

		// --- 🚨 Hashing Step (Replace Plain Text Storage) ---
		// hashedPassword, err := bcrypt.GenerateFromPassword([]byte(AdminDefaultPassword), bcrypt.DefaultCost)
		// if err != nil { return fmt.Errorf("failed to hash default admin password: %w", err) }
		// --- End Hashing Step ---

		id, _ := usersBucket.NextSequence()
		adminUserID := int(id)
		adminUser := User{
			ID:        adminUserID,
			Username:  AdminUsername,
			Email:     AdminDefaultEmail, // Validate format?
			IsAdmin:   true,
			CreatedAt: time.Now(),
			// PasswordHash: string(hashedPassword), // Store hash
		}
		// Store user data (excluding password)
		userData, err := json.Marshal(adminUser)
		if err != nil {
			return fmt.Errorf("failed to marshal admin user data: %w", err)
		}
		if err := usersBucket.Put(itob(adminUserID), userData); err != nil {
			return fmt.Errorf("failed to save admin user data: %w", err)
		}

		// Store username mapping
		if err := usernamesBucket.Put([]byte(adminUser.Username), itob(adminUserID)); err != nil {
			// Attempt rollback?
			log.Printf("CRITICAL: Failed to save username mapping for admin user %d!", adminUserID)
			return fmt.Errorf("failed to save admin username mapping")
		}

		// --- 🚨🚨 INSECURE: Storing plain text password 🚨🚨 ---
		if err := passwordsBucket.Put(itob(adminUserID), []byte(AdminDefaultPassword)); err != nil {
			log.Printf("CRITICAL: Failed to save admin plain text password for user %d!", adminUserID)
			return fmt.Errorf("failed to save admin user password")
		}
		// --- End Insecure Storage ---

		log.Printf("INFO: ✅ Seeded admin user: %s (ID: %d). 🚨 USING PLAIN TEXT PASSWORD! 🚨", adminUser.Username, adminUserID)
		return nil
	})
	if err != nil {
		// Log the specific error from the transaction
		return fmt.Errorf("admin seeding transaction failed: %w", err)
	}
	return nil
}

func initializeBleve(indexPath string) (bleve.Index, error) {
	log.Printf("INFO: Initializing Bleve index at %s", indexPath)

	// Ensure directory exists
	indexDir := path.Dir(indexPath)
	if _, err := os.Stat(indexDir); os.IsNotExist(err) {
		log.Printf("INFO: Creating Bleve index directory: %s", indexDir)
		if err := os.MkdirAll(indexDir, 0750); err != nil {
			return nil, fmt.Errorf("failed to create Bleve index directory '%s': %w", indexDir, err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("failed to check Bleve index directory '%s': %w", indexDir, err)
	}

	index, err := bleve.Open(indexPath)
	if errors.Is(err, bleve.ErrorIndexPathDoesNotExist) {
		log.Printf("INFO: Creating new Bleve index at '%s'...", indexPath)
		// TODO: Define actual mapping based on searchable fields
		// Example: index clients by name, email, contact
		mapping := bleve.NewIndexMapping()
		// mapping.AddDocumentMapping("client", clientMapping) // Define clientMapping

		index, err = bleve.New(indexPath, mapping)
		if err != nil {
			return nil, fmt.Errorf("failed to create new bleve index: %w", err)
		}
		log.Println("INFO: New Bleve index created.")
	} else if err != nil {
		return nil, fmt.Errorf("failed to open existing bleve index '%s': %w", indexPath, err)
	} else {
		log.Println("INFO: Opened existing Bleve index.")
	}
	// TODO: Index existing data if needed on startup?
	return index, nil
}

// --- Main Application ---

func main() {
	log.Println("INFO: =========================================")
	log.Println("INFO: Application starting...")
	log.Println("INFO: =========================================")

	// --- Load Timezone ---
	var err error
	istLocation, err = time.LoadLocation("Asia/Kolkata")
	if err != nil {
		// Fallback to UTC if IST fails? Or Fatal?
		log.Printf("FATAL: Failed to load IST location 'Asia/Kolkata': %v. Exiting.", err)
		os.Exit(1)
	}
	log.Printf("INFO: Timezone loaded: %s", istLocation.String())

	// --- Initialize Database ---
	db, err = initializeDB(DatabasePath)
	if err != nil {
		log.Printf("FATAL: Database initialization failed: %v. Exiting.", err)
		os.Exit(1)
	}
	defer func() {
		log.Println("INFO: Closing database connection...")
		if err := db.Close(); err != nil {
			log.Printf("ERROR: Failed to close database cleanly: %v", err)
		} else {
			log.Println("INFO: Database connection closed.")
		}
	}()
	log.Println("INFO: Database connection established.")

	// --- Seed Admin User ---
	if err := seedAdminUser(db); err != nil {
		// Log error but continue running? Or Fatal?
		log.Printf("ERROR: Admin user seeding failed: %v. Application will continue.", err)
	}

	// --- Initialize Bleve Search Index ---
	idx, err = initializeBleve(BlevePath)
	if err != nil {
		log.Printf("FATAL: Bleve search index initialization failed: %v. Exiting.", err)
		os.Exit(1) // Search might be critical
	}
	defer func() {
		log.Println("INFO: Closing Bleve index...")
		if err := idx.Close(); err != nil {
			log.Printf("ERROR: Failed to close Bleve index cleanly: %v", err)
		} else {
			log.Println("INFO: Bleve index closed.")
		}
	}()
	log.Println("INFO: Bleve index initialized.")

	// --- Create Fiber App ---
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			// Default error handler
			code := fiber.StatusInternalServerError
			message := "An unexpected error occurred."

			var e *fiber.Error
			if errors.As(err, &e) {
				code = e.Code
				message = e.Message
			} else {
				// Log non-fiber errors for debugging
				log.Printf("ERROR: Handler error: [%s] %s - %v", c.Method(), c.Path(), err)
			}

			// Send generic error message to client
			// Avoid sending detailed internal errors unless intended (e.g., for validation errors)
			c.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
			return c.Status(code).JSON(fiber.Map{"error": message})
		},
		ReadTimeout:  5 * time.Second, // Add timeouts
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	})

	// --- Core Middleware ---
	app.Use(recover.New())        // Recover from panics
	app.Use(cors.New(cors.Config{ // Configure CORS
		AllowOrigins: CORSOrigin, // 🚨 Use specific origins for production
		AllowHeaders: "Origin, Content-Type, Accept, Authorization",
		AllowMethods: "GET, POST, PUT, DELETE, OPTIONS",
	}))
	app.Use(logger.New(logger.Config{ // Request logging
		Format:     "[${time}] ${ip}:${port} ${status} | ${latency} | ${method} ${path} ${ua}\n", // Added User Agent
		TimeFormat: "2006/01/02 15:04:05",
		TimeZone:   istLocation.String(),
	}))

	// --- Prometheus Metrics Middleware ---
	httpRequestsTotal := promauto.NewCounterVec(prometheus.CounterOpts{Name: "http_requests_total", Help: "Total number of HTTP requests."}, []string{"method", "path", "status_code"})
	httpRequestDuration := promauto.NewHistogramVec(prometheus.HistogramOpts{Name: "http_request_duration_seconds", Help: "Duration of HTTP requests."}, []string{"method", "path"})

	app.Use(func(c *fiber.Ctx) error {
		start := time.Now()
		err := c.Next() // Execute route handler first

		// Determine status code even if error occurred before response was written
		statusCode := c.Response().StatusCode()
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

		// Use route path for label, fallback if route not matched
		routePath := c.Path() // Fallback to raw path
		if r := c.Route(); r != nil && r.Path != "" {
			routePath = r.Path // Use matched route path
		}

		// Record metrics
		httpRequestsTotal.WithLabelValues(c.Method(), routePath, strconv.Itoa(statusCode)).Inc()
		httpRequestDuration.WithLabelValues(c.Method(), routePath).Observe(time.Since(start).Seconds())

		return err // Return the original error to Fiber's error handler
	})
	app.Get("/metrics", metricsHandler) // Expose metrics endpoint

	// --- Public Routes (No Auth Required) ---
	app.Get("/healthz", healthzHandler)
	app.Post("/token", loginHandler)
	// app.Post("/send-test-email", sendTestEmailHandler) // Consider if needed

	// Manual report triggers (consider admin-only protection?)
	// app.Post("/send-admin-report-manual", adminOnly, sendReportHandler) // Example using admin summary
	// app.Post("/send-user-report-manual/:userid", adminOnly, sendUserReportManualHandler) // Example for specific user

	// --- API Routes Group (Requires Authentication) ---
	jwtMiddleware := NewJWTMiddleware()
	api := app.Group("/api", jwtMiddleware, authRequired) // Apply JWT and basic auth check

	// User Management Routes
	usersAPI := api.Group("/users")
	usersAPI.Post("/", adminOnly, createUserHandler)                    // Admin creates user
	usersAPI.Get("/", adminOnly, getUsersHandler)                       // Admin gets list of users
	usersAPI.Get("/:id", getUserHandler)                                // Admin or self gets user details
	usersAPI.Put("/:id", updateUserHandler)                             // Admin or self updates user details
	usersAPI.Delete("/:id", adminOnly, deleteUserHandler)               // Admin deletes user
	usersAPI.Put("/me/password", changeMyPasswordHandler)               // Self changes password
	usersAPI.Put("/:id/password", adminOnly, changeUserPasswordHandler) // Admin changes other user's password

	// Client Management Routes
	clientsAPI := api.Group("/clients")
	clientsAPI.Post("/", createClientHandler)                 // Any authenticated user creates client
	clientsAPI.Get("/", getClientsHandler)                    // Any authenticated user gets clients (with search)
	clientsAPI.Get("/:id", getClientHandler)                  // Any authenticated user gets specific client
	clientsAPI.Put("/:id", updateClientHandler)               // Admin or creator updates client
	clientsAPI.Delete("/:id", adminOnly, deleteClientHandler) // Admin deletes client

	// Product Management Routes
	productsAPI := api.Group("/products")
	productsAPI.Post("/", adminOnly, createProductHandler)      // Admin creates product
	productsAPI.Get("/", getProductsHandler)                    // Any authenticated user gets product list
	productsAPI.Get("/:id", getProductHandler)                  // Any authenticated user gets specific product
	productsAPI.Put("/:id", adminOnly, updateProductHandler)    // Admin updates product
	productsAPI.Delete("/:id", adminOnly, deleteProductHandler) // Admin deletes product

	// Order Management Routes
	ordersAPI := api.Group("/orders")
	ordersAPI.Post("/", createOrderHandler)                 // Any authenticated user creates order
	ordersAPI.Get("/", getOrdersHandler)                    // Admin sees all, user sees own
	ordersAPI.Get("/:id", getOrderHandler)                  // Admin sees all, user sees own
	ordersAPI.Put("/:id", updateOrderHandler)               // Admin or creator updates order status
	ordersAPI.Delete("/:id", adminOnly, deleteOrderHandler) // Admin deletes order

	// Visit Management Routes
	visitsAPI := api.Group("/visits")
	visitsAPI.Post("/", createVisitHandler)                 // Any authenticated user logs visit
	visitsAPI.Get("/", getVisitsHandler)                    // Admin sees all, user sees own
	visitsAPI.Put("/:id", updateVisitHandler)               // Admin or creator updates visit notes
	visitsAPI.Delete("/:id", adminOnly, deleteVisitHandler) // Admin deletes visit

	// Search Route
	api.Get("/search", searchHandler) // Any authenticated user can search

	// Master API Route (Use with EXTREME caution)
	masterAPI := api.Group("/master", adminOnly) // Ensure only admins can access
	masterAPI.Put("/:bucket/:key", masterUpdateHandler)

	// --- Static File Server ---
	// Serve static files (e.g., for a frontend UI) from the './static' directory
	// Make sure the 'static' directory exists and contains your files (index.html, css, js, etc.)
	// app.Static("/", "./static", fiber.Static{ // Serve index.html at root
	// 	Index: "index.html",
	// })
	// Or serve under a specific path:
	app.Static("/ui", "./static", fiber.Static{ // Serve UI under /ui/
		Index: "index.html",
	})
	// Fallback for unmatched routes (optional - could serve index.html for SPA routing)
	// app.Use(func(c *fiber.Ctx) error {
	//     // Check if it looks like a file request or API request
	//     if !strings.Contains(c.Path(), ".") && !strings.HasPrefix(c.Path(), "/api") {
	//         return c.SendFile("./static/index.html")
	//     }
	//     return c.Next()
	// })

	// --- Start Background Jobs ---
	log.Println("INFO: Starting background tasks...")
	go startReportJobs() // Start the reporting goroutine

	// --- Start Server and Handle Graceful Shutdown ---
	// Channel to listen for OS signals
	interruptChan := make(chan os.Signal, 1)
	signal.Notify(interruptChan, os.Interrupt, syscall.SIGTERM)

	// Goroutine to listen for signals and trigger shutdown
	go func() {
		sig := <-interruptChan
		log.Printf("INFO: Received signal: %s. Starting graceful shutdown...", sig)

		// Set deadline for shutdown
		shutdownTimeout := 30 * time.Second
		_ = app.ShutdownWithTimeout(shutdownTimeout) // Allow active requests to finish

		// Add cleanup tasks here if needed (e.g., flush logs)
		log.Println("INFO: Cleanup tasks finished.")
	}()

	// Start listening for HTTP requests
	listenAddr := ":" + Port
	log.Printf("INFO: Server starting, listening on %s", listenAddr)
	if err := app.Listen(listenAddr); err != nil && !errors.Is(err, http.ErrServerClosed) {
		// Log fatal error if server fails to start (excluding graceful shutdown)
		log.Fatalf("FATAL: Server listener failed: %v", err)
	}

	// This log message is reached after Shutdown() completes successfully
	log.Println("INFO: Server gracefully shut down. Application exit.")
	log.Println("INFO: =========================================")
}
