// main.go

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go" // JWT generation/validation
	"github.com/gin-contrib/cors" // CORS middleware
	"github.com/gin-gonic/gin"    // Gin web framework
	"github.com/google/uuid"      // UUID generation
	"go.etcd.io/bbolt"            // bbolt for lightweight embedded DB
	"golang.org/x/crypto/bcrypt"  // Password hashing
)

// -------------------
// Configurable Settings
// -------------------
const (
	// DBPath is the location of the database file.
	DBPath = "data/db/sales.db"
	// Token expiration in hours (24 hours by default)
	tokenExpirationHours = 24
)

// jwtSecret should be loaded from an environment variable in production.
var jwtSecret = []byte("your_secret_key_here")

// -------------------
// Global DB Variable
// -------------------
var db *bbolt.DB

// -------------------
// Bucket Names
// -------------------
var (
	UsersBucket      = []byte("users")
	ClientsBucket    = []byte("clients")
	VisitsBucket     = []byte("visits")
	ProductsBucket   = []byte("products")
	OrdersBucket     = []byte("orders")
	OrderItemsBucket = []byte("orderitems")
)

// -------------------
// Data Models
// -------------------
type User struct {
	ID             string    `json:"id"`
	Username       string    `json:"username"`
	Email          string    `json:"email"`
	HashedPassword string    `json:"hashed_password"`
	FullName       string    `json:"full_name"`
	Phone          string    `json:"phone"`
	IsActive       bool      `json:"is_active"`
	IsAdmin        bool      `json:"is_admin"`
	CreatedAt      time.Time `json:"created_at"`
	LastLogin      time.Time `json:"last_login,omitempty"`
}

type Client struct {
	ID           string    `json:"id"`
	CompanyName  string    `json:"company_name"`
	ContactName  string    `json:"contact_name"`
	ContactPhone string    `json:"contact_phone"`
	CreatorID    string    `json:"creator_id"` // Added CreatorID to track who created the client
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type Visit struct {
	ID              string    `json:"id"`
	EmployeeID      string    `json:"employee_id"`
	ClientID        string    `json:"client_id"`
	VisitDate       time.Time `json:"visit_date"`
	LocationName    string    `json:"location_name"`
	Latitude        float64   `json:"latitude,omitempty"`
	Longitude       float64   `json:"longitude,omitempty"`
	Purpose         string    `json:"purpose"`
	Notes           string    `json:"notes,omitempty"`
	DurationMinutes int       `json:"duration_minutes,omitempty"`
	HasOrder        bool      `json:"has_order"`
	CreatedAt       time.Time `json:"created_at"`
	StartTime       time.Time `json:"start_time,omitempty"`
	EndTime         time.Time `json:"end_time,omitempty"`
}

type Product struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Price       float64   `json:"price"`
	IsActive    bool      `json:"is_active"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at,omitempty"`
}

type Order struct {
	ID          string      `json:"id"`
	VisitID     string      `json:"visit_id"`
	OrderDate   time.Time   `json:"order_date"`
	TotalAmount float64     `json:"total_amount"`
	CreatedAt   time.Time   `json:"created_at"`
	OrderItems  []OrderItem `json:"order_items,omitempty"`
}

type OrderItem struct {
	ID        string  `json:"id"`
	OrderID   string  `json:"order_id"`
	ProductID string  `json:"product_id"`
	Quantity  int     `json:"quantity"`
	Price     float64 `json:"price"`
	Total     float64 `json:"total"`
}

// -------------------
// JWT Claims
// -------------------
type JWTClaims struct {
	Username string `json:"sub"`
	jwt.StandardClaims
}

// -------------------
// Helper Functions: Password Hashing
// -------------------
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// -------------------
// JWT Helper Functions
// -------------------
func GenerateToken(username string) (string, error) {
	expirationTime := time.Now().Add(tokenExpirationHours * time.Hour)
	claims := &JWTClaims{
		Username: username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
			IssuedAt:  time.Now().Unix(),
			Subject:   username,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func ValidateToken(tokenStr string) (*JWTClaims, error) {
	claims := &JWTClaims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	return claims, nil
}

// -------------------
// bbolt Helper Functions
// -------------------
func saveEntity(bucketName []byte, key string, value interface{}) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}

	return db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(bucketName)
		if bucket == nil {
			return fmt.Errorf("bucket not found")
		}

		return bucket.Put([]byte(key), data)
	})
}

func getEntity(bucketName []byte, key string, out interface{}) error {
	return db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(bucketName)
		if bucket == nil {
			return fmt.Errorf("bucket not found")
		}

		data := bucket.Get([]byte(key))
		if data == nil {
			return fmt.Errorf("entity not found")
		}

		return json.Unmarshal(data, out)
	})
}

func getAllEntities(bucketName []byte) ([][]byte, error) {
	var items [][]byte
	err := db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(bucketName)
		if bucket == nil {
			return fmt.Errorf("bucket not found")
		}

		return bucket.ForEach(func(k, v []byte) error {
			b := make([]byte, len(v))
			copy(b, v)
			items = append(items, b)
			return nil
		})
	})
	return items, err
}

// -------------------
// Entity-Specific Helper Functions
// -------------------
// Users
func saveUser(user *User) error {
	key := fmt.Sprintf("user:%s", user.ID)
	return saveEntity(UsersBucket, key, user)
}

func getUserByUsername(username string) (*User, error) {
	var foundUser *User
	data, err := getAllEntities(UsersBucket)
	if err != nil {
		return nil, err
	}

	for _, d := range data {
		var user User
		if err := json.Unmarshal(d, &user); err != nil {
			continue
		}

		if user.Username == username {
			foundUser = &user
			break
		}
	}

	if foundUser == nil {
		return nil, fmt.Errorf("user not found")
	}

	return foundUser, nil
}

// New function to check for duplicate email
func getUserByEmail(email string) (*User, error) {
	var foundUser *User
	data, err := getAllEntities(UsersBucket)
	if err != nil {
		return nil, err
	}

	for _, d := range data {
		var user User
		if err := json.Unmarshal(d, &user); err != nil {
			continue
		}

		if user.Email == email {
			foundUser = &user
			break
		}
	}

	if foundUser == nil {
		return nil, fmt.Errorf("user not found")
	}

	return foundUser, nil
}

func getAllUsers() ([]User, error) {
	var users []User
	data, err := getAllEntities(UsersBucket)
	if err != nil {
		return nil, err
	}

	for _, d := range data {
		var user User
		if err := json.Unmarshal(d, &user); err == nil {
			users = append(users, user)
		}
	}

	return users, nil
}

// Clients
func saveClient(client *Client) error {
	key := fmt.Sprintf("client:%s", client.ID)
	return saveEntity(ClientsBucket, key, client)
}

// New function to check for duplicate company name
func getClientByCompanyName(companyName string) (*Client, error) {
	var foundClient *Client
	data, err := getAllEntities(ClientsBucket)
	if err != nil {
		return nil, err
	}

	for _, d := range data {
		var client Client
		if err := json.Unmarshal(d, &client); err != nil {
			continue
		}

		if client.CompanyName == companyName {
			foundClient = &client
			break
		}
	}

	if foundClient == nil {
		return nil, fmt.Errorf("client not found")
	}

	return foundClient, nil
}

func getAllClients() ([]Client, error) {
	var clients []Client
	data, err := getAllEntities(ClientsBucket)
	if err != nil {
		return nil, err
	}

	for _, d := range data {
		var client Client
		if err := json.Unmarshal(d, &client); err == nil {
			clients = append(clients, client)
		}
	}

	return clients, nil
}

// Get clients by creator
func getClientsByCreator(creatorID string) ([]Client, error) {
	var userClients []Client
	allClients, err := getAllClients()
	if err != nil {
		return nil, err
	}

	for _, client := range allClients {
		if client.CreatorID == creatorID {
			userClients = append(userClients, client)
		}
	}

	return userClients, nil
}

// Visits
func saveVisit(visit *Visit) error {
	key := fmt.Sprintf("visit:%s", visit.ID)
	return saveEntity(VisitsBucket, key, visit)
}

func getAllVisits() ([]Visit, error) {
	var visits []Visit
	data, err := getAllEntities(VisitsBucket)
	if err != nil {
		return nil, err
	}

	for _, d := range data {
		var visit Visit
		if err := json.Unmarshal(d, &visit); err == nil {
			visits = append(visits, visit)
		}
	}

	return visits, nil
}

// Get visits by employee
func getVisitsByEmployee(employeeID string) ([]Visit, error) {
	var userVisits []Visit
	allVisits, err := getAllVisits()
	if err != nil {
		return nil, err
	}

	for _, visit := range allVisits {
		if visit.EmployeeID == employeeID {
			userVisits = append(userVisits, visit)
		}
	}

	return userVisits, nil
}

// Products
func saveProduct(product *Product) error {
	key := fmt.Sprintf("product:%s", product.ID)
	return saveEntity(ProductsBucket, key, product)
}

func getAllProducts() ([]Product, error) {
	var products []Product
	data, err := getAllEntities(ProductsBucket)
	if err != nil {
		return nil, err
	}

	for _, d := range data {
		var product Product
		if err := json.Unmarshal(d, &product); err == nil {
			products = append(products, product)
		}
	}

	return products, nil
}

func updateProduct(product *Product) error {
	key := fmt.Sprintf("product:%s", product.ID)
	return saveEntity(ProductsBucket, key, product)
}

// Orders
func saveOrder(order *Order) error {
	key := fmt.Sprintf("order:%s", order.ID)
	return saveEntity(OrdersBucket, key, order)
}

func getAllOrders() ([]Order, error) {
	var orders []Order
	data, err := getAllEntities(OrdersBucket)
	if err != nil {
		return nil, err
	}

	for _, d := range data {
		var order Order
		if err := json.Unmarshal(d, &order); err == nil {
			orders = append(orders, order)
		}
	}

	return orders, nil
}

// Get orders from user's visits
func getOrdersByEmployeeID(employeeID string) ([]Order, error) {
	// First get all visits by this employee
	visits, err := getVisitsByEmployee(employeeID)
	if err != nil {
		return nil, err
	}

	// Create a map of visit IDs
	visitIDMap := make(map[string]bool)
	for _, visit := range visits {
		visitIDMap[visit.ID] = true
	}

	// Get all orders and filter by visit IDs
	allOrders, err := getAllOrders()
	if err != nil {
		return nil, err
	}

	var userOrders []Order
	for _, order := range allOrders {
		if visitIDMap[order.VisitID] {
			userOrders = append(userOrders, order)
		}
	}

	return userOrders, nil
}

// Order Items
func saveOrderItem(item *OrderItem) error {
	key := fmt.Sprintf("orderitem:%s", item.ID)
	return saveEntity(OrderItemsBucket, key, item)
}

// -------------------
// Delete Endpoints for Permanent Deletion
// -------------------
func deleteUserHandler(c *gin.Context) {
	id := c.Param("id")
	key := fmt.Sprintf("user:%s", id)
	err := db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(UsersBucket)
		if bucket == nil {
			return fmt.Errorf("bucket not found")
		}

		return bucket.Delete([]byte(key))
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error deleting user: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User deleted permanently"})
}

func deleteProductHandler(c *gin.Context) {
	id := c.Param("id")
	key := fmt.Sprintf("product:%s", id)
	err := db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(ProductsBucket)
		if bucket == nil {
			return fmt.Errorf("bucket not found")
		}

		return bucket.Delete([]byte(key))
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error deleting product: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Product deleted permanently"})
}

// -------------------
// Middleware for Authentication
// -------------------
func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenStr := c.GetHeader("Authorization")
		if tokenStr == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing token"})
			c.Abort()
			return
		}

		claims, err := ValidateToken(tokenStr)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		c.Set("username", claims.Username)
		c.Next()
	}
}

// Admin middleware to check if user is admin
func adminMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		username := c.MustGet("username").(string)
		user, err := getUserByUsername(username)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error retrieving user"})
			c.Abort()
			return
		}

		if !user.IsAdmin {
			c.JSON(http.StatusForbidden, gin.H{"error": "Admin access required"})
			c.Abort()
			return
		}

		c.Next()
	}
}

// -------------------
// Handlers
// -------------------
func tokenHandler(c *gin.Context) {
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&creds); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON data"})
		return
	}

	// Add logging for debugging
	log.Printf("Login attempt for username: %s", creds.Username)
	user, err := getUserByUsername(creds.Username)
	if err != nil {
		log.Printf("User not found: %s, error: %v", creds.Username, err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Incorrect username or password"})
		return
	}

	// Check if user is active
	if !user.IsActive {
		log.Printf("Login attempt for inactive user: %s", creds.Username)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User account is inactive"})
		return
	}

	// Verify password
	if !CheckPasswordHash(creds.Password, user.HashedPassword) {
		log.Printf("Password mismatch for user: %s", creds.Username)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Incorrect username or password"})
		return
	}

	user.LastLogin = time.Now()
	_ = saveUser(user)
	token, err := GenerateToken(user.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate token"})
		return
	}

	log.Printf("Successful login for user: %s", creds.Username)
	c.JSON(http.StatusOK, gin.H{
		"access_token": token,
		"token_type":   "bearer",
		"user":         user,
	})
}

// Modified to filter data based on role
func getUsersHandler(c *gin.Context) {
	username := c.MustGet("username").(string)
	currentUser, err := getUserByUsername(username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error retrieving user"})
		return
	}

	if currentUser.IsAdmin {
		// Admin can see all users
		users, err := getAllUsers()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error retrieving users"})
			return
		}

		c.JSON(http.StatusOK, users)
	} else {
		// Normal user can only see their own profile
		c.JSON(http.StatusOK, []User{*currentUser})
	}
}

// Updated to check for duplicate username and email
func createUserHandler(c *gin.Context) {
	var request struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Email    string `json:"email"`
		FullName string `json:"full_name"`
		Phone    string `json:"phone"`
		IsAdmin  bool   `json:"is_admin"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request data"})
		return
	}

	// Check if user with the same username already exists
	_, err := getUserByUsername(request.Username)
	if err == nil {
		// User exists
		c.JSON(http.StatusConflict, gin.H{"error": "A user with this username already exists"})
		return
	}

	// Check if user with the same email already exists
	_, err = getUserByEmail(request.Email)
	if err == nil {
		// User exists
		c.JSON(http.StatusConflict, gin.H{"error": "A user with this email already exists"})
		return
	}

	// Create user with properly hashed password
	user := User{
		ID:        uuid.New().String(),
		Username:  request.Username,
		Email:     request.Email,
		FullName:  request.FullName,
		Phone:     request.Phone,
		IsAdmin:   request.IsAdmin,
		IsActive:  true,
		CreatedAt: time.Now(),
	}

	// Hash the password
	hashed, err := HashPassword(request.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error hashing password"})
		return
	}

	user.HashedPassword = hashed
	if err := saveUser(&user); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error saving user"})
		return
	}

	c.JSON(http.StatusCreated, user)
}

// Updated to support filtering by creator_id query parameter
func getClientsHandler(c *gin.Context) {
	username := c.MustGet("username").(string)
	currentUser, err := getUserByUsername(username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error retrieving user"})
		return
	}

	// Check for creator_id filter parameter
	creatorID := c.Query("creator_id")
	// Get all clients
	allClients, err := getAllClients()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error retrieving clients"})
		return
	}

	// Admin with no filters sees all clients
	if currentUser.IsAdmin && creatorID == "" {
		c.JSON(http.StatusOK, allClients)
		return
	}

	// If a specific creator filter is provided, use it
	if creatorID != "" {
		var filteredClients []Client
		for _, client := range allClients {
			if client.CreatorID == creatorID {
				filteredClients = append(filteredClients, client)
			}
		}

		c.JSON(http.StatusOK, filteredClients)
		return
	}

	// Standard users see clients they created
	if !currentUser.IsAdmin {
		var userClients []Client
		for _, client := range allClients {
			if client.CreatorID == username {
				userClients = append(userClients, client)
			}
		}

		c.JSON(http.StatusOK, userClients)
		return
	}

	// Fallback - should not reach here
	c.JSON(http.StatusOK, allClients)
}

// Updated to check for duplicate company name before creating a client
func createClientHandler(c *gin.Context) {
	var client Client
	if err := c.ShouldBindJSON(&client); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request data"})
		return
	}

	// Check if client with the same company name already exists
	_, err := getClientByCompanyName(client.CompanyName)
	if err == nil {
		// Client exists
		c.JSON(http.StatusConflict, gin.H{"error": "A client with this company name already exists"})
		return
	}

	// Get the current user's username and set as creator
	username := c.MustGet("username").(string)
	client.CreatorID = username
	client.ID = uuid.New().String()
	now := time.Now()
	client.CreatedAt = now
	client.UpdatedAt = now
	if err := saveClient(&client); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error saving client"})
		return
	}

	c.JSON(http.StatusCreated, client)
}

// Updated to support employee_id query parameter
func getVisitsHandler(c *gin.Context) {
	username := c.MustGet("username").(string)
	currentUser, err := getUserByUsername(username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error retrieving user"})
		return
	}

	// Check for employee_id filter parameter
	employeeID := c.Query("employee_id")
	if currentUser.IsAdmin && employeeID == "" {
		// Admin without filter sees all visits
		visits, err := getAllVisits()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error retrieving visits"})
			return
		}

		c.JSON(http.StatusOK, visits)
		return
	}

	// If employeeID filter is provided, use it
	if employeeID != "" {
		visits, err := getVisitsByEmployee(employeeID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error retrieving visits"})
			return
		}

		c.JSON(http.StatusOK, visits)
		return
	}

	// Normal user can only see their own visits
	visits, err := getVisitsByEmployee(username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error retrieving visits"})
		return
	}

	c.JSON(http.StatusOK, visits)
}

func createVisitHandler(c *gin.Context) {
	var visit Visit
	if err := c.ShouldBindJSON(&visit); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request data"})
		return
	}

	if username, exists := c.Get("username"); exists {
		visit.EmployeeID = fmt.Sprintf("%v", username)
	}

	visit.ID = uuid.New().String()
	now := time.Now()
	visit.VisitDate = now
	visit.CreatedAt = now
	visit.StartTime = now
	if err := saveVisit(&visit); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error saving visit"})
		return
	}

	c.JSON(http.StatusCreated, visit)
}

func getProductsHandler(c *gin.Context) {
	products, err := getAllProducts()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error retrieving products"})
		return
	}

	// Filter to only show active products
	var activeProducts []Product
	for _, product := range products {
		if product.IsActive {
			activeProducts = append(activeProducts, product)
		}
	}

	c.JSON(http.StatusOK, activeProducts)
}

func createProductHandler(c *gin.Context) {
	var product Product
	if err := c.ShouldBindJSON(&product); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request data"})
		return
	}

	product.ID = uuid.New().String()
	product.CreatedAt = time.Now()
	product.IsActive = true
	if err := saveProduct(&product); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error saving product"})
		return
	}

	c.JSON(http.StatusCreated, product)
}

func updateProductHandler(c *gin.Context) {
	id := c.Param("id")
	var product Product
	key := fmt.Sprintf("product:%s", id)
	if err := getEntity(ProductsBucket, key, &product); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Product not found"})
		return
	}

	if err := c.ShouldBindJSON(&product); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request data"})
		return
	}

	product.UpdatedAt = time.Now()
	if err := updateProduct(&product); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error updating product"})
		return
	}

	c.JSON(http.StatusOK, product)
}

func deactivateProductHandler(c *gin.Context) {
	id := c.Param("id")
	var product Product
	key := fmt.Sprintf("product:%s", id)
	if err := getEntity(ProductsBucket, key, &product); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Product not found"})
		return
	}

	product.IsActive = false
	if err := updateProduct(&product); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error deactivating product"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Product deactivated successfully"})
}

func createOrderHandler(c *gin.Context) {
	visitID := c.Param("visit_id")
	// Verify the visit belongs to the current user if not admin
	username := c.MustGet("username").(string)
	currentUser, err := getUserByUsername(username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error retrieving user"})
		return
	}

	// If not admin, check if visit belongs to this user
	if !currentUser.IsAdmin {
		var visit Visit
		visitKey := fmt.Sprintf("visit:%s", visitID)
		if err := getEntity(VisitsBucket, visitKey, &visit); err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Visit not found"})
			return
		}

		if visit.EmployeeID != username {
			c.JSON(http.StatusForbidden, gin.H{"error": "Cannot create orders for other users' visits"})
			return
		}
	}

	var orderData struct {
		Items []struct {
			ProductID string `json:"product_id"`
			Quantity  int    `json:"quantity"`
		} `json:"items"`
	}

	if err := c.ShouldBindJSON(&orderData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid order data"})
		return
	}

	var totalAmount float64
	var orderItems []OrderItem
	for _, item := range orderData.Items {
		var product Product
		prodKey := fmt.Sprintf("product:%s", item.ProductID)
		if err := getEntity(ProductsBucket, prodKey, &product); err != nil || !product.IsActive {
			c.JSON(http.StatusNotFound, gin.H{"error": "Product not found or inactive: " + item.ProductID})
			return
		}

		itemTotal := product.Price * float64(item.Quantity)
		totalAmount += itemTotal
		orderItem := OrderItem{
			ID:        uuid.New().String(),
			ProductID: item.ProductID,
			Quantity:  item.Quantity,
			Price:     product.Price,
			Total:     itemTotal,
		}

		orderItems = append(orderItems, orderItem)
	}

	order := Order{
		ID:          uuid.New().String(),
		VisitID:     visitID,
		OrderDate:   time.Now(),
		CreatedAt:   time.Now(),
		TotalAmount: totalAmount,
		OrderItems:  orderItems,
	}

	if err := saveOrder(&order); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error saving order"})
		return
	}

	for i := range orderItems {
		orderItems[i].OrderID = order.ID
		_ = saveOrderItem(&orderItems[i])
	}

	// Update visit to mark that it has an order
	var visit Visit
	visitKey := fmt.Sprintf("visit:%s", visitID)
	if err := getEntity(VisitsBucket, visitKey, &visit); err == nil {
		visit.HasOrder = true
		_ = saveVisit(&visit)
	}

	c.JSON(http.StatusCreated, order)
}

// Updated to support employee_id query parameter
func getOrdersHandler(c *gin.Context) {
	username := c.MustGet("username").(string)
	currentUser, err := getUserByUsername(username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error retrieving user"})
		return
	}

	// Check for employee_id filter parameter
	employeeID := c.Query("employee_id")
	if currentUser.IsAdmin && employeeID == "" {
		// Admin without filter sees all orders
		orders, err := getAllOrders()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error retrieving orders"})
			return
		}

		c.JSON(http.StatusOK, orders)
		return
	}

	// If employeeID filter is provided, get orders for that employee
	if employeeID != "" {
		orders, err := getOrdersByEmployeeID(employeeID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error retrieving orders"})
			return
		}

		c.JSON(http.StatusOK, orders)
		return
	}

	// Standard user sees their own orders
	orders, err := getOrdersByEmployeeID(username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error retrieving orders"})
		return
	}

	c.JSON(http.StatusOK, orders)
}

// Updated to support employee_id query parameter
func dashboardHandler(c *gin.Context) {
	username := c.MustGet("username").(string)
	currentUser, err := getUserByUsername(username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error retrieving user"})
		return
	}

	// Check for employee_id filter parameter
	employeeID := c.Query("employee_id")
	if currentUser.IsAdmin && employeeID == "" {
		// Admin sees complete dashboard with all data
		users, _ := getAllUsers()
		clients, _ := getAllClients()
		visits, _ := getAllVisits()
		orders, _ := getAllOrders()
		dashboard := gin.H{
			"total_users":   len(users),
			"total_clients": len(clients),
			"total_visits":  len(visits),
			"total_orders":  len(orders),
			"timestamp":     time.Now(),
		}

		c.JSON(http.StatusOK, dashboard)
		return
	}

	// If employeeID filter is provided, get data for that employee
	targetEmployeeID := username
	if employeeID != "" {
		targetEmployeeID = employeeID
	}

	// Get employee-specific data
	visits, _ := getVisitsByEmployee(targetEmployeeID)
	// Get clients created by this employee
	userClients, _ := getClientsByCreator(targetEmployeeID)
	// Get orders for this employee's visits
	orders, _ := getOrdersByEmployeeID(targetEmployeeID)
	// User-specific dashboard
	dashboard := gin.H{
		"total_users":   1, // Just counting the user themselves
		"total_clients": len(userClients),
		"total_visits":  len(visits),
		"total_orders":  len(orders),
		"timestamp":     time.Now(),
	}

	c.JSON(http.StatusOK, dashboard)
}

// Added user deactivation for soft delete
func deactivateUserHandler(c *gin.Context) {
	id := c.Param("id")
	var user User
	key := fmt.Sprintf("user:%s", id)
	if err := getEntity(UsersBucket, key, &user); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	user.IsActive = false
	if err := saveUser(&user); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error deactivating user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User deactivated successfully"})
}

// NEW HANDLER: Admin changing their own password
func changeAdminPasswordHandler(c *gin.Context) {
	// Get the current admin's username from the context
	adminUsername := c.MustGet("username").(string)

	// Parse the request body
	var request struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request data"})
		return
	}

	// Get the admin user
	admin, err := getUserByUsername(adminUsername)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error retrieving user"})
		return
	}

	// Verify the old password
	if !CheckPasswordHash(request.OldPassword, admin.HashedPassword) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Incorrect old password"})
		return
	}

	// Hash the new password
	hashedPassword, err := HashPassword(request.NewPassword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error hashing password"})
		return
	}

	// Update the admin's password
	admin.HashedPassword = hashedPassword

	if err := saveUser(admin); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error saving user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password updated successfully"})
}

// NEW HANDLER: Admin changing another user's password
func changeUserPasswordHandler(c *gin.Context) {
	// Get the target user ID from the URL parameter
	userID := c.Param("id")

	// Parse the request body
	var request struct {
		NewPassword string `json:"new_password"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request data"})
		return
	}

	// Get the target user
	var user User
	key := fmt.Sprintf("user:%s", userID)
	if err := getEntity(UsersBucket, key, &user); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Hash the new password
	hashedPassword, err := HashPassword(request.NewPassword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error hashing password"})
		return
	}

	// Update the user's password
	user.HashedPassword = hashedPassword

	if err := saveUser(&user); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error saving user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User password updated successfully"})
}

// -------------------
// Initial Admin Creation
// -------------------
func createInitialAdmin() {
	users, err := getAllUsers()
	if err != nil {
		log.Println("Error checking for initial users:", err)
		return
	}

	if len(users) == 0 {
		admin := &User{
			ID:             uuid.New().String(),
			Username:       "admin",
			Email:          "admin@example.com",
			FullName:       "Admin User",
			Phone:          "1234567890",
			IsActive:       true,
			IsAdmin:        true,
			CreatedAt:      time.Now(),
			LastLogin:      time.Now(),
			HashedPassword: "",
		}

		hashed, err := HashPassword("admin123")
		if err != nil {
			log.Println("Error hashing admin password:", err)
			return
		}

		admin.HashedPassword = hashed
		if err := saveUser(admin); err != nil {
			log.Println("Error creating initial admin user:", err)
			return
		}

		// Create a standard user for testing
		standardUser := &User{
			ID:             uuid.New().String(),
			Username:       "ml",
			Email:          "ml@example.com",
			FullName:       "Standard User",
			Phone:          "9876543210",
			IsActive:       true,
			IsAdmin:        false,
			CreatedAt:      time.Now(),
			LastLogin:      time.Now(),
			HashedPassword: "",
		}

		hashed, err = HashPassword("password123")
		if err != nil {
			log.Println("Error hashing standard user password:", err)
			return
		}

		standardUser.HashedPassword = hashed
		if err := saveUser(standardUser); err != nil {
			log.Println("Error creating standard user:", err)
			return
		}

		log.Println("Created initial admin user: username=admin, password=admin123")
		log.Println("Created standard user: username=ml, password=password123")
	}
}

// -------------------
// Main Function
// -------------------
func main() {
	// Ensure DB directory exists.
	if err := os.MkdirAll("data/db", os.ModePerm); err != nil {
		log.Fatalf("Failed to create DB directory: %v", err)
	}

	// Open bbolt database.
	var err error
	db, err = bbolt.Open(DBPath, 0600, nil)
	if err != nil {
		log.Fatalf("Failed to open bbolt DB: %v", err)
	}

	defer db.Close()
	// Ensure buckets exist.
	err = db.Update(func(tx *bbolt.Tx) error {
		buckets := [][]byte{UsersBucket, ClientsBucket, VisitsBucket, ProductsBucket, OrdersBucket, OrderItemsBucket}
		for _, bucket := range buckets {
			_, err := tx.CreateBucketIfNotExists(bucket)
			if err != nil {
				return fmt.Errorf("create bucket %s: %s", bucket, err)
			}
		}
		return nil
	})
	if err != nil {
		log.Fatalf("Error creating buckets: %v", err)
	}

	// Create initial admin if needed.
	createInitialAdmin()
	// Set up Gin router.
	router := gin.Default()
	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization"},
		ExposeHeaders:    []string{"Content-Length", "Authorization"},
		AllowCredentials: false,
		MaxAge:           12 * time.Hour,
	}))
	// Public endpoints.
	router.POST("/token", tokenHandler)
	router.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "pong"})
	})
	// Protected endpoints accessible by all authenticated users.
	api := router.Group("/api")
	api.Use(authMiddleware())
	// User can only view own profile
	api.GET("/users", getUsersHandler) // Modified to show only own profile for non-admins
	// Visit endpoints - user can view and create their own visits
	api.GET("/visits", getVisitsHandler) // Modified to support employee_id filter
	api.POST("/visits", createVisitHandler)
	// Client endpoints - user can view and create clients
	api.GET("/clients", getClientsHandler)    // Modified to support creator_id filter
	api.POST("/clients", createClientHandler) // Moved from admin-only to allow all users to create clients
	// Product endpoints - read-only for all users
	api.GET("/products", getProductsHandler)
	// Order endpoints - user can create orders and view their own
	api.POST("/visits/:visit_id/orders", createOrderHandler)
	api.GET("/orders", getOrdersHandler) // Modified to support employee_id filter
	// Dashboard - modified for non-admins
	api.GET("/dashboard", dashboardHandler) // Modified to support employee_id filter
	// Admin-only endpoints
	adminApi := api.Group("/")
	adminApi.Use(adminMiddleware())
	// User management - admin only
	adminApi.POST("/users", createUserHandler)
	adminApi.DELETE("/users/:id", deleteUserHandler)
	adminApi.DELETE("/users/:id/deactivate", deactivateUserHandler)
	// Product management - admin only
	adminApi.POST("/products", createProductHandler)
	adminApi.PUT("/products/:id", updateProductHandler)
	adminApi.DELETE("/products/:id", deactivateProductHandler)
	adminApi.DELETE("/products/:id/permanent", deleteProductHandler)
	// NEW ROUTES: Password management
	adminApi.POST("/change-password", changeAdminPasswordHandler)          // For admin to change their own password
	adminApi.POST("/users/:id/change-password", changeUserPasswordHandler) // For admin to change other users' passwords

	// Start the server.
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Server running on port %s", port)
	err = router.Run(":" + port)
	if err != nil {
		log.Fatalf("Failed to run server: %v", err)
	}
}
