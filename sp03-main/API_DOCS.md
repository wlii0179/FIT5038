# Phishing Detection API Documentation v2.0

## Overview
This is a comprehensive RESTful API for phishing website detection with enhanced features including user management, detection history, and advanced analytics.

## Base URL
```
http://localhost:5000/api
```

## Authentication
Most endpoints require session-based authentication. Login using `/api/auth/login` first.

---

## 🔍 URL Detection APIs

### Single URL Detection
**POST** `/api/detect`

Detect if a single URL is phishing or safe with enhanced heuristic analysis.

**Request Body:**
```json
{
  "url": "https://example.com"
}
```

**Response:**
```json
{
  "url": "https://example.com",
  "is_safe": true,
  "confidence_score": 0.85,
  "phishing_probability": 0.15,
  "detected_at": "2025-08-20T10:30:00",
  "url_accessible": true,
  "heuristic_score": 2,
  "ml_suspicious_features": 3,
  "detection_id": 123,
  "sandbox_data": {
    "access_result": "success",
    "response_time": 1.2
  }
}
```

### Batch URL Detection
**POST** `/api/detect/batch`

Detect multiple URLs at once (up to 100 URLs).

**Request Body:**
```json
{
  "urls": [
    "https://example.com",
    "https://suspicious-site.com"
  ]
}
```

**Response:**
```json
{
  "total": 2,
  "safe_count": 1,
  "unsafe_count": 1,
  "results": [
    {
      "url": "https://example.com",
      "is_safe": true,
      "confidence_score": 0.85,
      "detected_at": "2025-08-20T10:30:00"
    }
  ]
}
```

---

## 📚 Detection History Management APIs

### Get Detection History
**GET** `/api/history`

Get paginated detection history with filtering options.

**Query Parameters:**
- `page` (int): Page number (default: 1)
- `per_page` (int): Items per page (max: 100, default: 20)
- `is_safe` (bool): Filter by safety status (true/false)
- `start_date` (string): Start date filter (YYYY-MM-DD)
- `end_date` (string): End date filter (YYYY-MM-DD)
- `search_url` (string): Search URLs containing text

**Example:**
```
GET /api/history?page=1&per_page=10&is_safe=false&start_date=2025-08-01
```

**Response:**
```json
{
  "history": [
    {
      "id": 123,
      "url": "https://example.com",
      "is_safe": true,
      "confidence_score": 0.85,
      "detected_at": "2025-08-20T10:30:00",
      "sandbox_risk_level": "low"
    }
  ],
  "total": 50,
  "pages": 5,
  "current_page": 1,
  "per_page": 10,
  "has_next": true,
  "has_prev": false
}
```

### Get Detection Detail
**GET** `/api/history/{detection_id}`

Get detailed information about a specific detection.

**Response:**
```json
{
  "id": 123,
  "url": "https://example.com",
  "is_safe": true,
  "confidence_score": 0.85,
  "detected_at": "2025-08-20T10:30:00",
  "sandbox_risk_level": "low"
}
```

### Delete Detection Record
**DELETE** `/api/history/{detection_id}`

Delete a specific detection record.

**Response:**
```json
{
  "message": "Detection deleted successfully"
}
```

### Clear All History
**DELETE** `/api/history`

Clear all detection history for the current user.

**Query Parameters:**
- `older_than_days` (int): Only delete records older than X days

**Response:**
```json
{
  "message": "Cleared 25 detection records",
  "deleted_count": 25
}
```

---

## 🔐 Authentication APIs

### Login
**POST** `/api/auth/login`

Authenticate user and start session.

**Request Body:**
```json
{
  "username": "john_doe",
  "password": "secure_password"
}
```

**Response:**
```json
{
  "message": "Login successful",
  "user": {
    "id": 1,
    "username": "john_doe",
    "email": "john@example.com",
    "created_at": "2025-08-01T00:00:00",
    "last_login": "2025-08-20T10:30:00"
  }
}
```

### Register
**POST** `/api/auth/register`

Create a new user account.

**Request Body:**
```json
{
  "username": "new_user",
  "email": "user@example.com",
  "password": "secure_password"
}
```

**Response:**
```json
{
  "message": "Registration successful",
  "user": {
    "id": 2,
    "username": "new_user",
    "email": "user@example.com",
    "created_at": "2025-08-20T10:30:00"
  }
}
```

### Logout
**POST** `/api/auth/logout`

End user session.

**Response:**
```json
{
  "message": "Logout successful"
}
```

---

## 👤 User Management APIs

### Get User Profile
**GET** `/api/user/profile`

Get current user's profile information.

**Response:**
```json
{
  "user": {
    "id": 1,
    "username": "john_doe",
    "email": "john@example.com",
    "created_at": "2025-08-01T00:00:00",
    "last_login": "2025-08-20T10:30:00"
  }
}
```

### Update User Profile
**PUT** `/api/user/profile`

Update current user's profile.

**Request Body:**
```json
{
  "email": "newemail@example.com",
  "password": "new_password"
}
```

**Response:**
```json
{
  "message": "Profile updated: email, password",
  "user": {
    "id": 1,
    "username": "john_doe",
    "email": "newemail@example.com",
    "created_at": "2025-08-01T00:00:00",
    "last_login": "2025-08-20T10:30:00"
  }
}
```

---

## 📊 Statistics APIs

### Get User Statistics
**GET** `/api/stats/user`

Get detailed statistics for the current user.

**Response:**
```json
{
  "total_detections": 150,
  "safe_count": 120,
  "unsafe_count": 30,
  "avg_confidence": 0.78,
  "safe_percentage": 80.0,
  "recent_detections_30d": 25,
  "daily_stats_7d": [
    {
      "date": "2025-08-20",
      "detections": 5
    }
  ]
}
```

### Get Global Statistics
**GET** `/api/stats/global`

Get global system statistics (public endpoint).

**Response:**
```json
{
  "total_users": 500,
  "total_detections": 10000,
  "total_safe": 8000,
  "total_unsafe": 2000,
  "detection_rate_24h": 250,
  "global_safe_percentage": 80.0
}
```

---

## 🛠️ Admin APIs

### List All Users
**GET** `/api/admin/users`

List all users with their statistics (admin only).

**Query Parameters:**
- `page` (int): Page number
- `per_page` (int): Items per page

**Response:**
```json
{
  "users": [
    {
      "id": 1,
      "username": "john_doe",
      "email": "john@example.com",
      "created_at": "2025-08-01T00:00:00",
      "last_login": "2025-08-20T10:30:00",
      "detection_count": 150
    }
  ],
  "total": 500,
  "pages": 25,
  "current_page": 1,
  "per_page": 20
}
```

---

## 📖 API Documentation
**GET** `/api/docs`

Get API documentation in JSON format.

---

## Error Responses

All endpoints may return error responses in the following format:

```json
{
  "error": "Error message describing what went wrong"
}
```

**Common HTTP Status Codes:**
- `200` - Success
- `201` - Created (for registration)
- `400` - Bad Request (invalid parameters)
- `401` - Unauthorized (login required)
- `404` - Not Found
- `409` - Conflict (user already exists)
- `500` - Internal Server Error

---

## Rate Limiting
- **Limit:** 100 requests per minute per user
- **Detection APIs:** Additional rate limiting may apply for batch operations

---

## Example Usage with curl

### Login and Detection Flow
```bash
# 1. Login
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "password": "password"}' \
  -c cookies.txt

# 2. Detect URL
curl -X POST http://localhost:5000/api/detect \
  -H "Content-Type: application/json" \
  -d '{"url": "https://suspicious-site.com"}' \
  -b cookies.txt

# 3. Get Detection History
curl -X GET "http://localhost:5000/api/history?page=1&per_page=5" \
  -b cookies.txt

# 4. Get User Statistics
curl -X GET http://localhost:5000/api/stats/user \
  -b cookies.txt
```

### Batch Detection
```bash
curl -X POST http://localhost:5000/api/detect/batch \
  -H "Content-Type: application/json" \
  -d '{
    "urls": [
      "https://example.com",
      "https://suspicious-site.com",
      "https://another-site.org"
    ]
  }' \
  -b cookies.txt
```

---

## Enhanced Features

### Heuristic Detection
The API now includes enhanced heuristic analysis that checks for:
- Suspicious TLDs (.icu, .tk, .ml, etc.)
- Phishing keywords in URLs
- Brand impersonation attempts
- Suspicious URL structures
- Machine learning feature analysis

### Sandbox Integration
All URL detections include sandbox isolation analysis with:
- Safe URL access in isolated environment
- Response time measurement
- Redirect analysis
- Content preview (limited)

### Advanced Filtering
Detection history supports advanced filtering by:
- Safety status (safe/unsafe)
- Date ranges
- URL search
- Pagination with customizable page sizes

This API provides a complete solution for phishing detection with enterprise-grade features! 