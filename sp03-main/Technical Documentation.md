# Technical Documentation Phishing Website Detection System System Design, AI Model Integration & APIs
## Team SP03
### Contents
1. System Overview 3
2. System Architecture
   2.1 Overall Architecture Pattern
   2.2 Component Relationships
   2.3 Database Design …… 4
3. AI Model Integration 5
   3.1 AI Method 5
   3.2 Feature Engineering Process 5
   3.3 Real-Time Prediction Pipeline 6
   3.4 Model Performance and Confidence Scoring 7
4. API Documentation 7
   4.1 API Architecture 7
   4.2 Authentication and Session Management 7
5. Security Implementation 9
6. Performance Considerations
   6.1 Response Time Optimization 9
   6.2 Scalability Data 10
7. Deployment Architecture 10
   7.1 Development Environment 10
   7.2 Production Considerations 10
8. Testing and Quality Assurance 10
   8.1 Input Validation Testing 10
   8.2 Model Integration Testing 11
9. Future Technical Enhancements 11
   9.1 Planned Improvements 11
   9.2 Scalability Roadmap 11
10. Conclusion 11

### 1 System Overview

Our phishing website detection system is a modern web application built with Flask, integrating advanced machine learning models for real-time URL risk assessment. The architecture is modular, separating data persistence, business logic, AI processing, and user interface. Users can submit URLs via the web interface or REST API, and receive instant phishing detection results powered by an enhanced ensemble model. The system supports user registration, login, and maintains detection history for long-term tracking. If the enhanced model is unavailable, the system automatically falls back to a standard Gradient Boosting model, ensuring robust and reliable service.

### 2 System Architecture

#### 2.1 Overall Architecture Pattern
The system adopts a three-tier architecture: presentation (Flask + Jinja2 templates), application (business logic, AI inference), and data (SQLAlchemy ORM + SQLite). Both API and web interface share the same business logic and model pipeline, ensuring consistency and maintainability.

#### 2.2 Component Relationships
- `app.py`: Main entry, route management, user session, model loading, API registration.
- `feature.py`: Feature extraction for URLs, supporting 30+ features and sandbox data.
- `enhanced_model.py`: Implements ensemble learning with multiple ML algorithms; falls back to GBDT if needed.
- `models.py`: SQLAlchemy ORM definitions for users and detection history.
- `api.py`: RESTful API endpoints for detection, batch processing, and history.
- `sandbox.py`: Isolated URL access and content analysis for security.
- `forms.py`: WTForms-based input validation and security.

The data flow: user submits URL (web/API) → sandbox isolation (if enabled) → feature extraction → model prediction → result and confidence score returned and stored (if user is authenticated).

| Component          | Primary Function                    | Technologies                    | Dependencies        |
| ------------------ | ----------------------------------- | ------------------------------- | ------------------- |
| Flask App          | Routing, session, API, model mgmt   | Flask, Flask-Login              | All components      |
| Feature Extraction | URL analysis, feature engineering   | Python, BeautifulSoup, requests | Sandbox module      |
| ML Model           | Phishing classification (ensemble)  | scikit-learn, pickle            | Feature vectors     |
| Database Layer     | Data persistence                    | SQLAlchemy, SQLite              | User sessions       |
| API Blueprint      | RESTful API                         | Flask, JSON                     | Flask app, ML model |
| Sandbox Module     | Secure URL access                   | Threading, requests             | Feature extraction  |
| Forms              | Input validation                    | WTForms                         | -                   |

#### 2.3 Database Design
The database uses SQLite for development, with a schema designed for easy migration to production databases. There are two main tables:

| Table            | Field              | Type         | Description                      |
| ---------------- | ------------------ | ------------ | --------------------------------- |
| Users            | id                 | Integer (PK) | Unique user identifier           |
|                  | username           | String(80)   | Unique username                  |
|                  | email              | String(120)  | User email address               |
|                  | password_hash      | String(128)  | Hashed password                  |
|                  | created_at         | DateTime     | Account creation time            |
|                  | last_login         | DateTime     | Last login timestamp             |
| DetectionHistory | id                 | Integer (PK) | Detection record ID              |
|                  | user_id            | Integer (FK) | Reference to Users.id            |
|                  | url                | String(500)  | Analyzed URL                     |
|                  | is_safe            | Boolean      | Safety classification            |
|                  | confidence_score   | Float        | ML model confidence              |
|                  | sandbox_risk_level | String(20)   | Risk level from sandbox analysis  |
|                  | detected_at        | DateTime     | Detection timestamp              |

Passwords are hashed with Werkzeug and salted. Detection history records include sandbox risk level for enhanced security analysis.

### 3 AI Model Integration

#### 3.1 Model Architecture and Selection
The system uses an enhanced ensemble model (Voting/Bagging/Boosting with multiple base classifiers) as the primary phishing detection engine. If the enhanced model is unavailable, it automatically falls back to a standard Gradient Boosting model. Models are trained on labeled phishing and legitimate URLs, and serialized with pickle for fast loading and reproducibility.

#### 3.2 Feature Engineering Process
Feature extraction covers 30+ dimensions, including:
- URL structure: length, IP usage, special characters, subdomains, shortening services
- Domain analysis: registration length, WHOIS, domain age, TLD
- Security/protocol: HTTPS, port, SSL indicators
- Content-based: HTML, JavaScript, forms, external links
Each feature is standardized (typically -1, 0, 1) for model compatibility and interpretability.

| Category          | Features                                                     | Count | Risk Indicators                                       |
| ----------------- | ------------------------------------------------------------ | ----- | ----------------------------------------------------- |
| URL Structure     | URL length, IP usage, special characters, subdomains, shortening services | 8     | Long URLs, IP addresses, excessive subdomains         |
| Domain Analysis   | Registration length, WHOIS data, domain age, TLD analysis    | 6     | Short registration, recent domains, suspicious TLDs   |
| Security Protocol | HTTPS usage, port analysis, SSL indicators                   | 4     | HTTP only, non-standard ports, invalid certificates   |
| Content Analysis  | HTML features, JavaScript detection, form analysis, external links | 12    | Hidden forms, suspicious redirects, malicious scripts |
| Total             | All Features                                                 | 30    | Comprehensive Coverage                                |

#### 3.3 Real-Time Prediction Pipeline
1. URL validation and security checks (including sandbox isolation)
2. Feature extraction (FeatureExtraction class)
3. Feature vector creation (30D array)
4. Model prediction (ensemble or fallback)
5. Confidence score calculation
6. Result formatting and storage (if user is authenticated)
The pipeline is optimized for sub-second response and robust error handling.

#### 3.4 Model Performance and Confidence Scoring
The model outputs probability scores for both phishing and legitimate classes. The system uses the probability of the legitimate class as the confidence score, with a threshold of 0.5. High confidence (>0.8) indicates strong evidence; lower scores suggest caution. Model performance metrics are logged at startup for transparency.

### 4 API Documentation

#### 4.1 API Architecture
The REST API is implemented as a Flask Blueprint, sharing business logic and model pipeline with the web interface. All endpoints return JSON with consistent error handling and status codes. Both anonymous and authenticated usage are supported.

| Endpoint            | Method | Auth Required | Rate Limit | Purpose                |
| ------------------- | ------ | ------------- | ---------- | ---------------------- |
| /api/detect         | POST   | No            | 100/hour   | Single URL detection   |
| /api/batch_detect   | POST   | No            | 10/hour    | Batch URL processing   |
| /api/history        | GET    | Yes           | 1000/hour  | User detection history |
| /api/stats          | GET    | Yes           | 100/hour   | User statistics        |

#### 4.2 Authentication and Session Management
API authentication uses Flask-Login for session management, integrated with the web interface. Users can authenticate via the web and access API endpoints within the same session. Programmatic access maintains session cookies; future versions will support token-based authentication.

#### 4.3 Core API Endpoints
- **POST /api/detect**: Real-time phishing detection for a single URL. Request: `{ "url": "https://example.com" }`. Response: `{ "url": ..., "is_safe": true, "confidence_score": 0.85, "sandbox_risk_level": "low", "detected_at": ... }`
- **POST /api/batch_detect**: Batch detection for up to 50 URLs. Request: `{ "urls": [ ... ] }`. Response: summary and per-URL results, with error handling for failures.
- **GET /api/history**: Authenticated users can retrieve their detection history with pagination.
- **GET /api/stats**: Aggregated statistics for authenticated users.

#### 4.4 Error Handling and Response Codes
API returns meaningful HTTP status codes:
- 200: Success
- 400: Bad request (invalid parameters, malformed JSON)
- 401: Unauthorized (authentication required)
- 500: Server error (processing/model failures)
Error responses include descriptive messages for easier integration.

### 5 Security Implementation

#### 5.1 Input Validation and Sanitization
All user inputs are validated using WTForms, enforcing URL format, length, and preventing injection attacks. Batch detection limits the number of URLs and checks each for validity. Feature extraction enforces timeouts and content size limits for external requests.

#### 5.2 Sandbox Integration
The sandbox module isolates URL access in separate threads, with configurable timeouts, response size limits, and user-agent rotation. This prevents malicious URLs from affecting the main system and provides additional risk analysis (sandbox_risk_level) for each detection.

#### 5.3 Database Security
Passwords are hashed and salted using Werkzeug. SQLAlchemy ORM prevents SQL injection. Flask-Login manages secure sessions. User data is isolated, and all sensitive operations are protected by authentication and authorization checks.

### 6 Performance Considerations
#### 6.1 Response Time Optimization
The system is designed for fast response times through several optimization strategies. The machine learning model is loaded once during application startup and kept in memory for subsequent predictions. Feature extraction is optimized to minimize external network requests while still gathering comprehensive URL analysis data.

Database queries are optimized through proper indexing on frequently accessed columns, and pagination is implemented for endpoints that might return large result sets.

#### Table 5: Performance Benchmarks and Targets
| Metric              | Current Performance | Target        | Measurement Method      |
| ------------------- | ------------------- | ------------- | ----------------------- |
| URL Detection Time  | < 1 second          | < 0.5 seconds | End-to-end timing       |
| API Response Time   | < 2 seconds         | < 1 second    | Server-side measurement |
| Concurrent Users    | 10 users            | 50 users      | Load testing            |
| Model Accuracy      | > 85%               | > 90%         | Validation dataset      |
| Database Query Time | < 100ms             | < 50ms        | SQLAlchemy profiling    |
| Memory Usage        | < 512MB             | < 256MB       | System monitoring       |

#### 6.2 Scalability Design
While our current implementation uses SQLite for simplicity, the database abstraction layer makes migration to production databases straightforward. The modular architecture allows individual components to be scaled independently as traffic grows.

The stateless API design enables horizontal scaling through load balancing, and the separation between the ML model and application logic allows for dedicated model serving infrastructure if needed.

### 7 Deployment Architecture
#### 7.1 Development Environment
The development setup is designed for simplicity and quick iteration. Flask’s development server provides hot reload capabilities, and SQLite eliminates the need for external database setup during development.

Environment configuration is handled through Flask’s configuration system, allowing easy switching between development, testing, and production settings.

#### 7.2 Production Considerations
The application is designed to work with standard Python WSGI servers like Gunicorn for production deployment. Configuration management supports environment variables for sensitive settings like database connections and secret keys.

Static file serving is handled through Flask for development, but the architecture supports CDN integration and dedicated static file servers for production environments.

### 8 Testing and Quality Assurance
#### 8.1 Input Validation Testing
Our form validation system has been tested with various malformed inputs to ensure robust error handling. URL validation includes checks for proper formatting, protocol requirements, and length constraints.

The batch processing functionality includes limits to prevent system abuse and proper error reporting for individual URL failures within larger batches.

#### 8.2 Model Integration Testing
The machine learning pipeline has been tested with known phishing and legitimate URLs to verify prediction accuracy. Error handling ensures graceful degradation when feature extraction encounters unexpected website structures or network issues.

### 9 Future Technical Enhancements
#### 9.1 Planned Improvements
While not included in the current iteration, the modular architecture supports several planned enhancements. API rate limiting and token-based authentication will improve security and enable better usage monitoring.

Enhanced analytics and reporting capabilities can be added through additional database tables and API endpoints without disrupting existing functionality.

#### 9.2 Scalability Roadmap
The current architecture provides a solid foundation for scaling. Future enhancements might include model serving infrastructure for improved performance, caching layers for frequently accessed URLs, and enhanced monitoring and logging capabilities.

Real-time threat intelligence integration could enhance detection capabilities, while maintaining the fast response times that make the system valuable for users.

### 10 Conclusion
This technical implementation demonstrates successful integration of machine learning capabilities with a practical web application. The modular architecture ensures maintainability while the comprehensive API provides flexibility for future integrations.

The system successfully meets all technical requirements for Iteration 1 while establishing a robust foundation for future enhancements. The combination of real-time detection, user management, and programmatic access creates a complete solution that delivers immediate value to users while supporting long-term growth and improvement.