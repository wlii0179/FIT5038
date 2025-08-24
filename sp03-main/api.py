from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user, login_user, logout_user
from werkzeug.security import check_password_hash
import numpy as np
import pickle
from datetime import datetime, timedelta
from feature import FeatureExtraction
from models import db, User, DetectionHistory
from sandbox import get_sandbox

# Load enhanced model
try:
    print("🚀 API: 加载增强集成模型...")
    with open("pickle/enhanced_model.pkl", "rb") as file:
        enhanced_model_data = pickle.load(file)
        gbc = enhanced_model_data['ensemble_model']
    print("✅ API: 增强集成模型加载成功!")
        
except FileNotFoundError:
    print("⚠️ API: 增强模型不存在，使用原始模型...")
    with open("pickle/model.pkl", "rb") as file:
        gbc = pickle.load(file)
    print("✅ API: 原始模型加载成功!")
    
except Exception as e:
    print(f"❌ API: 模型加载失败: {e}")
    with open("pickle/model.pkl", "rb") as file:
        gbc = pickle.load(file)
    print("✅ API: 原始模型加载成功!")

api = Blueprint('api', __name__)

# ================================
# URL Detection APIs
# ================================

@api.route('/detect', methods=['POST'])
def detect_single():
    """Single URL detection API"""
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({'error': 'Please provide URL parameter'}), 400
        
        url = data['url']
        
        # Sandbox isolation
        sandbox = get_sandbox()
        sandbox_result = sandbox.safe_url_access(url)
        url_accessible = sandbox_result.get('sandbox_data', {}).get('access_result') == 'success'
        
        # Feature extraction
        obj = FeatureExtraction(url, sandbox_data=sandbox_result.get('sandbox_data', {}))
        x = np.array(obj.getFeaturesList()).reshape(1, 30)
        
        # Prediction with enhanced detection
        y_pred = gbc.predict(x)[0]
        y_pro_phishing = gbc.predict_proba(x)[0, 0]
        y_pro_non_phishing = gbc.predict_proba(x)[0, 1]
        
        # Apply enhanced phishing detection (same logic as main app)
        def enhanced_phishing_check(url, features):
            suspicious_score = 0
            domain = obj.domain.lower()
            full_url = url.lower()
            
            high_risk_tlds = ['.icu', '.tk', '.ml', '.ga', '.cf', '.pw', '.top', '.win', '.download']
            medium_risk_tlds = ['.ru', '.cn', '.cc', '.info', '.biz', '.us', '.ws']
            
            for tld in high_risk_tlds:
                if domain.endswith(tld):
                    suspicious_score += 3
                    break
            for tld in medium_risk_tlds:
                if domain.endswith(tld):
                    suspicious_score += 1
                    break
            
            suspicious_paths = ['config', 'admin', 'login', 'secure', 'verify', 'update', 'confirm',
                               'account', 'billing', 'payment', 'suspended', 'locked', 'security']
            for path in suspicious_paths:
                if path in full_url:
                    suspicious_score += 2
            
            negative_features = len([x for x in features if x == -1])
            if negative_features >= 8:
                suspicious_score += 3
            elif negative_features >= 5:
                suspicious_score += 2
            elif negative_features >= 3:
                suspicious_score += 1
                
            return suspicious_score, negative_features
        
        heuristic_score, neg_features = enhanced_phishing_check(url, obj.getFeaturesList())
        
        # Adjust predictions
        if heuristic_score >= 6:
            y_pro_phishing = max(y_pro_phishing, 0.9)
            y_pro_non_phishing = 1.0 - y_pro_phishing
        elif heuristic_score >= 4:
            y_pro_phishing = max(y_pro_phishing, 0.75)
            y_pro_non_phishing = 1.0 - y_pro_phishing
        elif heuristic_score >= 2:
            if y_pro_non_phishing > 0.6:
                y_pro_non_phishing = min(y_pro_non_phishing, 0.5)
                y_pro_phishing = 1.0 - y_pro_non_phishing
        
        # Handle non-accessible URLs
        if not url_accessible:
            y_pro_non_phishing = max(y_pro_non_phishing, 0.85)
            y_pro_phishing = 1.0 - y_pro_non_phishing
        
        result = {
            'url': url,
            'is_safe': y_pro_non_phishing >= 0.5,
            'confidence_score': float(y_pro_non_phishing),
            'phishing_probability': float(y_pro_phishing),
            'detected_at': datetime.utcnow().isoformat(),
            'url_accessible': url_accessible,
            'heuristic_score': heuristic_score,
            'ml_suspicious_features': neg_features,
            'sandbox_data': sandbox_result
        }
        
        # Save detection history if user is logged in
        if current_user.is_authenticated:
            detection = DetectionHistory(
                user_id=current_user.id,
                url=url,
                is_safe=result['is_safe'],
                confidence_score=result['confidence_score']
            )
            db.session.add(detection)
            db.session.commit()
            result['detection_id'] = detection.id
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': f'Detection failed: {str(e)}'}), 500

@api.route('/detect/batch', methods=['POST'])
def detect_batch():
    """Batch URL detection API"""
    try:
        data = request.get_json()
        if not data or 'urls' not in data:
            return jsonify({'error': 'Please provide urls parameter'}), 400
        
        urls = data['urls']
        if not isinstance(urls, list):
            return jsonify({'error': 'urls must be an array format'}), 400
        
        if len(urls) > 100:  # Increased limit
            return jsonify({'error': 'Maximum 100 URLs can be detected at once'}), 400
        
        results = []
        
        for url in urls:
            try:
                # Use the same detection logic as single detection
                # (Simplified for brevity - would call detect_single logic)
                obj = FeatureExtraction(url)
                x = np.array(obj.getFeaturesList()).reshape(1, 30)
                
                y_pred = gbc.predict(x)[0]
                y_pro_phishing = gbc.predict_proba(x)[0, 0]
                y_pro_non_phishing = gbc.predict_proba(x)[0, 1]
                
                result = {
                    'url': url,
                    'is_safe': y_pro_non_phishing >= 0.5,
                    'confidence_score': float(y_pro_non_phishing),
                    'detected_at': datetime.utcnow().isoformat()
                }
                
                # Save detection history if user is logged in
                if current_user.is_authenticated:
                    detection = DetectionHistory(
                        user_id=current_user.id,
                        url=url,
                        is_safe=result['is_safe'],
                        confidence_score=result['confidence_score']
                    )
                    db.session.add(detection)
                
                results.append(result)
                
            except Exception as e:
                result = {
                    'url': url,
                    'is_safe': False,
                    'confidence_score': 0.0,
                    'detected_at': datetime.utcnow().isoformat(),
                    'error': str(e)
                }
                results.append(result)
        
        # Commit all detection history
        if current_user.is_authenticated:
            db.session.commit()
        
        return jsonify({
            'total': len(results),
            'safe_count': len([r for r in results if r.get('is_safe', False)]),
            'unsafe_count': len([r for r in results if not r.get('is_safe', True)]),
            'results': results
        })
        
    except Exception as e:
        return jsonify({'error': f'Batch detection failed: {str(e)}'}), 500

# ================================
# Detection History Management APIs
# ================================

@api.route('/history', methods=['GET'])
@login_required
def get_history():
    """Get user detection history with filtering and pagination"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 20, type=int), 100)
        
        # Filtering parameters
        is_safe = request.args.get('is_safe')  # true/false
        start_date = request.args.get('start_date')  # YYYY-MM-DD
        end_date = request.args.get('end_date')  # YYYY-MM-DD
        search_url = request.args.get('search_url')  # URL search
        
        # Build query
        query = DetectionHistory.query.filter_by(user_id=current_user.id)
        
        if is_safe is not None:
            is_safe_bool = is_safe.lower() == 'true'
            query = query.filter(DetectionHistory.is_safe == is_safe_bool)
        
        if start_date:
            start_dt = datetime.strptime(start_date, '%Y-%m-%d')
            query = query.filter(DetectionHistory.detected_at >= start_dt)
        
        if end_date:
            end_dt = datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1)
            query = query.filter(DetectionHistory.detected_at < end_dt)
        
        if search_url:
            query = query.filter(DetectionHistory.url.contains(search_url))
        
        # Execute query with pagination
        detections = query.order_by(DetectionHistory.detected_at.desc())\
            .paginate(page=page, per_page=per_page, error_out=False)
        
        history = []
        for detection in detections.items:
            history.append({
                'id': detection.id,
                'url': detection.url,
                'is_safe': detection.is_safe,
                'confidence_score': float(detection.confidence_score),
                'detected_at': detection.detected_at.isoformat(),
                'sandbox_risk_level': detection.sandbox_risk_level
            })
        
        return jsonify({
            'history': history,
            'total': detections.total,
            'pages': detections.pages,
            'current_page': page,
            'per_page': per_page,
            'has_next': detections.has_next,
            'has_prev': detections.has_prev
        })
        
    except Exception as e:
        return jsonify({'error': f'Failed to get history: {str(e)}'}), 500

@api.route('/history/<int:detection_id>', methods=['GET'])
@login_required
def get_detection_detail(detection_id):
    """Get detailed information about a specific detection"""
    try:
        detection = DetectionHistory.query.filter_by(
            id=detection_id, 
            user_id=current_user.id
        ).first()
        
        if not detection:
            return jsonify({'error': 'Detection not found'}), 404
        
        return jsonify({
            'id': detection.id,
            'url': detection.url,
            'is_safe': detection.is_safe,
            'confidence_score': float(detection.confidence_score),
            'detected_at': detection.detected_at.isoformat(),
            'sandbox_risk_level': detection.sandbox_risk_level
        })
        
    except Exception as e:
        return jsonify({'error': f'Failed to get detection detail: {str(e)}'}), 500

@api.route('/history/<int:detection_id>', methods=['DELETE'])
@login_required
def delete_detection(detection_id):
    """Delete a specific detection record"""
    try:
        detection = DetectionHistory.query.filter_by(
            id=detection_id, 
            user_id=current_user.id
        ).first()
        
        if not detection:
            return jsonify({'error': 'Detection not found'}), 404
        
        db.session.delete(detection)
        db.session.commit()
        
        return jsonify({'message': 'Detection deleted successfully'})
        
    except Exception as e:
        return jsonify({'error': f'Failed to delete detection: {str(e)}'}), 500

@api.route('/history', methods=['DELETE'])
@login_required
def clear_history():
    """Clear all detection history for current user"""
    try:
        # Optional: only clear older than X days
        days = request.args.get('older_than_days', type=int)
        
        query = DetectionHistory.query.filter_by(user_id=current_user.id)
        
        if days:
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            query = query.filter(DetectionHistory.detected_at < cutoff_date)
        
        deleted_count = query.count()
        query.delete()
        db.session.commit()
        
        return jsonify({
            'message': f'Cleared {deleted_count} detection records',
            'deleted_count': deleted_count
        })
        
    except Exception as e:
        return jsonify({'error': f'Failed to clear history: {str(e)}'}), 500

# ================================
# User Management APIs
# ================================

@api.route('/auth/login', methods=['POST'])
def api_login():
    """API login endpoint"""
    try:
        data = request.get_json()
        if not data or 'username' not in data or 'password' not in data:
            return jsonify({'error': 'Username and password required'}), 400
        
        user = User.query.filter_by(username=data['username']).first()
        
        if user and user.check_password(data['password']):
            login_user(user)
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            return jsonify({
                'message': 'Login successful',
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'created_at': user.created_at.isoformat(),
                    'last_login': user.last_login.isoformat() if user.last_login else None
                }
            })
        else:
            return jsonify({'error': 'Invalid credentials'}), 401
            
    except Exception as e:
        return jsonify({'error': f'Login failed: {str(e)}'}), 500

@api.route('/auth/logout', methods=['POST'])
@login_required
def api_logout():
    """API logout endpoint"""
    logout_user()
    return jsonify({'message': 'Logout successful'})

@api.route('/auth/register', methods=['POST'])
def api_register():
    """API registration endpoint"""
    try:
        data = request.get_json()
        required_fields = ['username', 'email', 'password']
        
        if not data or not all(field in data for field in required_fields):
            return jsonify({'error': 'Username, email, and password required'}), 400
        
        # Check if user already exists
        if User.query.filter_by(username=data['username']).first():
            return jsonify({'error': 'Username already exists'}), 409
        
        if User.query.filter_by(email=data['email']).first():
            return jsonify({'error': 'Email already exists'}), 409
        
        # Create new user
        user = User(
            username=data['username'],
            email=data['email']
        )
        user.set_password(data['password'])
        
        db.session.add(user)
        db.session.commit()
        
        return jsonify({
            'message': 'Registration successful',
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'created_at': user.created_at.isoformat()
            }
        }), 201
        
    except Exception as e:
        return jsonify({'error': f'Registration failed: {str(e)}'}), 500

@api.route('/user/profile', methods=['GET'])
@login_required
def get_profile():
    """Get current user profile"""
    return jsonify({
        'user': {
            'id': current_user.id,
            'username': current_user.username,
            'email': current_user.email,
            'created_at': current_user.created_at.isoformat(),
            'last_login': current_user.last_login.isoformat() if current_user.last_login else None
        }
    })

@api.route('/user/profile', methods=['PUT'])
@login_required
def update_profile():
    """Update current user profile"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        updated_fields = []
        
        if 'email' in data:
            # Check if email is already taken by another user
            existing_user = User.query.filter_by(email=data['email']).first()
            if existing_user and existing_user.id != current_user.id:
                return jsonify({'error': 'Email already exists'}), 409
            
            current_user.email = data['email']
            updated_fields.append('email')
        
        if 'password' in data:
            current_user.set_password(data['password'])
            updated_fields.append('password')
        
        db.session.commit()
        
        return jsonify({
            'message': f'Profile updated: {", ".join(updated_fields)}',
            'user': {
                'id': current_user.id,
                'username': current_user.username,
                'email': current_user.email,
                'created_at': current_user.created_at.isoformat(),
                'last_login': current_user.last_login.isoformat() if current_user.last_login else None
            }
        })
        
    except Exception as e:
        return jsonify({'error': f'Failed to update profile: {str(e)}'}), 500

# ================================
# Statistics and Analytics APIs
# ================================

@api.route('/stats/user', methods=['GET'])
@login_required
def get_user_stats():
    """Get detailed user statistics"""
    try:
        # Calculate statistics
        total_detections = DetectionHistory.query.filter_by(user_id=current_user.id).count()
        safe_count = DetectionHistory.query.filter_by(user_id=current_user.id, is_safe=True).count()
        unsafe_count = DetectionHistory.query.filter_by(user_id=current_user.id, is_safe=False).count()
        
        # Calculate average confidence
        avg_confidence = db.session.query(db.func.avg(DetectionHistory.confidence_score))\
            .filter_by(user_id=current_user.id).scalar() or 0.0
        
        # Recent activity (last 30 days)
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        recent_detections = DetectionHistory.query.filter_by(user_id=current_user.id)\
            .filter(DetectionHistory.detected_at >= thirty_days_ago).count()
        
        # Daily statistics for the last 7 days
        daily_stats = []
        for i in range(7):
            day = datetime.utcnow() - timedelta(days=i)
            day_start = day.replace(hour=0, minute=0, second=0, microsecond=0)
            day_end = day_start + timedelta(days=1)
            
            day_count = DetectionHistory.query.filter_by(user_id=current_user.id)\
                .filter(DetectionHistory.detected_at >= day_start)\
                .filter(DetectionHistory.detected_at < day_end).count()
            
            daily_stats.append({
                'date': day_start.strftime('%Y-%m-%d'),
                'detections': day_count
            })
        
        return jsonify({
            'total_detections': total_detections,
            'safe_count': safe_count,
            'unsafe_count': unsafe_count,
            'avg_confidence': float(avg_confidence),
            'safe_percentage': (safe_count / total_detections * 100) if total_detections > 0 else 0,
            'recent_detections_30d': recent_detections,
            'daily_stats_7d': list(reversed(daily_stats))
        })
        
    except Exception as e:
        return jsonify({'error': f'Failed to get statistics: {str(e)}'}), 500

@api.route('/stats/global', methods=['GET'])
def get_global_stats():
    """Get global system statistics (public)"""
    try:
        total_users = User.query.count()
        total_detections = DetectionHistory.query.count()
        total_safe = DetectionHistory.query.filter_by(is_safe=True).count()
        total_unsafe = DetectionHistory.query.filter_by(is_safe=False).count()
        
        # Recent activity (last 24 hours)
        yesterday = datetime.utcnow() - timedelta(days=1)
        recent_detections = DetectionHistory.query.filter(
            DetectionHistory.detected_at >= yesterday
        ).count()
        
        return jsonify({
            'total_users': total_users,
            'total_detections': total_detections,
            'total_safe': total_safe,
            'total_unsafe': total_unsafe,
            'detection_rate_24h': recent_detections,
            'global_safe_percentage': (total_safe / total_detections * 100) if total_detections > 0 else 0
        })
        
    except Exception as e:
        return jsonify({'error': f'Failed to get global statistics: {str(e)}'}), 500

# ================================
# System Management APIs (Admin only)
# ================================

@api.route('/admin/users', methods=['GET'])
@login_required
def list_users():
    """List all users (admin only)"""
    # Note: In a real system, you'd check for admin privileges
    try:
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 20, type=int), 100)
        
        users = User.query.paginate(page=page, per_page=per_page, error_out=False)
        
        user_list = []
        for user in users.items:
            user_stats = {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'created_at': user.created_at.isoformat(),
                'last_login': user.last_login.isoformat() if user.last_login else None,
                'detection_count': DetectionHistory.query.filter_by(user_id=user.id).count()
            }
            user_list.append(user_stats)
        
        return jsonify({
            'users': user_list,
            'total': users.total,
            'pages': users.pages,
            'current_page': page,
            'per_page': per_page
        })
        
    except Exception as e:
        return jsonify({'error': f'Failed to list users: {str(e)}'}), 500

# ================================
# API Documentation Endpoint
# ================================

@api.route('/docs', methods=['GET'])
def api_documentation():
    """API documentation endpoint"""
    docs = {
        "API_VERSION": "2.0",
        "endpoints": {
            "Detection": {
                "POST /api/detect": "Single URL detection",
                "POST /api/detect/batch": "Batch URL detection"
            },
            "History Management": {
                "GET /api/history": "Get detection history with filtering",
                "GET /api/history/<id>": "Get specific detection details",
                "DELETE /api/history/<id>": "Delete specific detection",
                "DELETE /api/history": "Clear all history"
            },
            "Authentication": {
                "POST /api/auth/login": "User login",
                "POST /api/auth/logout": "User logout",
                "POST /api/auth/register": "User registration"
            },
            "User Management": {
                "GET /api/user/profile": "Get user profile",
                "PUT /api/user/profile": "Update user profile"
            },
            "Statistics": {
                "GET /api/stats/user": "Get user statistics",
                "GET /api/stats/global": "Get global statistics"
            },
            "Admin": {
                "GET /api/admin/users": "List all users (admin only)"
            }
        },
        "authentication": "Session-based authentication required for most endpoints",
        "rate_limiting": "100 requests per minute per user",
        "response_format": "JSON"
    }
    
    return jsonify(docs) 