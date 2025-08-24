#importing required libraries

from flask import Flask, request, render_template, flash, redirect, url_for, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
import numpy as np
import pandas as pd
from sklearn import metrics 
import warnings
import pickle
import os
from datetime import datetime
import threading
import time
warnings.filterwarnings('ignore')
from feature import FeatureExtraction
from models import db, User, DetectionHistory
from forms import LoginForm, RegistrationForm, BatchDetectionForm
from api import api
from sandbox import get_sandbox

# Load enhanced model
try:
    print("🚀 加载增强集成模型...")
    with open("pickle/enhanced_model.pkl", "rb") as file:
        enhanced_model_data = pickle.load(file)
        gbc = enhanced_model_data['ensemble_model']
        training_scores = enhanced_model_data['training_scores']
    print("✅ 增强集成模型加载成功!")
    print(f"📊 模型包含 {len(training_scores)} 个基础分类器")
    
    # 显示模型性能
    for name, scores in training_scores.items():
        print(f"  - {name.upper()}: 测试准确率 {scores['test_acc']:.4f}, AUC {scores['auc']:.4f}")
        
except FileNotFoundError:
    print("⚠️ 增强模型不存在，使用原始GradientBoosting模型...")
    with open("pickle/model.pkl", "rb") as file:
        gbc = pickle.load(file)
    print("✅ 原始模型加载成功!")
    
except Exception as e:
    print(f"❌ 模型加载失败: {e}")
    print("🔄 回退到原始模型...")
    with open("pickle/model.pkl", "rb") as file:
        gbc = pickle.load(file)
    print("✅ 原始模型加载成功!")

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'  # Please change to a random string
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///phishing_detection.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db.init_app(app)

# Register API blueprint
app.register_blueprint(api, url_prefix='/api')

# Initialize login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please login to access this page'
login_manager.login_message_category = 'info'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        url = request.form["url"]
        
        # Sandbox isolation
        sandbox = get_sandbox()
        sandbox_result = sandbox.safe_url_access(url)
        
        # Check if URL exists/is accessible
        url_accessible = sandbox_result.get('sandbox_data', {}).get('access_result') == 'success'
        
        # Continue with AI detection
        obj = FeatureExtraction(url, sandbox_data=sandbox_result.get('sandbox_data', {}))
        x = np.array(obj.getFeaturesList()).reshape(1,30) 

        y_pred = gbc.predict(x)[0]
        y_pro_phishing = gbc.predict_proba(x)[0,0]
        y_pro_non_phishing = gbc.predict_proba(x)[0,1]
        
        # Enhanced phishing detection with heuristic rules
        def enhanced_phishing_check(url, features):
            """Advanced heuristic checks for sophisticated phishing patterns"""
            suspicious_score = 0
            domain = obj.domain.lower()
            full_url = url.lower()
            
            # Extract URL components
            try:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                path = parsed.path.lower()
                query = parsed.query.lower()
            except:
                path = ""
                query = ""
            
            # 1. Suspicious TLDs with enhanced weighting
            high_risk_tlds = ['.icu', '.tk', '.ml', '.ga', '.cf', '.pw', '.top', '.win', '.download', '.click']
            medium_risk_tlds = ['.ru', '.cn', '.cc', '.info', '.biz', '.us', '.ws', '.xyz', '.club']
            
            for tld in high_risk_tlds:
                if domain.endswith(tld):
                    suspicious_score += 4  # Increased weight
                    break
            for tld in medium_risk_tlds:
                if domain.endswith(tld):
                    suspicious_score += 2  # Increased weight
                    break
            
            # 2. Financial institutions and major brands (EXPANDED)
            financial_brands = [
                # Global banks
                'paypal', 'visa', 'mastercard', 'amex', 'americanexpress',
                'chase', 'bankofamerica', 'wellsfargo', 'citibank', 'hsbc',
                # Brazilian banks (new addition)
                'bradesco', 'itau', 'santander', 'bb', 'bancodobrasil', 'caixa',
                'sicredi', 'banrisul', 'safra', 'original', 'inter',
                # Other financial
                'nubank', 'picpay', 'mercadopago', 'pagseguro', 'stone'
            ]
            
            major_brands = [
                'amazon', 'google', 'microsoft', 'apple', 'facebook', 'instagram',
                'twitter', 'linkedin', 'netflix', 'spotify', 'adobe', 'steam',
                'ebay', 'allegro', 'alibaba', 'dropbox', 'github', 'yahoo',
                'outlook', 'hotmail', 'gmail', 'whatsapp', 'telegram'
            ]
            
            # Check for brand impersonation with higher penalties
            for brand in financial_brands:
                if brand in domain and not domain.endswith(f'{brand}.com') and not domain.endswith(f'{brand}.com.br'):
                    suspicious_score += 5  # Very high penalty for financial impersonation
                    break
            
            for brand in major_brands:
                if brand in domain and not domain.endswith(f'{brand}.com'):
                    suspicious_score += 4  # High penalty for brand impersonation
                    break
            
            # 3. Financial and security sensitive keywords (NEW)
            financial_keywords = [
                'bank', 'banking', 'login', 'signin', 'account', 'payment', 'billing',
                'credit', 'debit', 'card', 'secure', 'security', 'verify', 'validation',
                'cpf', 'cnpj', 'rg', 'documento', 'dados', 'cadastro', 'conta',
                'cartao', 'credito', 'debito', 'pagamento', 'pix', 'transferencia'
            ]
            
            for keyword in financial_keywords:
                if keyword in domain or keyword in path:
                    suspicious_score += 2
            
            # 4. Suspicious file paths and extensions (ENHANCED)
            suspicious_paths = [
                'admin', 'login', 'signin', 'secure', 'verify', 'update', 'confirm',
                'account', 'billing', 'payment', 'suspended', 'locked', 'security',
                'cpf', 'documento', 'dados', 'cadastro', 'validacao', 'confirmacao',
                'feirao', 'promocao', 'oferta', 'desconto', 'sorteio'
            ]
            
            for susp_path in suspicious_paths:
                if susp_path in path:
                    suspicious_score += 3  # Higher penalty for suspicious paths
            
            # 5. Suspicious file extensions
            suspicious_extensions = ['.php', '.asp', '.jsp', '.cgi']
            for ext in suspicious_extensions:
                if path.endswith(ext):
                    suspicious_score += 1
            
            # 6. Geographic and language anomalies (NEW)
            # Brazilian domains with international brand names (suspicious)
            if '.br' in domain:
                international_brands = ['amazon', 'google', 'microsoft', 'apple', 'paypal']
                for brand in international_brands:
                    if brand in domain and not domain.startswith(f'{brand}.com'):
                        suspicious_score += 3
            
            # 7. Domain structure analysis (ENHANCED)
            domain_parts = domain.split('.')
            
            # Too many subdomains
            if len(domain_parts) > 4:
                suspicious_score += 2
            elif len(domain_parts) > 3:
                suspicious_score += 1
            
            # Numbers in domain
            if any(char.isdigit() for char in domain):
                suspicious_score += 2  # Increased penalty
            
            # Hyphens in domain
            if '-' in domain:
                suspicious_score += 2  # Increased penalty
            
            # Very long domain names
            if len(domain) > 25:
                suspicious_score += 2
            elif len(domain) > 20:
                suspicious_score += 1
            
            # 8. Suspicious character patterns (NEW)
            # Homograph attacks (similar looking characters)
            suspicious_chars = ['0', '1', 'l', 'i', 'o']
            char_count = sum(1 for c in domain if c in suspicious_chars)
            if char_count >= 3:
                suspicious_score += 2
            
            # 9. URL encoding and special characters (NEW)
            if '%' in full_url:  # URL encoding
                suspicious_score += 1
            if any(char in full_url for char in ['@', '&', '=', '?']) and len(query) > 20:
                suspicious_score += 1
            
            # 10. Machine Learning features integration (ENHANCED)
            negative_features = len([x for x in features if x == -1])
            if negative_features >= 10:  # Very suspicious
                suspicious_score += 4
            elif negative_features >= 8:
                suspicious_score += 3
            elif negative_features >= 6:
                suspicious_score += 2
            elif negative_features >= 4:
                suspicious_score += 1
            
            # 11. Domain reputation indicators (NEW)
            # Free hosting services (often used by phishers)
            free_hosting_indicators = [
                'github.io', 'herokuapp.com', 'netlify.app', 'vercel.app',
                'blogspot.com', 'wordpress.com', 'wix.com', 'weebly.com'
            ]
            for hosting in free_hosting_indicators:
                if hosting in domain:
                    suspicious_score += 1
            
            return suspicious_score, negative_features
        
        # Apply enhanced detection
        heuristic_score, neg_features = enhanced_phishing_check(url, obj.getFeaturesList())
        
        # More aggressive adjustment based on heuristic analysis (LOWERED THRESHOLDS)
        detection_details = []
        
        if heuristic_score >= 8:  # Extremely high suspicion (lowered from 6)
            y_pro_phishing = max(y_pro_phishing, 0.95)  # Force 95%+ phishing probability
            y_pro_non_phishing = 1.0 - y_pro_phishing
            detection_details.append(f'Critical threat patterns detected (score: {heuristic_score})')
        elif heuristic_score >= 5:  # Very high suspicion (lowered from 4)
            y_pro_phishing = max(y_pro_phishing, 0.85)  # Force 85%+ phishing probability
            y_pro_non_phishing = 1.0 - y_pro_phishing
            detection_details.append(f'High-risk patterns detected (score: {heuristic_score})')
        elif heuristic_score >= 3:  # High suspicion (lowered from 2)
            y_pro_phishing = max(y_pro_phishing, 0.75)  # Force 75%+ phishing probability
            y_pro_non_phishing = 1.0 - y_pro_phishing
            detection_details.append(f'Multiple suspicious patterns found (score: {heuristic_score})')
        elif heuristic_score >= 1:  # Medium suspicion (new threshold)
            # More aggressive reduction of safety confidence
            if y_pro_non_phishing > 0.7:
                y_pro_non_phishing = min(y_pro_non_phishing, 0.4)  # Cap at 40% (more aggressive)
                y_pro_phishing = 1.0 - y_pro_non_phishing
            detection_details.append(f'Suspicious patterns detected (score: {heuristic_score})')
        
        # Additional check for many negative ML features (ENHANCED)
        if neg_features >= 8:
            detection_details.append(f'ML model flagged {neg_features} critical suspicious features')
            if y_pro_non_phishing > 0.6:
                y_pro_non_phishing = min(y_pro_non_phishing, 0.3)  # Very aggressive cap
                y_pro_phishing = 1.0 - y_pro_non_phishing
        elif neg_features >= 5:
            detection_details.append(f'ML model flagged {neg_features} suspicious features')
            if y_pro_non_phishing > 0.7:
                y_pro_non_phishing = min(y_pro_non_phishing, 0.5)
                y_pro_phishing = 1.0 - y_pro_non_phishing
        
        if detection_details:
            sandbox_result['enhanced_detection'] = ' | '.join(detection_details)
        
        # For non-accessible URLs, ensure they are marked as safe
        if not url_accessible:
            # Override prediction to be safe for non-existent URLs
            y_pro_non_phishing = max(y_pro_non_phishing, 0.85)  # Ensure at least 85% safe
            y_pro_phishing = 1.0 - y_pro_non_phishing
            
            # Add specific message for non-existent URLs
            sandbox_result['url_status'] = 'not_accessible'
            sandbox_result['safety_message'] = 'This URL is inaccessible and has been marked as safe by the system'
        
        # Save detection history (if user is logged in)
        if current_user.is_authenticated:
            detection = DetectionHistory(
                user_id=current_user.id,
                url=url,
                is_safe=(y_pro_non_phishing >= 0.5),
                confidence_score=y_pro_non_phishing,
                sandbox_risk_level=sandbox_result.get('risk_level', 'unknown')
            )
            db.session.add(detection)
            db.session.commit()
        
        return render_template('index.html', 
                             xx=round(y_pro_non_phishing,2), 
                             url=url,
                             sandbox_result=sandbox_result,
                             sandbox_report=sandbox.get_sandbox_report(sandbox_result),
                             url_accessible=url_accessible)
    
    return render_template("index.html", xx=-1)

@app.route("/batch", methods=["GET", "POST"])
def batch_detection():
    form = BatchDetectionForm()
    results = []
    
    if form.validate_on_submit():
        urls_text = form.urls_text.data.strip()
        urls = [url.strip() for url in urls_text.split('\n') if url.strip()]
        
        if len(urls) > 50:
            flash('Maximum 50 URLs can be detected at once', 'error')
            return render_template('batch_detection.html', form=form)
        
        # Batch detection
        for i, url in enumerate(urls):
            try:
                obj = FeatureExtraction(url)
                x = np.array(obj.getFeaturesList()).reshape(1,30)
                
                y_pred = gbc.predict(x)[0]
                y_pro_phishing = gbc.predict_proba(x)[0,0]
                y_pro_non_phishing = gbc.predict_proba(x)[0,1]
                
                result = {
                    'url': url,
                    'is_safe': bool(y_pro_non_phishing >= 0.5),
                    'confidence_score': float(y_pro_non_phishing),
                    'detected_at': datetime.utcnow().isoformat()
                }
                
                # Save detection history (if user is logged in)
                if current_user.is_authenticated:
                    detection = DetectionHistory(
                        user_id=current_user.id,
                        url=url,
                        is_safe=bool(y_pro_non_phishing >= 0.5),
                        confidence_score=float(y_pro_non_phishing)
                    )
                    db.session.add(detection)
                
                results.append(result)
                
                # Add small delay to avoid too fast requests
                time.sleep(0.1)
                
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
        
        flash(f'Batch detection completed! Detected {len(results)} URLs', 'success')
        return render_template('batch_detection.html', form=form, results=results)
    
    return render_template('batch_detection.html', form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember_me.data)
            # Update last login time
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            flash('Login successful!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html', form=form)

@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            email=form.email.data
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please login', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash('Logged out successfully', 'info')
    return redirect(url_for('index'))

@app.route("/profile")
@login_required
def profile():
    # Get user's detection history
    detections = DetectionHistory.query.filter_by(user_id=current_user.id).order_by(DetectionHistory.detected_at.desc()).limit(10).all()
    
    # Calculate statistics
    total_detections = DetectionHistory.query.filter_by(user_id=current_user.id).count()
    safe_count = DetectionHistory.query.filter_by(user_id=current_user.id, is_safe=True).count()
    unsafe_count = DetectionHistory.query.filter_by(user_id=current_user.id, is_safe=False).count()
    
    return render_template('profile.html', 
                         detections=detections,
                         total_detections=total_detections,
                         safe_count=safe_count,
                         unsafe_count=unsafe_count)

# Create database tables
def create_tables():
    with app.app_context():
        db.create_all()
        print("Database tables created")

if __name__ == "__main__":
    create_tables()
    app.run(debug=True)