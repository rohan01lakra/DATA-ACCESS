from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    session,
    redirect,
    url_for,
    send_file,
)
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os
from werkzeug.security import generate_password_hash, check_password_hash
# from utils.pdf_generator import generate_firewall_request_pdf
from functools import wraps
from utils.pdf_generator import generate_firewall_request_pdf, generate_ip_request_pdf
from dotenv import load_dotenv

import tempfile

load_dotenv()

app = Flask(__name__)

# app.config["SECRET_KEY"] = (
#     "ybe8920e4e2e25f4e6654970f9148dbadc07b056795473592a58c92e09a67aea3"
# )
# app.config["SQLALCHEMY_DATABASE_URI"] = (
#     "postgresql://postgres:12345@localhost:5432/firewall_portal"
# )
# app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# db = SQLAlchemy(app)

app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")

app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL")

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# Role hierarchy for approval workflow
ROLES = [
    "Super Admin",
    "Requester",
    "Team Lead",
    "Department Head",
    "Security Auditor",
    "ITP Vertical Head",
    "Solution Administrator",
]

# Teams list - NEW
TEAMS = [
    "DC Infra",
    "VPN",
    "Backup",
    "UIDAI (Aadhaar)",
    "E-Mail",
    "Security (SOC)",
    "E-Office",
    "Customer-PMT",
]


# Database Models
class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)  # stored as hashed password
    role = db.Column(db.String(50), nullable=False)
    team = db.Column(db.String(50), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    requests = db.relationship(
        "FirewallRequest",
        backref="requester",
        lazy=True,
        foreign_keys="FirewallRequest.user_id",
    )

class FirewallRequest(db.Model):
    __tablename__ = "firewall_requests"
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.String(50), unique=True, nullable=False)
    ticket_title = db.Column(db.String(200), nullable=False)
    customer_department = db.Column(db.String(100), nullable=False)
    rule_type = db.Column(db.String(20), nullable=False)
    source_ip = db.Column(db.Text, nullable=False)
    destination_ip = db.Column(db.Text, nullable=False)
    destination_ports = db.Column(db.String(200), nullable=False)
    is_nat_involved = db.Column(db.String(10), nullable=False)
    geo_fencing = db.Column(db.Text)
    access_type = db.Column(db.String(20), default="Temporary", nullable=False)
    service_start_date = db.Column(db.Date)
    service_end_date = db.Column(db.Date)
    purpose = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(50), default="Pending")
    current_approver_role = db.Column(db.String(50))
    submitted_to_role = db.Column(db.String(50), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )
    # approval_history = db.relationship(
    #     "ApprovalHistory", backref="request", lazy=True, cascade="all, delete-orphan"
    # )
    user = db.relationship("User", backref="firewall_requests", foreign_keys=[user_id])

with app.app_context():
    existing = User.query.filter_by(username="superadmin").first()
    if not existing:
        user = User(
            username="superadmin",
            email="superadmin@example.com",
            role="Super Admin",
            team=None,
        )
        user.set_password("Admin@123")
        db.session.add(user)
        db.session.commit()
        print("Super Admin created successfully")
    else:
        print("Super Admin already exists")

class IPRequest(db.Model):
    __tablename__ = "ip_requests"
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.String(50), unique=True, nullable=False)
    rf_number = db.Column(db.String(100), nullable=False)
    subnet_count = db.Column(db.Integer, nullable=False, default=1)
    subnets = db.Column(db.Text, nullable=False)
    request_type = db.Column(db.String(20), nullable=False)
    owner_name = db.Column(db.String(100))  # NEW
    owner_email = db.Column(db.String(100))
    owner_mobile = db.Column(db.String(20))
    marketing_spoc_name = db.Column(db.String(100))  # NEW
    marketing_spoc_email = db.Column(db.String(100))
    marketing_spoc_mobile = db.Column(db.String(20))
    customer_spoc_name = db.Column(db.String(100))
    customer_spoc_email = db.Column(db.String(100))
    customer_spoc_mobile = db.Column(db.String(20))
    purpose = db.Column(db.Text, nullable=True)  # NEW FIELD
    status = db.Column(db.String(50), default="Pending")
    submitted_to_role = db.Column(db.String(50), nullable=False)
    current_approver_role = db.Column(db.String(50))
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # approval_history = db.relationship(
    #     "IPApprovalHistory",
    #     backref="ip_request",
    #     lazy=True,
    #     cascade="all, delete-orphan",
    # )

    # NEW: add this relationship
    user = db.relationship("User", backref="ip_requests", foreign_keys=[user_id])




class IPApprovalHistory(db.Model):
    __tablename__ = "ip_approval_history"

    id = db.Column(db.Integer, primary_key=True)
    ip_request_id = db.Column(
        db.Integer, db.ForeignKey("ip_requests.id"), nullable=False
    )

    approver_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    approver_role = db.Column(db.String(50), nullable=False)
    action = db.Column(db.String(20), nullable=False)  # Submitted / Approved / Rejected / Forwarded
    comments = db.Column(db.Text)
    forwarded_to_role = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    approver = db.relationship("User", foreign_keys=[approver_id])



class ApprovalHistory(db.Model):
    __tablename__ = "approval_history"
    id = db.Column(db.Integer, primary_key=True)
    request_id = db.Column(
        db.Integer, db.ForeignKey("firewall_requests.id"), nullable=False
    )
    approver_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    approver_role = db.Column(db.String(50), nullable=False)
    action = db.Column(db.String(20), nullable=False)
    comments = db.Column(db.Text)
    forwarded_to_role = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    approver = db.relationship("User", foreign_keys=[approver_id])

FirewallRequest.approval_history = db.relationship(
    "ApprovalHistory",
    backref="request",
    lazy=True,
    cascade="all, delete-orphan"
)

IPRequest.approval_history = db.relationship(
    "IPApprovalHistory",
    backref="ip_request",
    lazy=True,
    cascade="all, delete-orphan"
)

def super_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))

        user = User.query.get(session['user_id'])
        if not user or user.role != 'Super Admin':
            flash('Access denied. Super Admin only.', 'error')
            return redirect(url_for('dashboard'))

        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route("/")
def index():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return redirect(url_for("dashboard"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    data = request.json or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    user = User.query.filter_by(username=username).first()

    if not user:
        return jsonify({"success": False, "message": "Invalid credentials"}), 401

   

    if user.check_password(password):
        session["user_id"] = user.id
        session["username"] = user.username
        session["role"] = user.role
        session["team"] = user.team
        return jsonify({"success": True, "message": "Login successful"}), 200

    return jsonify({"success": False, "message": "Invalid credentials"}), 
    

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        allowed_roles = [r for r in ROLES if r != "Super Admin"]
        return render_template("register.html", roles=allowed_roles, teams=TEAMS)

    data = request.json or {}
    username = data.get("username", "").strip()
    email = data.get("email", "").strip()
    password = data.get("password", "").strip()
    role = data.get("role", "").strip()
    team = data.get("team")
    mobile = data.get("mobile", "").strip() if data.get("mobile") else None

    if not all([username, email, password, role]):
        return jsonify({"success": False, "message": "All fields are required"}), 400

    if role == "Super Admin":
        return jsonify(
            {"success": False, "message": "Super Admin cannot be created from registration"}
        ), 403

    if role in ["Requester", "Team Lead"] and not team:
        return jsonify(
            {
                "success": False,
                "message": "Team selection is required for Requester and Team Lead roles",
            }
        ), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"success": False, "message": "Username already exists"}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({"success": False, "message": "Email already exists"}), 400

    new_user = User(
        username=username,
        email=email,
        role=role,
        team=team if role in ["Requester", "Team Lead"] else None,
        mobile=mobile,
        
    )
    new_user.set_password(password)

    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify(
            {"success": True, "message": "Registration successful! Please login."}
        ), 201
    except Exception:
        db.session.rollback()
        return jsonify(
            {"success": False, "message": "Registration failed. Please try again."}
        ), 500


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/admin/users")
@super_admin_required
def admin_users():
    users = User.query.order_by(User.created_at.desc()).all()
    allowed_roles = [r for r in ROLES if r != "Super Admin"]
    return render_template(
        "admin_users.html",
        users=users,
        roles=allowed_roles,
        teams=TEAMS,
    )

@app.route('/api/admin/users')
@super_admin_required
def api_admin_users():
    users = User.query.order_by(User.created_at.desc()).all()

    users_data = []
    for user in users:
        users_data.append({
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "team": user.team,
            "created_at": user.created_at.strftime('%Y-%m-%d %H:%M') if user.created_at else ''
        })

    return jsonify({"success": True, "users": users_data})

@app.route("/admin/users/update/<int:user_id>", methods=["POST"])
@super_admin_required
def update_user(user_id):
    user = User.query.get(user_id)
    if not user:
        flash("User not found", "error")
        return redirect(url_for("admin_users"))

    username = request.form.get("username", "").strip()
    email = request.form.get("email", "").strip()
    role = request.form.get("role", "").strip()
    team = request.form.get("team", "").strip()

    if not all([username, email, role]):
        flash("Username, email and role are required", "error")
        return redirect(url_for("admin_users"))

    existing_username = User.query.filter(User.username == username, User.id != user_id).first()
    if existing_username:
        flash("Username already exists", "error")
        return redirect(url_for("admin_users"))

    existing_email = User.query.filter(User.email == email, User.id != user_id).first()
    if existing_email:
        flash("Email already exists", "error")
        return redirect(url_for("admin_users"))

    if role in ["Requester", "Team Lead"] and not team:
        flash("Team selection is required for Requester and Team Lead roles", "error")
        return redirect(url_for("admin_users"))

    user.username = username
    user.email = email
    user.role = role
    user.team = team if role in ["Requester", "Team Lead"] else None

    try:
        db.session.commit()
        flash("User updated successfully", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Failed to update user: {str(e)}", "error")

    return redirect(url_for("admin_users"))
    
@app.route("/admin/users/reset-password/<int:user_id>", methods=["POST"])
@super_admin_required
def reset_user_password(user_id):
    user = User.query.get(user_id)
    if not user:
        flash("User not found", "error")
        return redirect(url_for("admin_users"))

    new_password = request.form.get("new_password", "").strip()

    if not new_password:
        flash("New password is required", "error")
        return redirect(url_for("admin_users"))

    if len(new_password) < 6:
        flash("Password must be at least 6 characters long", "error")
        return redirect(url_for("admin_users"))

    user.set_password(new_password)

    try:
        db.session.commit()
        flash("Password updated successfully", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Failed to update password: {str(e)}", "error")

    return redirect(url_for("admin_users"))

    

@app.route("/admin/users/delete/<int:user_id>", methods=["POST"])
@super_admin_required
def delete_user(user_id):
    user = User.query.get(user_id)
    if not user:
        flash("User not found", "error")
        return redirect(url_for("admin_users"))

    if user.id == session.get("user_id"):
        flash("You cannot delete your own account", "error")
        return redirect(url_for("admin_users"))

    linked_firewall_requests = FirewallRequest.query.filter_by(user_id=user.id).count()
    linked_ip_requests = IPRequest.query.filter_by(user_id=user.id).count()

    if linked_firewall_requests > 0 or linked_ip_requests > 0:
        flash("User cannot be deleted because requests are linked.", "error")
        return redirect(url_for("admin_users"))

    try:
        db.session.delete(user)
        db.session.commit()
        flash("User deleted successfully", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Failed to delete user: {str(e)}", "error")

    return redirect(url_for("admin_users"))

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    user = User.query.get(session["user_id"])
    if not user:
        session.clear()
        return redirect(url_for("login"))

    if "role" not in session or not session["role"]:
        session["role"] = user.role if user.role else "Requester"

    # Show ALL requests for everyone on dashboard
    total_requests = FirewallRequest.query.count()
    pending = FirewallRequest.query.filter_by(status="Pending").count()
    approved = FirewallRequest.query.filter_by(status="Approved").count()
    rejected = FirewallRequest.query.filter_by(status="Rejected").count()

    # Show all recent requests (not filtered by user)
    recent_requests = (
        FirewallRequest.query.order_by(FirewallRequest.created_at.desc()).limit(5).all()
    )

    # NEW: IP stats (optional)
    ip_total = IPRequest.query.count()
    ip_pending = IPRequest.query.filter_by(status="Pending").count()
    ip_approved = IPRequest.query.filter_by(status="Approved").count()
    ip_rejected = IPRequest.query.filter_by(status="Rejected").count()

    ip_recent = (
       IPRequest.query.order_by(IPRequest.created_at.desc()).limit(5).all()
    )

    stats = {
    "total": total_requests,
    "pending": pending,
    "approved": approved,
    "rejected": rejected,
    "ip_total": ip_total,
    "ip_pending": ip_pending,
    "ip_approved": ip_approved,
    "ip_rejected": ip_rejected,
}

    return render_template(
    "dashboard.html",
    user=user,
    stats=stats,
    recent_requests=recent_requests,
    ip_recent_requests=ip_recent,
)


@app.route("/new-request")
def new_request():
    if "user_id" not in session:
        return redirect(url_for("login"))

    user = User.query.get(session["user_id"])
    if not user:
        session.clear()
        return redirect(url_for("login"))

    return render_template("new_request.html")


@app.route("/api/submit-request", methods=["POST"])
def submit_request():
    if "user_id" not in session:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    user = User.query.get(session["user_id"])
    if not user:
        return jsonify({"success": False, "message": "User not found"}), 401

    data = request.get_json()

    # Enforce Team Lead submission for requesters
    if user.role == "Requester" or not user.role:
        submitted_to_role = "Team Lead"
    else:
        submitted_to_role = data.get("submitted_to_role", "Team Lead")

    if not submitted_to_role:
        return jsonify({"success": False, "message": "Invalid submission role"}), 400

    # Generate ticket ID
    ticket_count = FirewallRequest.query.count() + 1
    ticket_id = f"FW{datetime.now().strftime('%Y%m%d')}{ticket_count:04d}"

    # Get access type
    access_type = data.get("access_type", "Temporary")

    # Parse dates only if temporary access
    if access_type == "Temporary":
        start_date = (
            datetime.strptime(data["service_start_date"], "%Y-%m-%d").date()
            if data.get("service_start_date")
            else None
        )
        end_date = (
            datetime.strptime(data["service_end_date"], "%Y-%m-%d").date()
            if data.get("service_end_date")
            else None
        )
    else:
        start_date = None
        end_date = None

    new_request = FirewallRequest(
        ticket_id=ticket_id,
        ticket_title=data["ticket_title"],
        customer_department=data["customer_department"],
        rule_type=data["rule_type"],
        source_ip=data["source_ip"],
        destination_ip=data["destination_ip"],
        destination_ports=data["destination_ports"],
        is_nat_involved=data["is_nat_involved"],
        geo_fencing=data.get("geo_fencing", ""),
        access_type=access_type,
        service_start_date=start_date,
        service_end_date=end_date,
        purpose=data["purpose"],
        submitted_to_role=submitted_to_role,
        current_approver_role=submitted_to_role,
        user_id=session["user_id"],
    )

    db.session.add(new_request)
    db.session.commit()

    # Create initial approval history entry
    history_entry = ApprovalHistory(
        request_id=new_request.id,
        approver_id=session["user_id"],
        approver_role=session.get("role", "Requester"),
        action="Submitted",
        forwarded_to_role=submitted_to_role,
        comments=f"Request submitted to {submitted_to_role}",
    )
    db.session.add(history_entry)
    db.session.commit()

    return jsonify(
        {
            "success": True,
            "message": "Request submitted successfully to Team Lead",
            "ticket_id": ticket_id,
        }
    )


@app.route("/api/requests")
def get_requests():
    if "user_id" not in session:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    user = User.query.get(session["user_id"])
    if not user:
        return jsonify({"success": False, "message": "User not found"}), 404

    # Show ALL requests for everyone
    requests = FirewallRequest.query.order_by(FirewallRequest.created_at.desc()).all()

    requests_data = [
        {
            "id": req.id,
            "ticket_id": req.ticket_id,
            "ticket_title": req.ticket_title,
            "rule_type": req.rule_type,
            "status": req.status,
            "created_at": req.created_at.strftime("%Y-%m-%d %H:%M"),
            "customer_department": req.customer_department,
            "current_approver_role": req.current_approver_role,
            "requester": (
                req.user.username if req.user else "Unknown"
            ),  # Add requester name
        }
        for req in requests
    ]

    return jsonify({"success": True, "requests": requests_data})


@app.route("/api/request/<int:request_id>")
def get_request_detail(request_id):
    if "user_id" not in session:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    req = FirewallRequest.query.get(request_id)

    if not req:
        return jsonify({"success": False, "message": "Request not found"}), 404

    request_data = {
        "id": req.id,
        "ticket_id": req.ticket_id,
        "ticket_title": req.ticket_title,
        "customer_department": req.customer_department,
        "rule_type": req.rule_type,
        "source_ip": req.source_ip,
        "destination_ip": req.destination_ip,
        "destination_ports": req.destination_ports,
        "is_nat_involved": req.is_nat_involved,
        "geo_fencing": req.geo_fencing,
        "access_type": req.access_type,
        "service_start_date": (
            req.service_start_date.strftime("%Y-%m-%d")
            if req.service_start_date
            else ""
        ),
        "service_end_date": (
            req.service_end_date.strftime("%Y-%m-%d") if req.service_end_date else ""
        ),
        "purpose": req.purpose,
        "status": req.status,
        "current_approver_role": req.current_approver_role,
        "submitted_to_role": req.submitted_to_role,
        "created_at": req.created_at.strftime("%Y-%m-%d %H:%M"),
        "requester_name": req.user.username if req.user else "Unknown",
    }

    # Get approval history
    history = (
        ApprovalHistory.query.filter_by(request_id=request_id)
        .order_by(ApprovalHistory.created_at.asc())
        .all()
    )

    history_data = [
        {
            "approver_name": h.approver.username if h.approver else "System",
            "approver_role": h.approver_role,
            "action": h.action,
            "comments": h.comments,
            "forwarded_to_role": h.forwarded_to_role,
            "created_at": h.created_at.strftime("%Y-%m-%d %H:%M"),
        }
        for h in history
    ]

    request_data["approval_history"] = history_data

    return jsonify({"success": True, "request": request_data})


@app.route("/api/search-ticket/<ticket_id>")
def search_ticket(ticket_id):
    """Enhanced route with complete role hierarchy and skipped role detection"""
    if "user_id" not in session:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    req = FirewallRequest.query.filter_by(ticket_id=ticket_id).first()

    if not req:
        return jsonify({"success": False, "message": "Ticket not found"}), 404

    # Check if user has access to this ticket
    # user = User.query.get(session["user_id"])
    # if req.user_id != session["user_id"] and user.role == "Requester":
    #     return jsonify({"success": False, "message": "Access denied"}), 403

    # Get approval history
    history = (
        ApprovalHistory.query.filter_by(request_id=req.id)
        .order_by(ApprovalHistory.created_at.asc())
        .all()
    )

    request_data = {
        "id": req.id,
        "ticket_id": req.ticket_id,
        "ticket_title": req.ticket_title,
        "customer_department": req.customer_department,
        "rule_type": req.rule_type,
        "status": req.status,
        "current_approver_role": req.current_approver_role,
        "submitted_to_role": req.submitted_to_role,
        "created_at": req.created_at.strftime("%Y-%m-%d %H:%M"),
        "requester_name": req.user.username if req.user else "Unknown",
    }

    history_data = [
        {
            "approver_name": h.approver.username if h.approver else "System",
            "approver_role": h.approver_role,
            "action": h.action,
            "comments": h.comments,
            "forwarded_to_role": h.forwarded_to_role,
            "created_at": h.created_at.strftime("%Y-%m-%d %H:%M"),
        }
        for h in history
    ]

    # Build complete approval flow with all roles in hierarchy
    complete_hierarchy = [
        "Team Lead",
        "Department Head",
        "Security Auditor",
        "ITP Vertical Head",
        "Solution Administrator",
    ]

    # Track which roles were actually involved
    involved_roles = set()
    for h in history:
        if h.action not in ["Submitted"]:
            involved_roles.add(h.approver_role)

    # Add current pending role
    if req.current_approver_role:
        involved_roles.add(req.current_approver_role)

    # Build flow stages
    flow_stages = []

    # Add requester/submitted stage first
    submitted_history = next((h for h in history if h.action == "Submitted"), None)
    flow_stages.append(
        {
            "role": "Requester",
            "status": "submitted",
            "approver": (
                submitted_history.approver.username
                if submitted_history and submitted_history.approver
                else req.user.username
            ),
            "comments": (
                submitted_history.comments
                if submitted_history
                else f"Request submitted to {req.submitted_to_role}"
            ),
            "date": (
                submitted_history.created_at.strftime("%Y-%m-%d %H:%M")
                if submitted_history
                else req.created_at.strftime("%Y-%m-%d %H:%M")
            ),
            "skipped": False,
        }
    )

    # Process each role in the complete hierarchy
    for role in complete_hierarchy:
        role_history = next(
            (
                h
                for h in history
                if h.approver_role == role and h.action not in ["Submitted"]
            ),
            None,
        )

        if role_history:
            flow_stages.append(
                {
                    "role": role,
                    "status": role_history.action.lower(),
                    "approver": (
                        role_history.approver.username
                        if role_history.approver
                        else "Unknown"
                    ),
                    "comments": role_history.comments,
                    "date": role_history.created_at.strftime("%Y-%m-%d %H:%M"),
                    "skipped": False,
                }
            )
        elif role == req.current_approver_role:
            flow_stages.append(
                {
                    "role": role,
                    "status": "pending",
                    "approver": None,
                    "comments": "Awaiting approval",
                    "date": None,
                    "skipped": False,
                }
            )
        elif role in involved_roles:
            pass
        else:
            role_index = complete_hierarchy.index(role)
            workflow_moved_past = False
            for higher_role in complete_hierarchy[role_index + 1 :]:
                if higher_role in involved_roles:
                    workflow_moved_past = True
                    break

            if workflow_moved_past:
                flow_stages.append(
                    {
                        "role": role,
                        "status": "skipped",
                        "approver": None,
                        "comments": "Skipped in approval workflow",
                        "date": None,
                        "skipped": True,
                    }
                )

    request_data["approval_flow"] = flow_stages
    request_data["approval_history"] = history_data

    return jsonify({"success": True, "request": request_data})


# @app.route("/api/approve-request/<int:request_id>", methods=["POST"])
# def approve_request(request_id):
#     if "user_id" not in session:
#         return jsonify({"success": False, "message": "Unauthorized"}), 401

#     user = User.query.get(session["user_id"])
#     if not user:
#         return jsonify({"success": False, "message": "User not found"}), 404

#     req = FirewallRequest.query.get(request_id)

#     if not req:
#         return jsonify({"success": False, "message": "Request not found"}), 404

#     if req.current_approver_role != user.role:
#         return (
#             jsonify(
#                 {
#                     "success": False,
#                     "message": "You are not authorized to approve this request",
#                 }
#             ),
#             403,
#         )

#     data = request.get_json()
#     action = data.get("action")
#     comments = data.get("comments", "")
#     forward_to_role = data.get("forward_to_role")

#     if action == "approve":
#         req.status = "Approved"
#         req.current_approver_role = None
#         history_action = "Approved"
#     elif action == "reject":
#         req.status = "Rejected"
#         req.current_approver_role = None
#         history_action = "Rejected"
#     elif action == "forward" and forward_to_role:
#         req.current_approver_role = forward_to_role
#         history_action = "Forwarded"
#     else:
#         return jsonify({"success": False, "message": "Invalid action"}), 400

#     req.updated_at = datetime.utcnow()

#     # Create approval history entry
#     history_entry = ApprovalHistory(
#         request_id=request_id,
#         approver_id=user.id,
#         approver_role=user.role,
#         action=history_action,
#         comments=comments,
#         forwarded_to_role=forward_to_role,
#     )

#     db.session.add(history_entry)
#     db.session.commit()

#     return jsonify({"success": True, "message": f"Request {action}d successfully"})

@app.route("/approvals")
def approvals():
    if "user_id" not in session:
        return redirect(url_for("login"))

    user = User.query.get(session["user_id"])
    team_filter = request.args.get("team", None)

    # Firewall pending
    fw_query = FirewallRequest.query.filter_by(
        current_approver_role=user.role, status="Pending"
    )
    if user.role == "Team Lead" and team_filter:
        fw_query = fw_query.join(User, FirewallRequest.user_id == User.id).filter(
            User.team == team_filter
        )
    pending_fw = fw_query.order_by(FirewallRequest.created_at.desc()).all()

    # IP pending
    ip_query = IPRequest.query.filter_by(
        current_approver_role=user.role, status="Pending"
    )
    if user.role == "Team Lead" and team_filter:
        ip_query = ip_query.join(User, IPRequest.user_id == User.id).filter(
            User.team == team_filter
        )
    pending_ip = ip_query.order_by(IPRequest.created_at.desc()).all()

    return render_template(
        "approvals.html",
        requests=pending_fw,
        ip_requests=pending_ip,
        user=user,
        teams=TEAMS,
        selected_team=team_filter,
    )


@app.route("/approve_request", methods=["POST"])
def approve_request():
    """Handle approve and reject actions"""
    if "user_id" not in session:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    user = User.query.get(session["user_id"])
    if not user:
        return jsonify({"success": False, "message": "User not found"}), 404

    data = request.json
    request_id = data.get("request_id")
    action = data.get("action")
    comments = data.get("comments", "")

    fw_request = FirewallRequest.query.get(request_id)
    if not fw_request:
        return jsonify({"success": False, "message": "Request not found"}), 404

    # Check authorization
    if fw_request.current_approver_role != user.role:
        return (
            jsonify(
                {
                    "success": False,
                    "message": "You are not authorized to approve this request",
                }
            ),
            403,
        )

    # Handle approve action - send directly to Solution Administrator
    if action == "approve":
        fw_request.current_approver_role = "Solution Administrator"
        history_action = "Approved"

        # If already at Solution Administrator, mark as complete
        if user.role == "Solution Administrator":
            fw_request.status = "Approved"
            fw_request.current_approver_role = None
            history_action = "Approved (Final)"

    # Handle reject action
    elif action == "reject":
        fw_request.status = "Rejected"
        fw_request.current_approver_role = None
        history_action = "Rejected"

    else:
        return jsonify({"success": False, "message": "Invalid action"}), 400

    fw_request.updated_at = datetime.utcnow()

    # Create approval history entry
    history_entry = ApprovalHistory(
        request_id=request_id,
        approver_id=user.id,
        approver_role=user.role,
        action=history_action,
        comments=comments,
        forwarded_to_role=(
            "Solution Administrator"
            if action == "approve" and user.role != "Solution Administrator"
            else None
        ),
    )

    try:
        db.session.add(history_entry)
        db.session.commit()

        if action == "approve":
            if user.role == "Solution Administrator":
                message = "Request approved and completed successfully"
            else:
                message = "Request approved and sent to Solution Administrator"
        else:
            message = "Request rejected successfully"

        return jsonify({"success": True, "message": message}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "message": f"Action failed: {str(e)}"}), 500


@app.route("/forward_request", methods=["POST"])
def forward_request():
    """Handle forward action"""
    if "user_id" not in session:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    data = request.json
    request_id = data.get("request_id")
    forward_to = data.get("forward_to")
    comments = data.get("comments", "")

    fw_request = FirewallRequest.query.get(request_id)
    if not fw_request:
        return jsonify({"success": False, "message": "Request not found"}), 404

    user = User.query.get(session["user_id"])

    # Update request with new approver
    fw_request.current_approver_role = forward_to
    fw_request.updated_at = datetime.utcnow()

    # Add to approval history
    approval = ApprovalHistory(
        request_id=request_id,
        approver_id=user.id,
        approver_role=user.role,
        action="Forwarded",
        comments=comments,
        forwarded_to_role=forward_to,
    )

    try:
        db.session.add(approval)
        db.session.commit()
        return (
            jsonify({"success": True, "message": f"Request forwarded to {forward_to}"}),
            200,
        )
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "message": f"Forward failed: {str(e)}"}), 500


@app.route("/get_request/<int:request_id>")
def get_request(request_id):
    """Get detailed request information for view details modal"""
    if "user_id" not in session:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    try:
        req = FirewallRequest.query.get(request_id)
        if not req:
            return jsonify({"success": False, "message": "Request not found"}), 404

        # Build request data dictionary
        request_data = {
            "id": req.id,
            "ticket_id": req.ticket_id,
            "ticket_title": req.ticket_title,
            "customer_department": req.customer_department,
            "rule_type": req.rule_type,
            "source_ip": req.source_ip,
            "destination_ip": req.destination_ip,
            "port": req.destination_ports,
            "protocol": "TCP/UDP",
            "is_nat_involved": (
                req.is_nat_involved if hasattr(req, "is_nat_involved") else False
            ),
            "geo_fencing": req.geo_fencing if hasattr(req, "geo_fencing") else None,
            "access_type": req.access_type if hasattr(req, "access_type") else None,
            "service_start_date": (
                req.service_start_date.strftime("%Y-%m-%d")
                if hasattr(req, "service_start_date") and req.service_start_date
                else None
            ),
            "service_end_date": (
                req.service_end_date.strftime("%Y-%m-%d")
                if hasattr(req, "service_end_date") and req.service_end_date
                else None
            ),
            "purpose": req.purpose,
            "status": req.status,
            "current_approver_role": req.current_approver_role,
            "created_at": req.created_at.strftime("%Y-%m-%d %H:%M"),
            "requester": req.user.username if req.user else "Unknown",
        }

        # Get approval history
        history = (
            ApprovalHistory.query.filter_by(request_id=request_id)
            .order_by(ApprovalHistory.created_at.asc())
            .all()
        )

        history_data = []
        for h in history:
            history_data.append(
                {
                    "approver_name": h.approver.username if h.approver else "System",
                    "approver_role": h.approver_role,
                    "action": h.action,
                    "comments": h.comments or "",
                    "action_date": h.created_at.strftime("%Y-%m-%d %H:%M"),
                }
            )

        request_data["approval_history"] = history_data

        return jsonify({"success": True, "request": request_data}), 200

    except Exception as e:
        print(f"Error in get_request: {str(e)}")  # Debug log
        import traceback

        traceback.print_exc()  # Print full error trace
        return jsonify({"success": False, "message": f"Server error: {str(e)}"}), 500


@app.route("/api/generate-pdf/<int:request_id>")
def generate_pdf(request_id):
    """Generate PDF for completed firewall request"""
    if "user_id" not in session:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    req = FirewallRequest.query.get(request_id)

    if not req:
        return jsonify({"success": False, "message": "Request not found"}), 404

    # Check if request is completed
    if req.status not in ["Approved", "Rejected"]:
        return (
            jsonify(
                {
                    "success": False,
                    "message": "PDF can only be generated for completed requests",
                }
            ),
            400,
        )

    # Check access permission
    # user = User.query.get(session["user_id"])
    # if req.user_id != session["user_id"] and user.role == "Requester":
    #     return jsonify({"success": False, "message": "Access denied"}), 403

    # Prepare request data
    request_data = {
        "ticket_id": req.ticket_id,
        "ticket_title": req.ticket_title,
        "customer_department": req.customer_department,
        "requester_name": req.user.username if req.user else "Unknown",
        "created_at": req.created_at.strftime("%d-%b-%Y %I:%M %p"),
        "status": req.status,
        "rule_type": req.rule_type,
        "source_ip": req.source_ip,
        "destination_ip": req.destination_ip,
        "destination_ports": req.destination_ports,
        "is_nat_involved": req.is_nat_involved,
        "geo_fencing": req.geo_fencing or "None",
        "access_type": req.access_type,
        "service_start_date": (
            req.service_start_date.strftime("%d-%b-%Y")
            if req.service_start_date
            else "Immediate"
        ),
        "service_end_date": (
            req.service_end_date.strftime("%d-%b-%Y")
            if req.service_end_date
            else "Permanent"
        ),
        "purpose": req.purpose,
    }

    # Get approval history
    history = (
        ApprovalHistory.query.filter_by(request_id=request_id)
        .order_by(ApprovalHistory.created_at.asc())
        .all()
    )

    approval_history = [
        {
            "approver_role": h.approver_role,
            "approver_name": h.approver.username if h.approver else "System",
            "action": h.action,
            "comments": h.comments or "-",
            "created_at": h.created_at.strftime("%d-%b-%Y %I:%M %p"),
        }
        for h in history
    ]

    # Generate PDF
    try:
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
        pdf_path = temp_file.name
        temp_file.close()

        generate_firewall_request_pdf(request_data, approval_history, pdf_path)

        filename = f"{req.ticket_id}_Firewall_Request.pdf"
        return send_file(
            pdf_path,
            as_attachment=True,
            download_name=filename,
            mimetype="application/pdf",
        )

    except Exception as e:
        return (
            jsonify({"success": False, "message": f"Error generating PDF: {str(e)}"}),
            500,
        )





# IP Request Routes

@app.route("/new-request-choice")
def new_request_choice():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("new_request_choice.html")


@app.route("/ip-request")
def ip_request_form():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("ip_request.html")

@app.route("/api/submit-ip-request", methods=["POST"])
def submit_ip_request():
    if "user_id" not in session:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    user = User.query.get(session["user_id"])
    if not user:
        return jsonify({"success": False, "message": "User not found"}), 404

    data = request.get_json() or {}

    rf_number = data.get("rf_number")
    subnets = data.get("subnets") or []
    request_type = data.get("request_type")
    purpose = data.get("purpose")

    if not rf_number or not subnets or not request_type or not purpose:
        return jsonify({"success": False, "message": "RF number, subnets and request type are required"}), 400

    # Enforce Team Lead submission for Requesters
    submitted_to_role = "Team Lead"

    # Generate IP ticket ID
    ticket_count = IPRequest.query.count() + 1
    ticket_id = f"IP{datetime.now().strftime('%Y%m%d')}{ticket_count:04d}"

    ip_req = IPRequest(
        ticket_id=ticket_id,
        rf_number=rf_number,
        subnet_count=len(subnets),
        subnets="\n".join(subnets),
        request_type=request_type,
        owner_name=data.get('owner_name'),
        owner_email=data.get("owner_email"),
        owner_mobile=data.get("owner_mobile"),
        marketing_spoc_name=data.get('marketing_spoc_name'),
        marketing_spoc_email=data.get("marketing_spoc_email"),
        marketing_spoc_mobile=data.get("marketing_spoc_mobile"),
        customer_spoc_name=data.get('customer_spoc_name'),
        customer_spoc_email=data.get("customer_spoc_email"),
        customer_spoc_mobile=data.get("customer_spoc_mobile"),
        purpose=purpose,  # NEW
        status="Pending",
        submitted_to_role=submitted_to_role,
        current_approver_role=submitted_to_role,
        user_id=session["user_id"],
    )

    db.session.add(ip_req)
    db.session.commit()

    history_entry = IPApprovalHistory(
        ip_request_id=ip_req.id,
        approver_id=session["user_id"],
        approver_role=session.get("role", "Requester"),
        action="Submitted",
        forwarded_to_role=submitted_to_role,
        comments=f"IP request submitted to {submitted_to_role}",
    )
    db.session.add(history_entry)
    db.session.commit()

    return jsonify({
        "success": True,
        "message": "IP Request submitted successfully to Team Lead",
        "ticket_id": ticket_id,
    }), 201


@app.route("/ip_approve_request", methods=["POST"])
def ip_approve_request():
    """Handle approve/reject actions for IP requests with role-based routing"""
    if "user_id" not in session:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    user = User.query.get(session["user_id"])
    if not user:
        return jsonify({"success": False, "message": "User not found"}), 404

    data = request.json or {}
    request_id = data.get("request_id")
    action = data.get("action")
    comments = data.get("comments", "")
    ipam_updated = data.get("ipam_updated", False)  # NEW

    ip_request = IPRequest.query.get(request_id)
    if not ip_request:
        return jsonify({"success": False, "message": "IP Request not found"}), 404

    # Verify user is authorized
    if ip_request.current_approver_role != user.role:
        return jsonify(
            {"success": False, "message": "You are not authorized to approve this IP request"}
        ), 403

    # Solution Administrator completing - check IPAM confirmation
    if action == "approve" and user.role == "Solution Administrator":
        if not ipam_updated:
            return jsonify(
                {"success": False, "message": "Please confirm IPAM records update"}
            ), 400

    # Handle approve action
    if action == "approve":
        if user.role == "Solution Administrator":
            ip_request.status = "Approved"
            ip_request.current_approver_role = None
            history_action = "Approved (Final)"
            # Optionally store IPAM confirmation in comments
            if ipam_updated:
                comments = f"{comments}\n[IPAM Records Updated]" if comments else "[IPAM Records Updated]"
        else:
            ip_request.current_approver_role = "Solution Administrator"
            history_action = "Approved"
    # Handle reject action
    elif action == "reject":
        ip_request.status = "Rejected"
        ip_request.current_approver_role = None
        history_action = "Rejected"
    else:
        return jsonify({"success": False, "message": "Invalid action"}), 400

    ip_request.updated_at = datetime.utcnow()

    history_entry = IPApprovalHistory(
        ip_request_id=request_id,
        approver_id=user.id,
        approver_role=user.role,
        action=history_action,
        comments=comments,
        forwarded_to_role=(
            "Solution Administrator"
            if action == "approve" and user.role != "Solution Administrator"
            else None
        ),
    )

    try:
        db.session.add(history_entry)
        db.session.commit()
        if action == "approve":
            if user.role == "Solution Administrator":
                message = "IP request completed successfully"
            else:
                message = "IP request approved and sent to Solution Administrator"
        else:
            message = "IP request rejected successfully"
        return jsonify({"success": True, "message": message}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "message": f"Action failed: {str(e)}"}), 500


@app.route("/ip_forward_request", methods=["POST"])
def ip_forward_request():
    """Handle forward action for IP requests."""
    if "user_id" not in session:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    data = request.json or {}
    request_id = data.get("request_id")
    forward_to = data.get("forward_to")
    comments = data.get("comments", "")

    ip_request = IPRequest.query.get(request_id)
    if not ip_request:
        return jsonify({"success": False, "message": "Request not found"}), 404

    user = User.query.get(session["user_id"])

    # Update request with new approver
    ip_request.current_approver_role = forward_to
    ip_request.updated_at = datetime.utcnow()

    # Add to approval history
    approval = IPApprovalHistory(
        ip_request_id=request_id,
        approver_id=user.id,
        approver_role=user.role,
        action="Forwarded",
        comments=comments,
        forwarded_to_role=forward_to,
    )

    try:
        db.session.add(approval)
        db.session.commit()
        return (
            jsonify(
                {
                    "success": True,
                    "message": f"IP request forwarded to {forward_to}",
                }
            ),
            200,
        )
    except Exception as e:
        db.session.rollback()
        return (
            jsonify(
                {"success": False, "message": f"Forward failed: {str(e)}"}
            ),
            500,
        )



@app.route("/api/ip-request/<int:request_id>")
def get_ip_request(request_id):
    if "user_id" not in session:
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    try:
        req = IPRequest.query.get(request_id)
        if not req:
            return jsonify({"success": False, "message": "Request not found"}), 404

        data = {
            "id": req.id,
            "ticket_id": req.ticket_id,
            "rf_number": req.rf_number,
            "subnet_count": req.subnet_count,
            "subnets": req.subnets,
            "request_type": req.request_type,
            'owner_name': req.owner_name,
            "owner_email": req.owner_email,
            "owner_mobile": req.owner_mobile,
            'marketing_spoc_name': req.marketing_spoc_name,
            "marketing_spoc_email": req.marketing_spoc_email,
            "marketing_spoc_mobile": req.marketing_spoc_mobile,
            'customer_spoc_name': req.customer_spoc_name,
            "customer_spoc_email": req.customer_spoc_email,
            "customer_spoc_mobile": req.customer_spoc_mobile,
            "purpose": req.purpose,
            "status": req.status,
            "requester": req.user.username if req.user else "Unknown",
            "created_at": req.created_at.strftime("%Y-%m-%d %H:%M"),
        }

        return jsonify({"success": True, "request": data}), 200
    except Exception as e:
        print(f"Error in get_ip_request: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"success": False, "message": f"Server error: {str(e)}"}), 500




# @app.route("/api/ip-approve-request/<int:request_id>", methods=["POST"])
# def ip_approve_request(request_id):
#     if "user_id" not in session:
#         return jsonify({"success": False, "message": "Unauthorized"}), 401

#     user = User.query.get(session["user_id"])
#     if not user:
#         return jsonify({"success": False, "message": "User not found"}), 404

#     req = IPRequest.query.get(request_id)
#     if not req:
#         return jsonify({"success": False, "message": "Request not found"}), 404

#     data = request.get_json() or {}
#     action = data.get("action")

#     # mimic firewall approval rules or adjust
#     if req.current_approver_role != user.role:
#         return jsonify({"success": False, "message": "You are not authorized to approve this IP request"}), 403

#     if action == "approve":
#         req.status = "Approved"
#         req.current_approver_role = None
#         history_action = "Approved"
#     elif action == "reject":
#         req.status = "Rejected"
#         req.current_approver_role = None
#         history_action = "Rejected"
#     else:
#         return jsonify({"success": False, "message": "Invalid action"}), 400

#     req.updated_at = datetime.utcnow()

#     # Add IPApprovalHistory entry once model exists

#     db.session.commit()

#     return jsonify({"success": True, "message": f"IP request {action}d successfully"})


@app.route("/api/ip-search-ticket/<ticket_id>")
def ip_search_ticket(ticket_id):
    """Enhanced route with complete role hierarchy and skipped role detection for IP requests"""
    if "user_id" not in session:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    req = IPRequest.query.filter_by(ticket_id=ticket_id).first()
    if not req:
        return jsonify({"success": False, "message": "IP Ticket not found"}), 404

    # Get approval history
    history = (
        IPApprovalHistory.query.filter_by(ip_request_id=req.id)
        .order_by(IPApprovalHistory.created_at.asc())
        .all()
    )

    request_data = {
        "id": req.id,
        "ticket_id": req.ticket_id,
        "rf_number": req.rf_number,
        "subnet_count": req.subnet_count,
        "subnets": req.subnets,
        "request_type": req.request_type,
        "status": req.status,
        "current_approver_role": req.current_approver_role,
        "submitted_to_role": req.submitted_to_role,
        "created_at": req.created_at.strftime("%Y-%m-%d %H:%M"),
        "requester_name": req.user.username if req.user else "Unknown",
    
        "owner_email": req.owner_email,
        "owner_mobile": req.owner_mobile,
        
        "marketing_spoc_email": req.marketing_spoc_email,
        "marketing_spoc_mobile": req.marketing_spoc_mobile,
        
        "customer_spoc_email": req.customer_spoc_email,
        "customer_spoc_mobile": req.customer_spoc_mobile,
    }

    history_data = [
        {
            "approver_name": h.approver.username if h.approver else "System",
            "approver_role": h.approver_role,
            "action": h.action,
            "comments": h.comments,
            "forwarded_to_role": h.forwarded_to_role,
            "created_at": h.created_at.strftime("%Y-%m-%d %H:%M"),
        }
        for h in history
    ]

    # Build complete approval flow with all roles in hierarchy
    complete_hierarchy = [
        "Team Lead",
        "Department Head",
        "Security Auditor",
        "ITP Vertical Head",
        "Solution Administrator",
    ]

    # Track which roles were actually involved
    involved_roles = set()
    for h in history:
        if h.action not in ["Submitted"]:
            involved_roles.add(h.approver_role)

    # Add current pending role
    if req.current_approver_role:
        involved_roles.add(req.current_approver_role)

    # Build flow stages
    flow_stages = []

    # Add requester/submitted stage first
    submitted_history = next((h for h in history if h.action == "Submitted"), None)
    flow_stages.append(
        {
            "role": "Requester",
            "status": "submitted",
            "approver": (
                submitted_history.approver.username
                if submitted_history and submitted_history.approver
                else req.user.username if req.user else "Unknown"
            ),
            "comments": (
                submitted_history.comments
                if submitted_history
                else f"IP Request submitted to {req.submitted_to_role}"
            ),
            "date": (
                submitted_history.created_at.strftime("%Y-%m-%d %H:%M")
                if submitted_history
                else req.created_at.strftime("%Y-%m-%d %H:%M")
            ),
            "skipped": False,
        }
    )

    # Process each role in the complete hierarchy
    for role in complete_hierarchy:
        role_history = next(
            (
                h
                for h in history
                if h.approver_role == role and h.action not in ["Submitted"]
            ),
            None,
        )

        if role_history:
            flow_stages.append(
                {
                    "role": role,
                    "status": role_history.action.lower(),
                    "approver": (
                        role_history.approver.username
                        if role_history.approver
                        else "Unknown"
                    ),
                    "comments": role_history.comments,
                    "date": role_history.created_at.strftime("%Y-%m-%d %H:%M"),
                    "skipped": False,
                }
            )
        elif role == req.current_approver_role:
            flow_stages.append(
                {
                    "role": role,
                    "status": "pending",
                    "approver": None,
                    "comments": "Awaiting approval",
                    "date": None,
                    "skipped": False,
                }
            )
        elif role in involved_roles:
            pass
        else:
            role_index = complete_hierarchy.index(role)
            workflow_moved_past = False
            for higher_role in complete_hierarchy[role_index + 1 :]:
                if higher_role in involved_roles:
                    workflow_moved_past = True
                    break

            if workflow_moved_past:
                flow_stages.append(
                    {
                        "role": role,
                        "status": "skipped",
                        "approver": None,
                        "comments": "Skipped in approval workflow",
                        "date": None,
                        "skipped": True,
                    }
                )

    request_data["approval_flow"] = flow_stages
    request_data["approval_history"] = history_data

    return jsonify({"success": True, "request": request_data})


@app.route("/download-ip-pdf/<int:request_id>")
def download_ip_pdf(request_id):
    """Generate and download PDF for IP request"""
    if "user_id" not in session:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    ip_request = IPRequest.query.get(request_id)
    if not ip_request:
        return jsonify({"success": False, "message": "IP Request not found"}), 404

    # Only allow PDF download for Approved or Rejected requests
    if ip_request.status not in ["Approved", "Rejected"]:
        return jsonify({"success": False, "message": "PDF can only be generated for Approved or Rejected requests"}), 400

    # Get the user who created the request
    requester_user = User.query.get(ip_request.user_id)
    requester_name = requester_user.username if requester_user else "Unknown"

    # Prepare request data - handle None values properly
    request_data = {
        "ticket_id": ip_request.ticket_id or "N/A",
        "rf_number": ip_request.rf_number or "N/A",
        "requester": requester_name,
        "request_type": ip_request.request_type or "N/A",
        "subnet_count": ip_request.subnet_count or 0,
        "subnets": ip_request.subnets or "No subnets specified",  # Fix: Handle None
        "purpose": ip_request.purpose or "Not provided", 
        "owner_name": ip_request.owner_name or "-",
        "owner_email": ip_request.owner_email or "-",
        "owner_mobile": ip_request.owner_mobile or "-",
        "marketing_spoc_name": ip_request.marketing_spoc_name or "-",
        "marketing_spoc_email": ip_request.marketing_spoc_email or "-",
        "marketing_spoc_mobile": ip_request.marketing_spoc_mobile or "-",
        "customer_spoc_name": ip_request.customer_spoc_name or "-",
        "customer_spoc_email": ip_request.customer_spoc_email or "-",
        "customer_spoc_mobile": ip_request.customer_spoc_mobile or "-",
        "status": ip_request.status or "Pending",
        "created_at": ip_request.created_at.strftime("%d-%b-%Y %I:%M %p") if ip_request.created_at else "N/A",
    }

    # Get approval history
    history_records = IPApprovalHistory.query.filter_by(ip_request_id=request_id).order_by(
        IPApprovalHistory.created_at
    ).all()

    approval_history = []
    for record in history_records:
        approver_user = User.query.get(record.approver_id) if record.approver_id else None
        approval_history.append({
            "approver_role": record.approver_role or "N/A",
            "approver_name": approver_user.username if approver_user else "System",
            "action": record.action or "N/A",
            "comments": record.comments or "-",
            "created_at": record.created_at.strftime("%d-%b-%Y %I:%M %p") if record.created_at else "N/A",
        })

    # Generate PDF
    pdf_filename = f"{ip_request.ticket_id}.pdf"
    pdf_path = os.path.join("static", "pdfs", pdf_filename)

    # Ensure pdfs directory exists
    os.makedirs(os.path.dirname(pdf_path), exist_ok=True)

    try:
        from utils.pdf_generator import generate_ip_request_pdf
        generate_ip_request_pdf(request_data, approval_history, pdf_path)
        return send_file(pdf_path, as_attachment=True, download_name=pdf_filename)
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"success": False, "message": f"Failed to generate PDF: {str(e)}"}), 500


@app.route('/all-ip-requests')
def all_ip_requests():
    """Show all IP requests"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        return redirect(url_for('login'))
    
    # Get all IP requests
    all_requests = IPRequest.query.order_by(IPRequest.created_at.desc()).all()
    
    return render_template('all_ip_requests.html', requests=all_requests, user=user)


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, host="0.0.0.0")
