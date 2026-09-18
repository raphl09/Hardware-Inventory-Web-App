"""Engineering Laboratory Asset Tracking System."""

import csv
import logging
import os
import re
import sqlite3
#import tkinter as tk
# DESKTOP ONLY — Tkinter is unavailable on headless servers such as Render.
try:
    import tkinter as tk
    from tkinter import messagebox, ttk
except ImportError:
    tk = None
    messagebox = None
    ttk = None
from datetime import datetime
from pathlib import Path
#from tkinter import messagebox, ttk

import bcrypt
from dotenv import load_dotenv
from pydantic import BaseModel, Field, ValidationError, field_validator

from database_compat import connect_postgresql


# logger.py

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "hardware_inventory.db"
LOG_DIR = BASE_DIR / "app_logging"
LOG_PATH = LOG_DIR / "app.log"
CSV_PATH = BASE_DIR / "inventory_report.csv"
LOG_DIR.mkdir(exist_ok=True)

load_dotenv(BASE_DIR / ".env")
DATABASE_URL = os.getenv("DATABASE_URL")

logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s - [%(levelname)s] - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

logger = logging.getLogger("HardwareInventoryApp")


# database.py

def get_connection():
    if DATABASE_URL:
        return connect_postgresql(DATABASE_URL)

    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    """Create the users and hardware tables if they do not exist."""

    # The PostgreSQL schema was created by migrate_to_postgres.py.
    # Confirm that Supabase is reachable without running SQLite-only DDL.
    if DATABASE_URL:
        try:
            conn = get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            cursor.close()
            conn.close()
            logger.info("PostgreSQL database connection verified.")
            return
        except sqlite3.Error as e:
            logger.error(f"PostgreSQL initialization check failed: {e}")
            raise

    try:
        conn = get_connection()
        cursor = conn.cursor()

        # Authentication Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'USER',
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                is_locked INTEGER NOT NULL DEFAULT 0
            )
        """)

        # Add missing columns if the table came from older code
        cursor.execute("PRAGMA table_info(users)")
        columns = [column[1] for column in cursor.fetchall()]

        if "email" not in columns:
            cursor.execute(
                "ALTER TABLE users ADD COLUMN email TEXT"
            )

        if "role" not in columns:
            cursor.execute(
                "ALTER TABLE users "
                "ADD COLUMN role TEXT NOT NULL DEFAULT 'USER'"
            )

        if "failed_attempts" not in columns:
            cursor.execute(
                "ALTER TABLE users "
                "ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0"
            )

        if "is_locked" not in columns:
            cursor.execute(
                "ALTER TABLE users "
                "ADD COLUMN is_locked INTEGER NOT NULL DEFAULT 0"
            )

        # Keep the earlier Administrator role compatible with Task 2.
        cursor.execute(
            "UPDATE users SET role = 'ADMIN' "
            "WHERE role = 'Administrator'"
        )

        # Task 5 uses USER as the standard non-administrator role.
        cursor.execute(
            "UPDATE users SET role = 'USER' "
            "WHERE role = 'Staff'"
        )

        # Make email unique even for an upgraded database
        cursor.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS
            idx_users_email_unique
            ON users(email)
            WHERE email IS NOT NULL
        """)

        # Hardware Table from Activity 2
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS hardware (
                item_id INTEGER PRIMARY KEY AUTOINCREMENT,
                item_name TEXT NOT NULL UNIQUE,
                category TEXT NOT NULL,
                quantity INTEGER NOT NULL,
                unit_price REAL NOT NULL,
                status TEXT NOT NULL
            )
        """)

        # Password Reset Requests Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS password_reset_requests (
                request_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                email TEXT NOT NULL,
                requested_password_hash TEXT NOT NULL,
                request_date TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                status TEXT NOT NULL DEFAULT 'Pending',
                reviewed_by TEXT,
                reviewed_date TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)

        # A locked user may only have one pending request at a time.
        cursor.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS
            idx_one_pending_reset_per_user
            ON password_reset_requests(user_id)
            WHERE status = 'Pending'
        """)

        # Equipment Requests and Reservations Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS equipment_requests (
                request_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                borrower_id_number TEXT NOT NULL,
                group_members TEXT NOT NULL DEFAULT 'None',
                item_id INTEGER NOT NULL,
                quantity INTEGER NOT NULL,
                purpose TEXT NOT NULL,
                start_time TEXT NOT NULL,
                end_time TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Pending',
                admin_note TEXT,
                reviewed_by TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (item_id) REFERENCES hardware(item_id)
            )
        """)

        # Add borrower details when upgrading from an older database.
        cursor.execute("PRAGMA table_info(equipment_requests)")
        request_columns = [column[1] for column in cursor.fetchall()]

        if "borrower_id_number" not in request_columns:
            cursor.execute(
                "ALTER TABLE equipment_requests "
                "ADD COLUMN borrower_id_number TEXT NOT NULL "
                "DEFAULT 'Not provided'"
            )

        if "group_members" not in request_columns:
            cursor.execute(
                "ALTER TABLE equipment_requests "
                "ADD COLUMN group_members TEXT NOT NULL DEFAULT 'None'"
            )

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_requests_schedule
            ON equipment_requests(item_id, start_time, end_time, status)
        """)

        conn.commit()
        conn.close()

        logger.info("Database initialized successfully.")

    except sqlite3.Error as e:
        logger.error(
            f"Database initialization failed: {e}"
        )


# schemas.py

class UserRegisterSchema(BaseModel):

    username: str = Field(..., min_length=3, max_length=20)
    email: str
    password: str = Field(...,min_length=8)
    role: str

    # Username Validation
    @field_validator("username")
    @classmethod
    def validate_username(cls, value):

        if not re.fullmatch(r"[A-Za-z0-9]+", value):
            raise ValueError("Username must contain only letters and numbers.")
        return value

    # Email Validation
    @field_validator("email")
    @classmethod
    def validate_email(cls, value):

        if not re.fullmatch(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",value):
            raise ValueError("Please enter a valid email address.")
        return value.lower()

    # Password Complexity Validation
    @field_validator("password")
    @classmethod
    # RESTRICTION
    def validate_password(cls, value):
        if not re.search(r"[A-Z]", value):
            raise ValueError("Password must contain at least one uppercase letter.")
        if not re.search(r"[0-9]", value):
            raise ValueError("Password must contain at least one number.")

        if not re.search(r"[@#$%^&*]", value):
            raise ValueError(
                "Password must contain at least one special "
                "character (@#$%^&*)."
            )
        return value

    # User Role Validation
    @field_validator("role")
    @classmethod
    def validate_role(cls, value):
        allowed_roles = ["ADMIN", "USER"]

        if value not in allowed_roles:
            raise ValueError("Please select a valid user role.")
        return value


class PasswordResetSchema(BaseModel):

    email: str
    new_password: str = Field(..., min_length=8)

    # Registered Email Validation
    @field_validator("email")
    @classmethod
    def validate_email(cls, value):

        if not re.fullmatch(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", value):
            raise ValueError("Please enter a valid registered email address.")
        return value.lower()

    # New Password Complexity Validation
    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, value):

        if not re.search(r"[A-Z]", value):
            raise ValueError("New password must contain at least one uppercase letter.")

        if not re.search(r"[0-9]", value):
            raise ValueError("New password must contain at least one number.")

        if not re.search(r"[@#$%^&*]", value):
            raise ValueError(
                "New password must contain at least one special "
                "character (@#$%^&*)."
            )
        return value


class DirectPasswordChangeSchema(BaseModel):

    current_password: str = Field(..., min_length=1)
    new_password: str = Field(
        ...,
        min_length=8
    )

    confirm_password: str = Field(..., min_length=1)

    # New Password Complexity Validation
    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, value):

        if not re.search(r"[A-Z]", value):
            raise ValueError(
                "New password must contain at least one uppercase letter."
            )

        if not re.search(r"[0-9]", value):
            raise ValueError(
                "New password must contain at least one number."
            )

        if not re.search(r"[@#$%^&*]", value):
            raise ValueError(
                "New password must contain at least one special "
                "character (@#$%^&*)."
            )

        return value


class HardwareSchema(BaseModel):

    item_name: str = Field(..., min_length=2, max_length=100)
    category: str = Field(..., min_length=2, max_length=50)
    quantity: int = Field(..., ge=0)
    unit_price: float = Field(..., ge=0)


class HardwareUpdateSchema(BaseModel):

    quantity: int = Field(..., ge=0)
    unit_price: float = Field(..., ge=0)


class EquipmentRequestSchema(BaseModel):

    item_id: int = Field(..., gt=0)
    quantity: int = Field(..., gt=0)
    borrower_id_number: str = Field(..., min_length=4, max_length=30)
    group_members: str = Field(default="None", max_length=500)
    purpose: str = Field(..., min_length=3, max_length=250)
    start_time: str
    end_time: str

    @field_validator("borrower_id_number")
    @classmethod
    def validate_borrower_id_number(cls, value):

        cleaned_value = value.strip()

        if not re.fullmatch(r"[A-Za-z0-9./-]+", cleaned_value):
            raise ValueError(
                "ID Number may contain only letters, numbers, periods, "
                "slashes, and hyphens."
            )

        return cleaned_value

    @field_validator("group_members")
    @classmethod
    def normalize_group_members(cls, value):

        cleaned_value = value.strip()
        return cleaned_value if cleaned_value else "None"


# Auth_controller.py
class AuthController:

    def __init__(self):
        # Login attempts and lock status are stored in SQLite so the
        # lock remains active even after the program is restarted.
        pass

    # REGISTER
    def register_user(
        self,
        username,
        email,
        password,
        role
    ):

        try:
            validated = UserRegisterSchema(
                username=username,
                email=email,
                password=password,
                role=role
            )

        except ValidationError as e:
            msg = e.errors()[0]["msg"]

            logger.warning(
                f"Registration validation failed "
                f"for username '{username}': {msg}"
            )

            return False, f"Validation Error: {msg}"

        # Hash Password Using bcrypt
        hashed_password = bcrypt.hashpw(
            validated.password.encode("utf-8"),
            bcrypt.gensalt()
        )

        try:
            conn = get_connection()
            cursor = conn.cursor()

            # Check Duplicate Username
            cursor.execute(
                """
                SELECT id
                FROM users
                WHERE username = ?
                """,
                (validated.username,)
            )

            if cursor.fetchone():
                conn.close()

                logger.warning(
                    f"Registration failed - username "
                    f"already exists: '{validated.username}'"
                )

                return False, "Username already taken."

            # Check Duplicate Email
            cursor.execute(
                """
                SELECT id
                FROM users
                WHERE LOWER(email) = LOWER(?)
                """,
                (validated.email,)
            )

            if cursor.fetchone():
                conn.close()

                logger.warning(
                    f"Registration failed - email "
                    f"already exists: '{validated.email}'"
                )

                return False, "Email address is already registered."

            # Insert Account with Role
            cursor.execute(
                """
                INSERT INTO users
                (username, email, password_hash, role)
                VALUES (?, ?, ?, ?)
                """,
                (
                    validated.username,
                    validated.email,
                    hashed_password.decode("utf-8"),
                    validated.role
                )
            )

            conn.commit()
            conn.close()

            logger.info(
                f"Account registered successfully: "
                f"'{validated.username}' as {validated.role}"
            )

            return True, (
                "Registration successful!\n"
                f"Role: {validated.role}\n"
                "You may now log in."
            )

        except sqlite3.IntegrityError:
            logger.warning(
                f"Registration failed due to duplicate data "
                f"for username '{username}'"
            )

            return False, "Username or email is already registered."

        except sqlite3.Error as e:
            logger.error(
                f"Registration database error: {e}"
            )

            return False, "Registration failed."

    # LOGIN
    def login_user(
        self,
        username,
        password
    ):

        if not username or not password:
            logger.warning(
                "Login attempt failed - missing credentials."
            )

            return (
                False,
                "Please enter both username and password.",
                None,
                False
            )

        # Query Database
        try:
            conn = get_connection()
            cursor = conn.cursor()

            # Retrieve the stored password, role, attempts, and lock status.
            cursor.execute(
                """
                SELECT
                    id,
                    password_hash,
                    role,
                    failed_attempts,
                    is_locked
                FROM users
                WHERE username = ?
                """,
                (username,)
            )

            row = cursor.fetchone()

            # Unknown usernames cannot be locked because no account exists.
            if not row:
                conn.close()

                logger.warning(
                    f"Login failed - unknown username '{username}'."
                )

                return (
                    False,
                    "Invalid username or password.",
                    None,
                    False
                )

            user_id = row[0]
            password_hash = row[1]
            role = row[2]
            failed_attempts = row[3]
            is_locked = row[4]

            # A locked account stays locked until an admin approves a reset.
            if is_locked == 1:
                conn.close()

                logger.warning(
                    f"Login blocked - account '{username}' is locked."
                )

                return (
                    False,
                    "Account locked.\n"
                    "Proceed to Reset / Unlock Password.",
                    None,
                    True
                )

            # Correct Password
            if bcrypt.checkpw(
                password.encode("utf-8"),
                password_hash.encode("utf-8")
            ):
                cursor.execute(
                    """
                    UPDATE users
                    SET failed_attempts = 0
                    WHERE id = ?
                    """,
                    (user_id,)
                )

                conn.commit()
                conn.close()

                logger.info(
                    f"Successful login: '{username}' as {role}"
                )

                return True, "Login successful!", role, False

            # Incorrect Password
            attempts = failed_attempts + 1

            logger.warning(
                f"Failed login attempt {attempts}/3 "
                f"for username '{username}'"
            )

            # Permanently lock the account after three failed attempts.
            if attempts >= 3:
                cursor.execute(
                    """
                    UPDATE users
                    SET failed_attempts = 3,
                        is_locked = 1
                    WHERE id = ?
                    """,
                    (user_id,)
                )

                conn.commit()
                conn.close()

                logger.warning(
                    f"Account '{username}' locked after "
                    "three unsuccessful login attempts."
                )

                return (
                    False,
                    "Too many failed login attempts.\n"
                    "Account locked. Proceed to Reset / Unlock Password.",
                    None,
                    True
                )

            cursor.execute(
                """
                UPDATE users
                SET failed_attempts = ?
                WHERE id = ?
                """,
                (attempts, user_id)
            )

            conn.commit()
            conn.close()

            remaining = 3 - attempts

            return (
                False,
                "Invalid username or password.\n"
                f"{remaining} attempt(s) remaining.",
                None,
                False
            )

        except sqlite3.Error as e:
            logger.error(
                f"Login database error: {e}"
            )

            return False, "Login failed.", None, False

    # GET USER PROFILE INFORMATION
    def get_user_profile(self, username):

        try:
            conn = get_connection()
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT username, email, role
                FROM users
                WHERE username = ?
                """,
                (username,)
            )

            profile = cursor.fetchone()
            conn.close()

            return profile

        except sqlite3.Error as e:
            logger.error(
                f"Failed to retrieve profile for '{username}': {e}"
            )

            return None

    # DIRECT PASSWORD CHANGE FOR A LOGGED-IN USER
    def change_password(
        self,
        username,
        current_password,
        new_password,
        confirm_password
    ):

        try:
            validated = DirectPasswordChangeSchema(
                current_password=current_password,
                new_password=new_password,
                confirm_password=confirm_password
            )

        except ValidationError as e:
            msg = e.errors()[0]["msg"]

            logger.warning(
                f"Direct password-change validation failed "
                f"for '{username}': {msg}"
            )

            return False, f"Validation Error: {msg}"

        if validated.new_password != validated.confirm_password:
            return False, "New password and confirmation do not match."

        try:
            conn = get_connection()
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT password_hash, is_locked
                FROM users
                WHERE username = ?
                """,
                (username,)
            )

            account = cursor.fetchone()

            if not account:
                conn.close()
                return False, "User account was not found."

            if account[1] == 1:
                conn.close()
                return False, (
                    "This account is locked. Use the "
                    "Reset / Unlock Password function."
                )

            if not bcrypt.checkpw(
                validated.current_password.encode("utf-8"),
                account[0].encode("utf-8")
            ):
                conn.close()

                logger.warning(
                    f"Direct password change rejected for "
                    f"'{username}' - incorrect current password."
                )

                return False, "The current password is incorrect."

            if bcrypt.checkpw(
                validated.new_password.encode("utf-8"),
                account[0].encode("utf-8")
            ):
                conn.close()
                return False, (
                    "The new password must be different "
                    "from the current password."
                )

            new_password_hash = bcrypt.hashpw(
                validated.new_password.encode("utf-8"),
                bcrypt.gensalt()
            ).decode("utf-8")

            cursor.execute(
                """
                UPDATE users
                SET password_hash = ?,
                    failed_attempts = 0
                WHERE username = ?
                """,
                (new_password_hash, username)
            )

            conn.commit()
            conn.close()

            logger.info(
                f"Password changed directly by '{username}'."
            )

            return True, (
                "Password changed successfully.\n"
                "Log out and use the updated password on your next login."
            )

        except sqlite3.Error as e:
            logger.error(
                f"Direct password change failed for '{username}': {e}"
            )

            return False, "Unable to change the password."

    # SUBMIT PASSWORD RESET REQUEST
    def submit_reset_request(self, email, new_password):

        try:
            validated = PasswordResetSchema(
                email=email,
                new_password=new_password
            )

        except ValidationError as e:
            msg = e.errors()[0]["msg"]

            logger.warning(
                f"Password reset validation failed: {msg}"
            )

            return False, f"Validation Error: {msg}"

        try:
            conn = get_connection()
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT id, username, is_locked
                FROM users
                WHERE LOWER(email) = LOWER(?)
                """,
                (validated.email,)
            )

            user = cursor.fetchone()

            if not user:
                conn.close()

                logger.warning(
                    "Password reset request used an unregistered email."
                )

                return False, "No account is registered with that email."

            user_id = user[0]
            username = user[1]
            is_locked = user[2]

            if is_locked == 0:
                conn.close()

                return False, (
                    "This account is not locked. "
                    "A reset request is not required."
                )

            cursor.execute(
                """
                SELECT request_id
                FROM password_reset_requests
                WHERE user_id = ? AND status = 'Pending'
                """,
                (user_id,)
            )

            if cursor.fetchone():
                conn.close()

                return False, (
                    "A password-reset request for this account "
                    "is already pending admin review."
                )

            requested_password_hash = bcrypt.hashpw(
                validated.new_password.encode("utf-8"),
                bcrypt.gensalt()
            ).decode("utf-8")

            cursor.execute(
                """
                INSERT INTO password_reset_requests
                (
                    user_id,
                    email,
                    requested_password_hash
                )
                VALUES (?, ?, ?)
                """,
                (
                    user_id,
                    validated.email,
                    requested_password_hash
                )
            )

            conn.commit()
            conn.close()

            logger.info(
                f"Password reset requested for '{username}'."
            )

            return True, (
                "Password-reset request submitted.\n"
                "Wait for an ADMIN to approve or reject it."
            )

        except sqlite3.Error as e:
            logger.error(
                f"Password reset request failed: {e}"
            )

            return False, "Unable to submit the password-reset request."

    # FETCH RESET REQUESTS FOR ADMIN APPROVALS
    def fetch_reset_requests(self, status_filter="All Requests"):

        try:
            conn = get_connection()
            cursor = conn.cursor()

            query = """
                SELECT
                    requests.request_id,
                    users.username,
                    requests.email,
                    requests.request_date,
                    requests.status,
                    COALESCE(requests.reviewed_by, '-'),
                    COALESCE(requests.reviewed_date, '-')
                FROM password_reset_requests AS requests
                INNER JOIN users
                    ON requests.user_id = users.id
                WHERE 1 = 1
            """

            parameters = []

            if status_filter in ["Pending", "Approved", "Rejected"]:
                query += " AND requests.status = ?"
                parameters.append(status_filter)

            query += " ORDER BY requests.request_id DESC"

            cursor.execute(query, parameters)

            rows = cursor.fetchall()
            conn.close()

            return rows

        except sqlite3.Error as e:
            logger.error(
                f"Failed to fetch reset requests: {e}"
            )

            return []

    # RETAIN THE ORIGINAL PENDING-ONLY METHOD
    def fetch_pending_reset_requests(self):

        return self.fetch_reset_requests("Pending")

    # APPROVE OR REJECT A PASSWORD RESET REQUEST
    def review_reset_request(
        self,
        request_id,
        admin_username,
        decision
    ):

        if decision not in ["Approved", "Rejected"]:
            return False, "Invalid approval decision."

        try:
            conn = get_connection()
            cursor = conn.cursor()

            # Verify that the reviewer is an ADMIN.
            cursor.execute(
                """
                SELECT role
                FROM users
                WHERE username = ?
                """,
                (admin_username,)
            )

            admin = cursor.fetchone()

            if not admin or admin[0] != "ADMIN":
                conn.close()

                logger.warning(
                    f"Unauthorized reset review attempt by "
                    f"'{admin_username}'."
                )

                return False, "Only an ADMIN may review reset requests."

            cursor.execute(
                """
                SELECT user_id, requested_password_hash, status
                FROM password_reset_requests
                WHERE request_id = ?
                """,
                (request_id,)
            )

            request = cursor.fetchone()

            if not request:
                conn.close()
                return False, "Password-reset request was not found."

            if request[2] != "Pending":
                conn.close()
                return False, "This request has already been reviewed."

            user_id = request[0]
            requested_password_hash = request[1]

            if decision == "Approved":
                cursor.execute(
                    """
                    UPDATE users
                    SET password_hash = ?,
                        failed_attempts = 0,
                        is_locked = 0
                    WHERE id = ?
                    """,
                    (requested_password_hash, user_id)
                )

            cursor.execute(
                """
                UPDATE password_reset_requests
                SET status = ?,
                    reviewed_by = ?,
                    reviewed_date = CURRENT_TIMESTAMP
                WHERE request_id = ?
                """,
                (decision, admin_username, request_id)
            )

            conn.commit()
            conn.close()

            logger.info(
                f"Password reset request {request_id} "
                f"{decision.lower()} by '{admin_username}'."
            )

            if decision == "Approved":
                return True, (
                    "Request approved.\n"
                    "The password was changed and the account was unlocked."
                )

            return True, (
                "Request rejected.\n"
                "The account remains locked."
            )

        except sqlite3.Error as e:
            logger.error(
                f"Failed to review reset request: {e}"
            )

            return False, "Unable to review the password-reset request."


# HARDWARE CONTROLLER
class HardwareController:

    # Stock status
    @staticmethod
    def get_status(quantity):

        if quantity > 5:
            return "In Stock"

        elif quantity >= 1:
            return "Low Stock"

        else:
            return "Out of Stock"

    # FETCH, SEARCH, AND FILTER HARDWARE
    def fetch_all_hardware(
        self,
        search_text="",
        category_filter="All Categories",
        status_filter="All Statuses"
    ):

        try:
            conn = get_connection()
            cursor = conn.cursor()

            query = """
                SELECT
                    item_id,
                    item_name,
                    category,
                    quantity,
                    unit_price,
                    status
                FROM hardware
                WHERE 1 = 1
            """

            parameters = []

            if search_text:
                query += """
                    AND (
                        item_name LIKE ?
                        OR category LIKE ?
                    )
                """

                search_value = f"%{search_text}%"
                parameters.extend([search_value, search_value])

            if category_filter != "All Categories":
                query += " AND category = ?"
                parameters.append(category_filter)

            if status_filter != "All Statuses":
                query += " AND status = ?"
                parameters.append(status_filter)

            query += " ORDER BY item_id"

            cursor.execute(query, parameters)

            rows = cursor.fetchall()
            conn.close()

            return rows

        except sqlite3.Error as e:
            logger.error(
                f"Failed to fetch hardware records: {e}"
            )

            return []

    # FETCH AVAILABLE CATEGORIES FOR THE FILTER
    def fetch_categories(self):

        try:
            conn = get_connection()
            cursor = conn.cursor()

            cursor.execute("""
                SELECT DISTINCT category
                FROM hardware
                ORDER BY category
            """)

            categories = [row[0] for row in cursor.fetchall()]
            conn.close()

            return categories

        except sqlite3.Error as e:
            logger.error(
                f"Failed to fetch hardware categories: {e}"
            )

            return []

    def add_hardware(
        self,
        name,
        category,
        quantity,
        price
    ):

        try:
            validated = HardwareSchema(
                item_name=name,
                category=category,
                quantity=quantity,
                unit_price=price
            )

        except ValidationError as e:
            msg = e.errors()[0]["msg"]

            logger.warning(
                f"Hardware validation failed: {msg}"
            )

            return False, f"Validation Error: {msg}"

        # Calculate stock status automatically
        status = self.get_status(validated.quantity)

        try:
            conn = get_connection()
            cursor = conn.cursor()

            # Duplicate Hardware Name Check
            cursor.execute(
                """
                SELECT item_id
                FROM hardware
                WHERE item_name = ?
                """,
                (validated.item_name,)
            )

            if cursor.fetchone():
                conn.close()

                logger.warning(
                    f"Duplicate hardware name rejected: "
                    f"'{validated.item_name}'"
                )

                return False, "Hardware name already exists."

            # Insert Hardware
            cursor.execute(
                """
                INSERT INTO hardware
                (
                    item_name,
                    category,
                    quantity,
                    unit_price,
                    status
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    validated.item_name,
                    validated.category,
                    validated.quantity,
                    validated.unit_price,
                    status
                )
            )

            conn.commit()
            conn.close()

            logger.info(
                f"Hardware added: '{validated.item_name}'"
            )

            return True, "Hardware added successfully."

        except sqlite3.Error as e:
            logger.error(
                f"Failed to add hardware: {e}"
            )

            return False, "Database insertion failed."

    # UPDATE HARDWARE
    def update_hardware(
        self,
        item_id,
        quantity,
        price
    ):

        try:
            validated = HardwareUpdateSchema(
                quantity=quantity,
                unit_price=price
            )

        except ValidationError as e:
            msg = e.errors()[0]["msg"]

            logger.warning(
                f"Hardware update validation failed "
                f"for ID {item_id}: {msg}"
            )

            return False, f"Validation Error: {msg}"

        status = self.get_status(validated.quantity)

        try:
            conn = get_connection()
            cursor = conn.cursor()

            cursor.execute(
                """
                UPDATE hardware
                SET
                    quantity = ?,
                    unit_price = ?,
                    status = ?
                WHERE item_id = ?
                """,
                (
                    validated.quantity,
                    validated.unit_price,
                    status,
                    item_id
                )
            )

            conn.commit()
            conn.close()

            logger.info(
                f"Hardware ID {item_id} updated."
            )

            return True, "Item updated successfully."

        except sqlite3.Error as e:
            logger.error(
                f"Failed to update hardware: {e}"
            )

            return False, "Database update failed."

    # DELETE HARDWARE
    def delete_hardware(self, item_id):

        try:
            conn = get_connection()
            cursor = conn.cursor()

            cursor.execute(
                """
                DELETE FROM hardware
                WHERE item_id = ?
                """,
                (item_id,)
            )

            conn.commit()
            conn.close()

            logger.info(
                f"Hardware ID {item_id} deleted."
            )

            return True, "Item deleted successfully."

        except sqlite3.Error as e:
            logger.error(
                f"Failed to delete hardware: {e}"
            )

            return False, "Database deletion failed."

    # TOTAL INVENTORY VALUE
    def get_total_value(self):

        try:
            conn = get_connection()
            cursor = conn.cursor()

            cursor.execute("""
                SELECT COALESCE(
                    SUM(quantity * unit_price),
                    0
                )
                FROM hardware
            """)

            total = cursor.fetchone()[0]
            conn.close()

            return total

        except sqlite3.Error as e:
            logger.error(
                f"Failed to calculate inventory valuation: {e}"
            )

            return 0

    # EXPORT CSV
    def export_csv(self):

        try:
            rows = self.fetch_all_hardware()

            with open(
                CSV_PATH,
                "w",
                newline="",
                encoding="utf-8"
            ) as csv_file:
                writer = csv.writer(csv_file)

                writer.writerow([
                    "ID",
                    "Name",
                    "Category",
                    "Qty",
                    "Price ($)",
                    "Status"
                ])

                for row in rows:
                    writer.writerow(row)

            logger.info(
                f"Inventory report generated: {CSV_PATH.name}"
            )

            return True, f"Inventory exported to {CSV_PATH.name}"

        except OSError as e:
            logger.error(
                f"CSV export failed: {e}"
            )

            return False, "Failed to export inventory report."


# EQUIPMENT REQUEST AND RESERVATION CONTROLLER
class AssetTrackingController:

    DATE_TIME_FORMAT = "%Y-%m-%d %H:%M"

    @classmethod
    def validate_time_range(cls, start_time, end_time):

        try:
            start_value = datetime.strptime(
                start_time,
                cls.DATE_TIME_FORMAT
            )

            end_value = datetime.strptime(
                end_time,
                cls.DATE_TIME_FORMAT
            )

        except ValueError:
            return False, (
                "Use the date and time format YYYY-MM-DD HH:MM."
            )

        if end_value <= start_value:
            return False, "The end time must be later than the start time."

        return True, ""

    @staticmethod
    def _get_user(cursor, username):

        cursor.execute(
            "SELECT id, role FROM users WHERE username = ?",
            (username,)
        )

        return cursor.fetchone()

    def fetch_hardware_options(self):

        try:
            conn = get_connection()
            cursor = conn.cursor()

            cursor.execute("""
                SELECT item_id, item_name, quantity, status
                FROM hardware
                ORDER BY item_name
            """)

            rows = cursor.fetchall()
            conn.close()

            return rows

        except sqlite3.Error as e:
            logger.error(f"Failed to fetch equipment options: {e}")
            return []

    def get_availability(
        self,
        item_id,
        start_time,
        end_time,
        excluded_request_id=None
    ):

        valid_time, message = self.validate_time_range(
            start_time,
            end_time
        )

        if not valid_time:
            return False, message, 0, 0

        try:
            conn = get_connection()
            cursor = conn.cursor()

            cursor.execute(
                "SELECT item_name, quantity FROM hardware WHERE item_id = ?",
                (item_id,)
            )

            hardware = cursor.fetchone()

            if not hardware:
                conn.close()
                return False, "The selected equipment was not found.", 0, 0

            item_name = hardware[0]
            total_quantity = hardware[1]

            query = """
                SELECT COALESCE(SUM(quantity), 0)
                FROM equipment_requests
                WHERE item_id = ?
                  AND status = 'Approved'
                  AND start_time < ?
                  AND end_time > ?
            """

            parameters = [item_id, end_time, start_time]

            if excluded_request_id is not None:
                query += " AND request_id != ?"
                parameters.append(excluded_request_id)

            cursor.execute(query, parameters)
            reserved_quantity = cursor.fetchone()[0]
            conn.close()

            available_quantity = max(
                total_quantity - reserved_quantity,
                0
            )

            return True, (
                f"{available_quantity} of {total_quantity} unit(s) of "
                f"{item_name} are available for the selected schedule."
            ), available_quantity, total_quantity

        except sqlite3.Error as e:
            logger.error(f"Availability check failed: {e}")
            return False, "Unable to check equipment availability.", 0, 0

    def submit_request(
        self,
        username,
        item_id,
        quantity,
        borrower_id_number,
        group_members,
        purpose,
        start_time,
        end_time
    ):

        try:
            validated = EquipmentRequestSchema(
                item_id=item_id,
                quantity=quantity,
                borrower_id_number=borrower_id_number,
                group_members=group_members,
                purpose=purpose,
                start_time=start_time,
                end_time=end_time
            )

        except ValidationError as e:
            return False, f"Validation Error: {e.errors()[0]['msg']}"

        valid_time, message = self.validate_time_range(
            validated.start_time,
            validated.end_time
        )

        if not valid_time:
            return False, message

        available, message, available_quantity, _ = self.get_availability(
            validated.item_id,
            validated.start_time,
            validated.end_time
        )

        if not available or validated.quantity > available_quantity:
            if available and validated.quantity > available_quantity:
                message = (
                    f"Only {available_quantity} unit(s) are available "
                    "for the selected schedule."
                )
            return False, message

        try:
            conn = get_connection()
            cursor = conn.cursor()
            user = self._get_user(cursor, username)

            if not user or user[1] != "USER":
                conn.close()
                return False, "Only a USER account may submit a request."

            cursor.execute(
                """
                INSERT INTO equipment_requests
                (
                    user_id,
                    borrower_id_number,
                    group_members,
                    item_id,
                    quantity,
                    purpose,
                    start_time,
                    end_time
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user[0],
                    validated.borrower_id_number,
                    validated.group_members,
                    validated.item_id,
                    validated.quantity,
                    validated.purpose.strip(),
                    validated.start_time,
                    validated.end_time
                )
            )

            request_id = cursor.lastrowid
            conn.commit()
            conn.close()

            logger.info(
                f"Equipment request {request_id} submitted by '{username}'."
            )

            return True, (
                f"Equipment request #{request_id} was submitted.\n"
                "Wait for an ADMIN to approve or decline it."
            )

        except sqlite3.Error as e:
            logger.error(f"Equipment request submission failed: {e}")
            return False, "Unable to submit the equipment request."

    def fetch_requests(self, username, role, status_filter="All Requests"):

        try:
            conn = get_connection()
            cursor = conn.cursor()

            query = """
                SELECT
                    requests.request_id,
                    users.username,
                    requests.borrower_id_number,
                    requests.group_members,
                    hardware.item_name,
                    requests.quantity,
                    requests.purpose,
                    requests.start_time,
                    requests.end_time,
                    requests.status,
                    COALESCE(requests.admin_note, '-'),
                    COALESCE(requests.reviewed_by, '-')
                FROM equipment_requests AS requests
                INNER JOIN users ON requests.user_id = users.id
                INNER JOIN hardware ON requests.item_id = hardware.item_id
                WHERE 1 = 1
            """

            parameters = []

            if role != "ADMIN":
                query += " AND users.username = ?"
                parameters.append(username)

            if status_filter in [
                "Pending",
                "Approved",
                "Rejected",
                "Cancelled"
            ]:
                query += " AND requests.status = ?"
                parameters.append(status_filter)

            query += " ORDER BY requests.start_time DESC, requests.request_id DESC"

            cursor.execute(query, parameters)
            rows = cursor.fetchall()
            conn.close()

            return rows

        except sqlite3.Error as e:
            logger.error(f"Failed to fetch equipment requests: {e}")
            return []

    def update_user_request(
        self,
        request_id,
        username,
        item_id,
        quantity,
        borrower_id_number,
        group_members,
        purpose,
        start_time,
        end_time
    ):

        try:
            validated = EquipmentRequestSchema(
                item_id=item_id,
                quantity=quantity,
                borrower_id_number=borrower_id_number,
                group_members=group_members,
                purpose=purpose,
                start_time=start_time,
                end_time=end_time
            )

        except ValidationError as e:
            return False, f"Validation Error: {e.errors()[0]['msg']}"

        valid_time, message = self.validate_time_range(
            validated.start_time,
            validated.end_time
        )

        if not valid_time:
            return False, message

        try:
            conn = get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT users.username, requests.status
                FROM equipment_requests AS requests
                INNER JOIN users ON requests.user_id = users.id
                WHERE requests.request_id = ?
                """,
                (request_id,)
            )

            request = cursor.fetchone()
            conn.close()

            if not request:
                return False, "The selected request was not found."

            if request[0] != username:
                return False, "You may edit only your own requests."

            if request[1] != "Pending":
                return False, "Only a pending request may be edited."

            available, message, available_quantity, _ = self.get_availability(
                validated.item_id,
                validated.start_time,
                validated.end_time,
                request_id
            )

            if not available or validated.quantity > available_quantity:
                if available and validated.quantity > available_quantity:
                    message = (
                        f"Only {available_quantity} unit(s) are available "
                        "for the selected schedule."
                    )
                return False, message

            conn = get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE equipment_requests
                SET item_id = ?,
                    quantity = ?,
                    borrower_id_number = ?,
                    group_members = ?,
                    purpose = ?,
                    start_time = ?,
                    end_time = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE request_id = ?
                """,
                (
                    validated.item_id,
                    validated.quantity,
                    validated.borrower_id_number,
                    validated.group_members,
                    validated.purpose.strip(),
                    validated.start_time,
                    validated.end_time,
                    request_id
                )
            )

            conn.commit()
            conn.close()

            logger.info(
                f"Equipment request {request_id} edited by '{username}'."
            )

            return True, "The pending equipment request was updated."

        except sqlite3.Error as e:
            logger.error(f"Equipment request update failed: {e}")
            return False, "Unable to update the equipment request."

    def review_request(
        self,
        request_id,
        admin_username,
        decision,
        admin_note=""
    ):

        if decision not in ["Approved", "Rejected"]:
            return False, "Invalid request decision."

        try:
            conn = get_connection()
            cursor = conn.cursor()
            admin = self._get_user(cursor, admin_username)

            if not admin or admin[1] != "ADMIN":
                conn.close()
                return False, "Only an ADMIN may review requests."

            cursor.execute(
                """
                SELECT item_id, quantity, start_time, end_time, status
                FROM equipment_requests
                WHERE request_id = ?
                """,
                (request_id,)
            )

            request = cursor.fetchone()
            conn.close()

            if not request:
                return False, "The selected request was not found."

            if request[4] != "Pending":
                return False, "Only a pending request may be reviewed."

            if decision == "Approved":
                available, message, available_quantity, _ = self.get_availability(
                    request[0],
                    request[2],
                    request[3],
                    request_id
                )

                if not available or request[1] > available_quantity:
                    if available and request[1] > available_quantity:
                        message = (
                            f"Approval would create a schedule conflict. Only "
                            f"{available_quantity} unit(s) remain available."
                        )
                    return False, message

            conn = get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE equipment_requests
                SET status = ?,
                    admin_note = ?,
                    reviewed_by = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE request_id = ?
                  AND status = 'Pending'
                """,
                (
                    decision,
                    admin_note.strip(),
                    admin_username,
                    request_id
                )
            )

            conn.commit()
            conn.close()

            logger.info(
                f"Equipment request {request_id} {decision.lower()} "
                f"by '{admin_username}'."
            )

            return True, f"Equipment request #{request_id} was {decision.lower()}."

        except sqlite3.Error as e:
            logger.error(f"Equipment request review failed: {e}")
            return False, "Unable to review the equipment request."

    def reschedule_request(
        self,
        request_id,
        admin_username,
        start_time,
        end_time
    ):

        valid_time, message = self.validate_time_range(start_time, end_time)

        if not valid_time:
            return False, message

        try:
            conn = get_connection()
            cursor = conn.cursor()
            admin = self._get_user(cursor, admin_username)

            if not admin or admin[1] != "ADMIN":
                conn.close()
                return False, "Only an ADMIN may reschedule requests."

            cursor.execute(
                """
                SELECT item_id, quantity, status
                FROM equipment_requests
                WHERE request_id = ?
                """,
                (request_id,)
            )

            request = cursor.fetchone()
            conn.close()

            if not request:
                return False, "The selected request was not found."

            if request[2] not in ["Pending", "Approved"]:
                return False, "Only pending or approved requests may be rescheduled."

            available, message, available_quantity, _ = self.get_availability(
                request[0],
                start_time,
                end_time,
                request_id
            )

            if not available or request[1] > available_quantity:
                if available and request[1] > available_quantity:
                    message = (
                        f"Only {available_quantity} unit(s) are available "
                        "for the new schedule."
                    )
                return False, message

            conn = get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE equipment_requests
                SET start_time = ?,
                    end_time = ?,
                    reviewed_by = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE request_id = ?
                """,
                (start_time, end_time, admin_username, request_id)
            )

            conn.commit()
            conn.close()

            logger.info(
                f"Equipment request {request_id} rescheduled "
                f"by '{admin_username}'."
            )

            return True, f"Equipment request #{request_id} was rescheduled."

        except sqlite3.Error as e:
            logger.error(f"Equipment request reschedule failed: {e}")
            return False, "Unable to reschedule the equipment request."

    def cancel_request(self, request_id, username, role):

        try:
            conn = get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT users.username, requests.status
                FROM equipment_requests AS requests
                INNER JOIN users ON requests.user_id = users.id
                WHERE requests.request_id = ?
                """,
                (request_id,)
            )

            request = cursor.fetchone()

            if not request:
                conn.close()
                return False, "The selected request was not found."

            if role != "ADMIN" and request[0] != username:
                conn.close()
                return False, "You may cancel only your own reservation."

            if request[1] not in ["Pending", "Approved"]:
                conn.close()
                return False, "Only pending or approved requests may be cancelled."

            cursor.execute(
                """
                UPDATE equipment_requests
                SET status = 'Cancelled',
                    reviewed_by = CASE
                        WHEN ? = 'ADMIN' THEN ?
                        ELSE reviewed_by
                    END,
                    updated_at = CURRENT_TIMESTAMP
                WHERE request_id = ?
                """,
                (role, username, request_id)
            )

            conn.commit()
            conn.close()

            logger.info(
                f"Equipment request {request_id} cancelled by '{username}'."
            )

            return True, f"Equipment request #{request_id} was cancelled."

        except sqlite3.Error as e:
            logger.error(f"Equipment request cancellation failed: {e}")
            return False, "Unable to cancel the equipment request."

# ============================================================
# DESKTOP ONLY — retained for the original desktop version
# The Flask web application must not create these windows.
# ============================================================
# LOGIN / REGISTER WINDOW
class LoginWindow:

    def __init__(
        self,
        root,
        on_login_success
    ):

        self.root = root
        self.on_login_success = on_login_success
        self.auth = AuthController()

        self.build_login()

    # LOGIN / REGISTRATION TABS
    def build_login(self):

        # Remove old widgets
        for widget in self.root.winfo_children():
            widget.destroy()

        self.root.title(
            "Campus Hardware Inventory - Authentication"
        )

        self.root.geometry("500x570")
        self.root.resizable(False, False)

        # Title
        tk.Label(
            self.root,
            text="Campus Hardware Inventory",
            font=("Arial", 16, "bold")
        ).pack(pady=(20, 5))

        tk.Label(
            self.root,
            text="User Authentication",
            font=("Arial", 11)
        ).pack(pady=(0, 15))

        # Notebook for separate Login and Register tabs
        self.auth_notebook = ttk.Notebook(self.root)
        self.auth_notebook.pack(
            fill="both",
            expand=True,
            padx=25,
            pady=(0, 20)
        )

        self.login_tab = ttk.Frame(self.auth_notebook)
        self.register_tab = ttk.Frame(self.auth_notebook)
        self.reset_tab = ttk.Frame(self.auth_notebook)

        self.auth_notebook.add(
            self.login_tab,
            text="Login"
        )

        self.auth_notebook.add(
            self.register_tab,
            text="Register"
        )

        self.auth_notebook.add(
            self.reset_tab,
            text="Reset / Unlock Password"
        )

        self.build_login_tab()
        self.build_register_tab()
        self.build_reset_tab()

    # BUILD LOGIN TAB
    def build_login_tab(self):

        form = tk.Frame(self.login_tab)
        form.pack(pady=(35, 10))

        # Login Username
        tk.Label(
            form,
            text="Username:"
        ).grid(
            row=0,
            column=0,
            sticky="e",
            padx=5,
            pady=10
        )

        self.entry_login_user = tk.Entry(
            form,
            width=27
        )

        self.entry_login_user.grid(
            row=0,
            column=1,
            padx=5,
            pady=10
        )

        # Login Password
        tk.Label(
            form,
            text="Password:"
        ).grid(
            row=1,
            column=0,
            sticky="e",
            padx=5,
            pady=10
        )

        self.entry_login_pass = tk.Entry(
            form,
            show="*",
            width=27
        )

        self.entry_login_pass.grid(
            row=1,
            column=1,
            padx=5,
            pady=10
        )

        # Show / Hide Login Password
        self.show_login_password_var = tk.BooleanVar()

        tk.Checkbutton(
            form,
            text="Show Password",
            variable=self.show_login_password_var,
            command=self.toggle_login_password
        ).grid(
            row=2,
            column=1,
            sticky="w",
            padx=5,
            pady=(0, 15)
        )

        tk.Button(
            self.login_tab,
            text="Login",
            width=20,
            bg="#4CAF50",
            fg="white",
            command=self.handle_login
        ).pack(pady=5)

        tk.Button(
            self.login_tab,
            text="Reset / Unlock Password",
            width=24,
            command=lambda: self.auth_notebook.select(self.reset_tab)
        ).pack(pady=5)

        self.entry_login_pass.bind(
            "<Return>",
            lambda event: self.handle_login()
        )

    # BUILD REGISTER TAB
    def build_register_tab(self):

        form = tk.Frame(self.register_tab)
        form.pack(pady=(15, 5))

        # Register Username
        tk.Label(
            form,
            text="Username:"
        ).grid(
            row=0,
            column=0,
            sticky="e",
            padx=5,
            pady=7
        )

        self.entry_register_user = tk.Entry(
            form,
            width=27
        )

        self.entry_register_user.grid(
            row=0,
            column=1,
            padx=5,
            pady=7
        )

        # Register Email
        tk.Label(
            form,
            text="Email:"
        ).grid(
            row=1,
            column=0,
            sticky="e",
            padx=5,
            pady=7
        )

        self.entry_register_email = tk.Entry(
            form,
            width=27
        )

        self.entry_register_email.grid(
            row=1,
            column=1,
            padx=5,
            pady=7
        )

        # Register Password
        tk.Label(
            form,
            text="Password:"
        ).grid(
            row=2,
            column=0,
            sticky="e",
            padx=5,
            pady=7
        )

        self.entry_register_pass = tk.Entry(
            form,
            show="*",
            width=27
        )

        self.entry_register_pass.grid(
            row=2,
            column=1,
            padx=5,
            pady=7
        )

        # Required User Role
        tk.Label(
            form,
            text="User Role:"
        ).grid(
            row=3,
            column=0,
            sticky="e",
            padx=5,
            pady=7
        )

        self.combo_register_role = ttk.Combobox(
            form,
            values=["ADMIN", "USER"],
            state="readonly",
            width=24
        )

        self.combo_register_role.grid(
            row=3,
            column=1,
            padx=5,
            pady=7
        )

        self.combo_register_role.set("Select a role")

        # Show / Hide Register Password
        self.show_register_password_var = tk.BooleanVar()

        tk.Checkbutton(
            form,
            text="Show Password",
            variable=self.show_register_password_var,
            command=self.toggle_register_password
        ).grid(
            row=4,
            column=1,
            sticky="w",
            padx=5,
            pady=(0, 5)
        )

        # Password Information
        tk.Label(
            self.register_tab,
            text=(
                "Password must have 8+ characters, an uppercase letter,\n"
                "a number, and a special character (@#$%^&*)."
            ),
            font=("Arial", 8),
            fg="gray"
        ).pack(pady=(0, 10))

        tk.Button(
            self.register_tab,
            text="Register",
            width=20,
            bg="#2196F3",
            fg="white",
            command=self.handle_register
        ).pack(pady=5)

        self.entry_register_pass.bind(
            "<Return>",
            lambda event: self.handle_register()
        )

    # BUILD RESET / UNLOCK PASSWORD TAB
    def build_reset_tab(self):

        tk.Label(
            self.reset_tab,
            text="Locked Account Password Reset",
            font=("Arial", 13, "bold")
        ).pack(pady=(25, 5))

        tk.Label(
            self.reset_tab,
            text=(
                "Enter the email registered to the locked account\n"
                "and choose a new password for ADMIN approval."
            ),
            justify="center"
        ).pack(pady=(0, 15))

        form = tk.Frame(self.reset_tab)
        form.pack(pady=5)

        tk.Label(
            form,
            text="Registered Email:"
        ).grid(
            row=0,
            column=0,
            sticky="e",
            padx=5,
            pady=10
        )

        self.entry_reset_email = tk.Entry(
            form,
            width=27
        )

        self.entry_reset_email.grid(
            row=0,
            column=1,
            padx=5,
            pady=10
        )

        tk.Label(
            form,
            text="New Password:"
        ).grid(
            row=1,
            column=0,
            sticky="e",
            padx=5,
            pady=10
        )

        self.entry_reset_password = tk.Entry(
            form,
            show="*",
            width=27
        )

        self.entry_reset_password.grid(
            row=1,
            column=1,
            padx=5,
            pady=10
        )

        self.show_reset_password_var = tk.BooleanVar()

        tk.Checkbutton(
            form,
            text="Show Password",
            variable=self.show_reset_password_var,
            command=self.toggle_reset_password
        ).grid(
            row=2,
            column=1,
            sticky="w",
            padx=5,
            pady=(0, 5)
        )

        tk.Label(
            self.reset_tab,
            text=(
                "New password must have 8+ characters, an uppercase letter,\n"
                "a number, and a special character (@#$%^&*)."
            ),
            font=("Arial", 8),
            fg="gray"
        ).pack(pady=(0, 10))

        tk.Button(
            self.reset_tab,
            text="Submit Password-Reset Request",
            width=28,
            bg="#FF9800",
            fg="white",
            command=self.handle_reset_request
        ).pack(pady=5)

        self.entry_reset_password.bind(
            "<Return>",
            lambda event: self.handle_reset_request()
        )

    # SHOW / HIDE LOGIN PASSWORD
    def toggle_login_password(self):

        if self.show_login_password_var.get():
            self.entry_login_pass.config(show="")

        else:
            self.entry_login_pass.config(show="*")

    # SHOW / HIDE REGISTER PASSWORD
    def toggle_register_password(self):

        if self.show_register_password_var.get():
            self.entry_register_pass.config(show="")

        else:
            self.entry_register_pass.config(show="*")

    # SHOW / HIDE RESET PASSWORD
    def toggle_reset_password(self):

        if self.show_reset_password_var.get():
            self.entry_reset_password.config(show="")

        else:
            self.entry_reset_password.config(show="*")

    # LOGIN BUTTON
    def handle_login(self):

        username = self.entry_login_user.get().strip()
        password = self.entry_login_pass.get()

        success, message, role, is_locked = self.auth.login_user(
            username,
            password
        )

        if success:
            messagebox.showinfo(
                "Login",
                f"{message}\nRole: {role}"
            )

            self.on_login_success(username, role)

        else:
            messagebox.showerror(
                "Authentication Failed",
                message
            )

            if is_locked:
                self.auth_notebook.select(self.reset_tab)
                self.entry_reset_email.focus_set()

    # REGISTER BUTTON
    def handle_register(self):

        username = self.entry_register_user.get().strip()
        email = self.entry_register_email.get().strip()
        password = self.entry_register_pass.get()
        role = self.combo_register_role.get()

        success, message = self.auth.register_user(
            username,
            email,
            password,
            role
        )

        if success:
            messagebox.showinfo(
                "Registration",
                message
            )

            # Clear registration fields
            self.entry_register_user.delete(0, tk.END)
            self.entry_register_email.delete(0, tk.END)
            self.entry_register_pass.delete(0, tk.END)
            self.combo_register_role.set("Select a role")

            self.show_register_password_var.set(False)
            self.entry_register_pass.config(show="*")

            # Place the registered username in the Login tab
            self.entry_login_user.delete(0, tk.END)
            self.entry_login_user.insert(0, username)
            self.entry_login_pass.delete(0, tk.END)

            # Automatically switch to the Login tab
            self.auth_notebook.select(self.login_tab)
            self.entry_login_pass.focus_set()

        else:
            messagebox.showwarning(
                "Registration Failed",
                message
            )

    # SUBMIT PASSWORD RESET REQUEST
    def handle_reset_request(self):

        email = self.entry_reset_email.get().strip()
        new_password = self.entry_reset_password.get()

        success, message = self.auth.submit_reset_request(
            email,
            new_password
        )

        if success:
            messagebox.showinfo(
                "Password Reset Request",
                message
            )

            self.entry_reset_email.delete(0, tk.END)
            self.entry_reset_password.delete(0, tk.END)
            self.show_reset_password_var.set(False)
            self.entry_reset_password.config(show="*")

            self.auth_notebook.select(self.login_tab)

        else:
            messagebox.showwarning(
                "Password Reset Request",
                message
            )


# ADMIN APPROVALS WINDOW
class AdminApprovalsWindow:

    def __init__(self, parent, admin_username):

        self.admin_username = admin_username
        self.auth = AuthController()

        self.window = tk.Toplevel(parent)
        self.window.title("Admin Approvals - Password Reset Requests")
        self.window.geometry("1100x520")
        self.window.resizable(True, True)

        tk.Label(
            self.window,
            text="Admin Approvals",
            font=("Arial", 18, "bold")
        ).pack(pady=(15, 3))

        tk.Label(
            self.window,
            text=(
                "Review password-reset requests and verify their updated status."
            )
        ).pack(pady=(0, 12))

        # REQUEST STATUS FILTER
        filter_frame = tk.Frame(self.window)
        filter_frame.pack(fill="x", padx=15, pady=(0, 5))

        tk.Label(
            filter_frame,
            text="Request Status:"
        ).pack(side="left", padx=(0, 5))

        self.request_status_filter_var = tk.StringVar(
            value="All Requests"
        )

        self.combo_request_status = ttk.Combobox(
            filter_frame,
            textvariable=self.request_status_filter_var,
            values=[
                "All Requests",
                "Pending",
                "Approved",
                "Rejected"
            ],
            state="readonly",
            width=18
        )

        self.combo_request_status.pack(side="left", padx=5)

        self.combo_request_status.bind(
            "<<ComboboxSelected>>",
            lambda event: self.load_requests()
        )

        table_frame = tk.Frame(self.window)
        table_frame.pack(
            fill="both",
            expand=True,
            padx=15,
            pady=5
        )

        scroll = ttk.Scrollbar(
            table_frame,
            orient="vertical"
        )

        scroll.pack(side="right", fill="y")

        self.tree = ttk.Treeview(
            table_frame,
            columns=(
                "Request ID",
                "Username",
                "Email",
                "Requested At",
                "Status",
                "Reviewed By",
                "Reviewed At"
            ),
            show="headings",
            yscrollcommand=scroll.set
        )

        scroll.config(command=self.tree.yview)

        columns = [
            ("Request ID", "Request ID", 90),
            ("Username", "Username", 120),
            ("Email", "Registered Email", 190),
            ("Requested At", "Requested At", 150),
            ("Status", "Status", 90),
            ("Reviewed By", "Reviewed By", 120),
            ("Reviewed At", "Reviewed At", 150)
        ]

        for column_id, heading, width in columns:
            self.tree.heading(column_id, text=heading)
            self.tree.column(
                column_id,
                width=width,
                anchor="center"
            )

        self.tree.tag_configure(
            "pending",
            background="#fff2cc"
        )

        self.tree.tag_configure(
            "approved",
            background="#ccffcc"
        )

        self.tree.tag_configure(
            "rejected",
            background="#ffcccc"
        )

        self.tree.pack(fill="both", expand=True)

        button_frame = tk.Frame(self.window)
        button_frame.pack(fill="x", padx=15, pady=12)

        tk.Button(
            button_frame,
            text="Approve Selected",
            bg="#4CAF50",
            fg="white",
            width=20,
            command=lambda: self.review_selected("Approved")
        ).pack(side="left", padx=5)

        tk.Button(
            button_frame,
            text="Reject Selected",
            bg="#F44336",
            fg="white",
            width=20,
            command=lambda: self.review_selected("Rejected")
        ).pack(side="left", padx=5)

        tk.Button(
            button_frame,
            text="Refresh",
            width=12,
            command=self.load_requests
        ).pack(side="right", padx=5)

        self.load_requests()

    # LOAD AND FILTER RESET REQUESTS
    def load_requests(self):

        for item in self.tree.get_children():
            self.tree.delete(item)

        requests = self.auth.fetch_reset_requests(
            self.request_status_filter_var.get()
        )

        for request in requests:
            status_tag = request[4].lower()

            self.tree.insert(
                "",
                tk.END,
                values=request,
                tags=(status_tag,)
            )

    # APPROVE OR REJECT SELECTED REQUEST
    def review_selected(self, decision):

        selected = self.tree.selection()

        if not selected:
            messagebox.showwarning(
                "Admin Approvals",
                "Select a password-reset request first.",
                parent=self.window
            )
            return

        values = self.tree.item(selected[0], "values")
        request_id = values[0]
        username = values[1]
        current_status = values[4]
        action_word = "Approve" if decision == "Approved" else "Reject"

        if current_status != "Pending":
            messagebox.showwarning(
                "Admin Approvals",
                "Only pending requests can be approved or rejected.",
                parent=self.window
            )
            return

        confirm = messagebox.askyesno(
            "Confirm Decision",
            f"{action_word} the request for '{username}'?",
            parent=self.window
        )

        if not confirm:
            return

        success, message = self.auth.review_reset_request(
            request_id,
            self.admin_username,
            decision
        )

        if success:
            messagebox.showinfo(
                "Admin Approvals",
                message,
                parent=self.window
            )

            # Show the reviewed row with its updated status immediately.
            self.request_status_filter_var.set("All Requests")
            self.load_requests()

        else:
            messagebox.showerror(
                "Admin Approvals",
                message,
                parent=self.window
            )


# INVENTORY WINDOW
class InventoryWindow:

    def __init__(
        self,
        root,
        username,
        role,
        on_logout
    ):

        self.root = root
        self.username = username
        self.role = role
        self.on_logout = on_logout
        self.controller = HardwareController()
        self.asset_controller = AssetTrackingController()
        self.auth_controller = AuthController()
        self.admin_approvals_window = None

        self.build_dashboard()

    # BUILD DASHBOARD
    def build_dashboard(self):

        for widget in self.root.winfo_children():
            widget.destroy()

        self.root.title("Campus Hardware Inventory")
        self.root.geometry("1380x850")
        self.root.resizable(True, True)

        # HEADER
        header = tk.Frame(
            self.root,
            padx=15,
            pady=10
        )

        header.pack(fill="x")

        tk.Label(
            header,
            text="Campus Hardware Inventory",
            font=("Arial", 18, "bold")
        ).pack(side="left")

        tk.Button(
            header,
            text="Logout",
            bg="#F44336",
            fg="white",
            width=10,
            command=self.logout
        ).pack(side="right")

        tk.Button(
            header,
            text="Hardware Catalog",
            bg="#2196F3",
            fg="white",
            width=16,
            command=self.open_hardware_catalog
        ).pack(side="right", padx=5)

        tk.Button(
            header,
            text="Requests",
            bg="#FF9800",
            fg="white",
            width=12,
            command=self.open_requests
        ).pack(side="right", padx=5)

        tk.Button(
            header,
            text="My Profile & Security",
            bg="#009688",
            fg="white",
            width=19,
            command=self.open_profile_security
        ).pack(side="right", padx=5)

        if self.role == "ADMIN":
            tk.Button(
                header,
                text="Admin Approvals",
                bg="#673AB7",
                fg="white",
                width=15,
                command=self.open_admin_approvals
            ).pack(side="right", padx=5)

        tk.Label(
            header,
            text=(
                f"Logged in as: {self.username}\n"
                f"Role: {self.role}"
            ),
            justify="right"
        ).pack(
            side="right",
            padx=15
        )

        # MAIN APPLICATION TABS
        self.main_notebook = ttk.Notebook(self.root)
        self.main_notebook.pack(
            fill="both",
            expand=True,
            padx=10,
            pady=(0, 10)
        )

        self.dashboard_tab = ttk.Frame(self.main_notebook)
        self.catalog_tab = ttk.Frame(self.main_notebook)
        self.requests_tab = ttk.Frame(self.main_notebook)
        self.profile_tab = ttk.Frame(self.main_notebook)

        self.main_notebook.add(
            self.dashboard_tab,
            text="Dashboard"
        )

        self.main_notebook.add(
            self.catalog_tab,
            text="Hardware Catalog"
        )

        self.main_notebook.add(
            self.requests_tab,
            text=(
                "Manage Requests"
                if self.role == "ADMIN"
                else "My Requests"
            )
        )

        self.main_notebook.add(
            self.profile_tab,
            text="My Profile & Security"
        )

        # DASHBOARD CONTENT
        tk.Label(
            self.dashboard_tab,
            text="Campus Hardware Inventory Dashboard",
            font=("Arial", 20, "bold")
        ).pack(pady=(80, 10))

        tk.Label(
            self.dashboard_tab,
            text=(
                "Track laboratory equipment, requests, approved reservations,\n"
                "and borrowing details in one system."
            ),
            font=("Arial", 11),
            justify="center"
        ).pack(pady=10)

        tk.Button(
            self.dashboard_tab,
            text=(
                "Review Equipment Requests"
                if self.role == "ADMIN"
                else "Request Laboratory Equipment"
            ),
            width=28,
            bg="#FF9800",
            fg="white",
            command=self.open_requests
        ).pack(pady=5)

        tk.Button(
            self.dashboard_tab,
            text="Open Hardware Catalog",
            width=28,
            bg="#2196F3",
            fg="white",
            command=self.open_hardware_catalog
        ).pack(pady=10)

        tk.Button(
            self.dashboard_tab,
            text="Open My Profile & Security",
            width=28,
            bg="#009688",
            fg="white",
            command=self.open_profile_security
        ).pack(pady=5)

        if self.role == "ADMIN":
            tk.Button(
                self.dashboard_tab,
                text="Open Admin Approvals",
                width=28,
                bg="#673AB7",
                fg="white",
                command=self.open_admin_approvals
            ).pack(pady=5)

        self.build_requests_tab()
        self.build_profile_security()

        # TOTAL VALUE BANNER
        self.total_label = tk.Label(
            self.catalog_tab,
            text="Total Inventory Value: $0.00",
            font=("Arial", 14, "bold"),
            relief="groove",
            padx=10,
            pady=10
        )

        self.total_label.pack(
            fill="x",
            padx=10,
            pady=5
        )

        if self.role != "ADMIN":
            self.total_label.pack_forget()

            tk.Label(
                self.catalog_tab,
                text=(
                    "Available laboratory equipment — select an item when "
                    "creating a borrowing request."
                ),
                fg="#9C5700",
                font=("Arial", 10, "bold")
            ).pack(pady=(2, 4))

        # ADD HARDWARE
        form = tk.LabelFrame(
            self.catalog_tab,
            text="Add New Hardware Component",
            padx=10,
            pady=10
        )

        form.pack(
            fill="x",
            padx=10,
            pady=5
        )

        # Item Name
        tk.Label(
            form,
            text="Item Name:"
        ).grid(
            row=0,
            column=0,
            padx=5,
            pady=5,
            sticky="e"
        )

        self.entry_name = tk.Entry(form, width=25)

        self.entry_name.grid(
            row=0,
            column=1,
            padx=5,
            pady=5
        )

        # Category
        tk.Label(
            form,
            text="Category:"
        ).grid(
            row=0,
            column=2,
            padx=5,
            pady=5,
            sticky="e"
        )

        self.entry_category = tk.Entry(form, width=20)

        self.entry_category.grid(
            row=0,
            column=3,
            padx=5,
            pady=5
        )

        # Quantity
        tk.Label(
            form,
            text="Quantity:"
        ).grid(
            row=1,
            column=0,
            padx=5,
            pady=5,
            sticky="e"
        )

        self.entry_quantity = tk.Entry(form, width=25)

        self.entry_quantity.grid(
            row=1,
            column=1,
            padx=5,
            pady=5
        )

        # Unit Price
        tk.Label(
            form,
            text="Unit Price ($):"
        ).grid(
            row=1,
            column=2,
            padx=5,
            pady=5,
            sticky="e"
        )

        self.entry_price = tk.Entry(form, width=20)

        self.entry_price.grid(
            row=1,
            column=3,
            padx=5,
            pady=5
        )

        # Add Button
        tk.Button(
            form,
            text="Save Hardware Record",
            bg="#4CAF50",
            fg="white",
            command=self.add_hardware
        ).grid(
            row=2,
            column=0,
            columnspan=4,
            sticky="ew",
            padx=5,
            pady=5
        )

        # SEARCH AND FILTER CONTROLS
        search_frame = tk.LabelFrame(
            self.catalog_tab,
            text="Search and Filter Hardware",
            padx=10,
            pady=8
        )

        search_frame.pack(
            fill="x",
            padx=10,
            pady=5
        )

        tk.Label(
            search_frame,
            text="Search:"
        ).grid(row=0, column=0, padx=5, pady=3)

        self.search_var = tk.StringVar()

        self.entry_search = tk.Entry(
            search_frame,
            textvariable=self.search_var,
            width=24
        )

        self.entry_search.grid(
            row=0,
            column=1,
            padx=5,
            pady=3
        )

        self.entry_search.bind(
            "<KeyRelease>",
            lambda event: self.load_data()
        )

        tk.Label(
            search_frame,
            text="Category:"
        ).grid(row=0, column=2, padx=5, pady=3)

        self.category_filter_var = tk.StringVar(
            value="All Categories"
        )

        self.combo_category_filter = ttk.Combobox(
            search_frame,
            textvariable=self.category_filter_var,
            values=["All Categories"],
            state="readonly",
            width=18
        )

        self.combo_category_filter.grid(
            row=0,
            column=3,
            padx=5,
            pady=3
        )

        self.combo_category_filter.bind(
            "<<ComboboxSelected>>",
            lambda event: self.load_data()
        )

        tk.Label(
            search_frame,
            text="Status:"
        ).grid(row=0, column=4, padx=5, pady=3)

        self.status_filter_var = tk.StringVar(
            value="All Statuses"
        )

        self.combo_status_filter = ttk.Combobox(
            search_frame,
            textvariable=self.status_filter_var,
            values=[
                "All Statuses",
                "In Stock",
                "Low Stock",
                "Out of Stock"
            ],
            state="readonly",
            width=15
        )

        self.combo_status_filter.grid(
            row=0,
            column=5,
            padx=5,
            pady=3
        )

        self.combo_status_filter.bind(
            "<<ComboboxSelected>>",
            lambda event: self.load_data()
        )

        tk.Button(
            search_frame,
            text="Clear Filters",
            command=self.clear_filters
        ).grid(row=0, column=6, padx=8, pady=3)

        # TREEVIEW
        table_frame = tk.Frame(self.catalog_tab)

        table_frame.pack(
            fill="both",
            expand=True,
            padx=10,
            pady=5
        )

        scroll = ttk.Scrollbar(
            table_frame,
            orient="vertical"
        )

        scroll.pack(
            side="right",
            fill="y"
        )

        if self.role == "ADMIN":
            hardware_column_ids = (
                "ID",
                "Name",
                "Category",
                "Qty",
                "Price",
                "Status"
            )

            columns = [
                ("ID", "ID", 50),
                ("Name", "Name", 180),
                ("Category", "Category", 130),
                ("Qty", "Qty", 70),
                ("Price", "Price ($)", 100),
                ("Status", "Status", 120)
            ]

        else:
            hardware_column_ids = (
                "ID",
                "Name",
                "Category",
                "Qty",
                "Status"
            )

            columns = [
                ("ID", "ID", 60),
                ("Name", "Equipment", 260),
                ("Category", "Category", 180),
                ("Qty", "Available Units", 120),
                ("Status", "Availability Status", 160)
            ]

        self.tree = ttk.Treeview(
            table_frame,
            columns=hardware_column_ids,
            show="headings",
            yscrollcommand=scroll.set
        )

        scroll.config(command=self.tree.yview)

        for column_id, heading, width in columns:
            self.tree.heading(
                column_id,
                text=heading
            )

            self.tree.column(
                column_id,
                width=width,
                anchor="center"
            )

        self.tree.column("Name", anchor="w")

        # Row Color Tags
        self.tree.tag_configure(
            "out_of_stock",
            background="#ffcccc"
        )

        self.tree.tag_configure(
            "low_stock",
            background="#fff2cc"
        )

        self.tree.tag_configure(
            "in_stock",
            background="#ccffcc"
        )

        self.tree.pack(
            fill="both",
            expand=True
        )

        self.tree.bind(
            "<<TreeviewSelect>>",
            self.on_select
        )

        # UPDATE SECTION
        update_frame = tk.LabelFrame(
            self.catalog_tab,
            text="Update Selected Item",
            padx=10,
            pady=10
        )

        update_frame.pack(
            fill="x",
            padx=10,
            pady=5
        )

        tk.Label(
            update_frame,
            text="New Quantity:"
        ).grid(
            row=0,
            column=0,
            padx=5
        )

        self.entry_update_quantity = tk.Entry(
            update_frame,
            width=12
        )

        self.entry_update_quantity.grid(
            row=0,
            column=1,
            padx=5
        )

        tk.Label(
            update_frame,
            text="New Unit Price ($):"
        ).grid(
            row=0,
            column=2,
            padx=5
        )

        self.entry_update_price = tk.Entry(
            update_frame,
            width=12
        )

        self.entry_update_price.grid(
            row=0,
            column=3,
            padx=5
        )

        tk.Button(
            update_frame,
            text="Update",
            bg="#2196F3",
            fg="white",
            command=self.update_item
        ).grid(
            row=0,
            column=4,
            padx=10
        )

        # DELETE
        self.delete_hardware_button = tk.Button(
            self.catalog_tab,
            text="Delete Selected",
            bg="#F44336",
            fg="white",
            command=self.delete_item
        )

        self.delete_hardware_button.pack(
            fill="x",
            padx=10,
            pady=5
        )

        # CSV EXPORT
        self.export_hardware_button = tk.Button(
            self.catalog_tab,
            text="Export Inventory to CSV Report",
            bg="#795548",
            fg="white",
            command=self.export_csv
        )

        self.export_hardware_button.pack(
            fill="x",
            padx=10,
            pady=5
        )

        if self.role != "ADMIN":
            # USER accounts receive a clean, view-only catalog. Price and all
            # inventory mutation controls are not displayed at all.
            form.pack_forget()
            update_frame.pack_forget()
            self.delete_hardware_button.pack_forget()
            self.export_hardware_button.pack_forget()

        self.load_data()

    # COMMON EQUIPMENT AND TIME OPTIONS
    def get_time_options(self):

        options = []

        for hour in range(7, 21):
            options.append(f"{hour:02d}:00")

            if hour < 20:
                options.append(f"{hour:02d}:30")

        return options

    def refresh_equipment_options(self):

        rows = self.asset_controller.fetch_hardware_options()
        self.equipment_option_map = {}
        values = []

        for item_id, item_name, quantity, status in rows:
            label = (
                f"{item_id} - {item_name} "
                f"({quantity} unit(s), {status})"
            )
            values.append(label)
            self.equipment_option_map[label] = item_id

        combo_names = [
            "request_equipment_combo"
        ]

        for combo_name in combo_names:
            if hasattr(self, combo_name):
                combo = getattr(self, combo_name)
                current_value = combo.get()
                combo.config(values=values)

                if current_value not in values:
                    combo.set(values[0] if values else "")

    def get_equipment_id(self, combo):

        return self.equipment_option_map.get(combo.get())

    def select_equipment_by_name(self, combo, equipment_name):

        for label in self.equipment_option_map:
            item_name = label.split(" - ", 1)[1].rsplit(" (", 1)[0]

            if item_name == equipment_name:
                combo.set(label)
                return

    @staticmethod
    def combine_date_time(date_value, time_value):

        return f"{date_value.strip()} {time_value.strip()}"

    # BUILD EQUIPMENT REQUESTS / RESERVATIONS TAB
    def build_requests_tab(self):

        tk.Label(
            self.requests_tab,
            text=(
                "Equipment Request Administration"
                if self.role == "ADMIN"
                else "Request Laboratory Equipment"
            ),
            font=("Arial", 18, "bold")
        ).pack(pady=(12, 5))

        tk.Label(
            self.requests_tab,
            text=(
                "Approve, decline, reschedule, or cancel equipment requests."
                if self.role == "ADMIN"
                else (
                    "Submit a request with its purpose, date, and time. "
                    "Pending requests may be edited or cancelled."
                )
            )
        ).pack(pady=(0, 8))

        if self.role == "USER":
            form = tk.LabelFrame(
                self.requests_tab,
                text="Request Details",
                padx=10,
                pady=8
            )
            form.pack(fill="x", padx=10, pady=5)

            tk.Label(form, text="Equipment:").grid(
                row=0, column=0, padx=4, pady=4, sticky="e"
            )

            self.request_equipment_combo = ttk.Combobox(
                form,
                state="readonly",
                width=44
            )
            self.request_equipment_combo.grid(
                row=0, column=1, columnspan=3, padx=4, pady=4, sticky="w"
            )

            tk.Label(form, text="Quantity:").grid(
                row=0, column=4, padx=4, pady=4, sticky="e"
            )

            self.request_quantity_entry = tk.Entry(form, width=8)
            self.request_quantity_entry.grid(
                row=0, column=5, padx=4, pady=4, sticky="w"
            )

            tk.Label(form, text="Borrower ID Number:").grid(
                row=1, column=0, padx=4, pady=4, sticky="e"
            )

            self.request_borrower_id_entry = tk.Entry(form, width=22)
            self.request_borrower_id_entry.grid(
                row=1, column=1, padx=4, pady=4, sticky="w"
            )

            tk.Label(form, text="Group Members:").grid(
                row=1, column=2, padx=4, pady=4, sticky="e"
            )

            self.request_group_members_entry = tk.Entry(form, width=42)
            self.request_group_members_entry.grid(
                row=1, column=3, columnspan=3, padx=4, pady=4, sticky="ew"
            )

            tk.Label(form, text="Purpose / Reason:").grid(
                row=2, column=0, padx=4, pady=4, sticky="e"
            )

            self.request_purpose_entry = tk.Entry(form, width=70)
            self.request_purpose_entry.grid(
                row=2, column=1, columnspan=5, padx=4, pady=4, sticky="ew"
            )

            tk.Label(form, text="Date (YYYY-MM-DD):").grid(
                row=3, column=0, padx=4, pady=4, sticky="e"
            )

            self.request_date_entry = tk.Entry(form, width=14)
            self.request_date_entry.grid(
                row=3, column=1, padx=4, pady=4, sticky="w"
            )
            self.request_date_entry.insert(
                0,
                datetime.now().strftime("%Y-%m-%d")
            )

            tk.Label(form, text="Start:").grid(
                row=3, column=2, padx=4, pady=4, sticky="e"
            )

            self.request_start_combo = ttk.Combobox(
                form,
                values=self.get_time_options(),
                state="readonly",
                width=8
            )
            self.request_start_combo.grid(
                row=3, column=3, padx=4, pady=4, sticky="w"
            )
            self.request_start_combo.set("08:00")

            tk.Label(form, text="End:").grid(
                row=3, column=4, padx=4, pady=4, sticky="e"
            )

            self.request_end_combo = ttk.Combobox(
                form,
                values=self.get_time_options(),
                state="readonly",
                width=8
            )
            self.request_end_combo.grid(
                row=3, column=5, padx=4, pady=4, sticky="w"
            )
            self.request_end_combo.set("09:00")

            button_frame = tk.Frame(form)
            button_frame.grid(
                row=4, column=0, columnspan=6, pady=5
            )

            tk.Button(
                button_frame,
                text="Submit Request",
                bg="#4CAF50",
                fg="white",
                width=18,
                command=self.submit_equipment_request
            ).pack(side="left", padx=4)

            tk.Button(
                button_frame,
                text="Update Selected",
                bg="#2196F3",
                fg="white",
                width=18,
                command=self.update_equipment_request
            ).pack(side="left", padx=4)

            tk.Button(
                button_frame,
                text="Clear Form",
                width=14,
                command=self.clear_request_form
            ).pack(side="left", padx=4)

        else:
            admin_frame = tk.LabelFrame(
                self.requests_tab,
                text="ADMIN Request Actions",
                padx=10,
                pady=8
            )
            admin_frame.pack(fill="x", padx=10, pady=5)

            tk.Label(admin_frame, text="Admin Note:").grid(
                row=0, column=0, padx=4, pady=4, sticky="e"
            )

            self.admin_request_note_entry = tk.Entry(
                admin_frame,
                width=48
            )
            self.admin_request_note_entry.grid(
                row=0, column=1, columnspan=3, padx=4, pady=4, sticky="w"
            )

            tk.Button(
                admin_frame,
                text="Approve",
                bg="#4CAF50",
                fg="white",
                width=13,
                command=lambda: self.review_equipment_request("Approved")
            ).grid(row=0, column=4, padx=4, pady=4)

            tk.Button(
                admin_frame,
                text="Decline",
                bg="#F44336",
                fg="white",
                width=13,
                command=lambda: self.review_equipment_request("Rejected")
            ).grid(row=0, column=5, padx=4, pady=4)

            tk.Label(admin_frame, text="New Date:").grid(
                row=1, column=0, padx=4, pady=4, sticky="e"
            )

            self.admin_reschedule_date_entry = tk.Entry(
                admin_frame,
                width=14
            )
            self.admin_reschedule_date_entry.grid(
                row=1, column=1, padx=4, pady=4, sticky="w"
            )

            tk.Label(admin_frame, text="Start:").grid(
                row=1, column=2, padx=4, pady=4, sticky="e"
            )

            self.admin_reschedule_start_combo = ttk.Combobox(
                admin_frame,
                values=self.get_time_options(),
                state="readonly",
                width=8
            )
            self.admin_reschedule_start_combo.grid(
                row=1, column=3, padx=4, pady=4, sticky="w"
            )

            tk.Label(admin_frame, text="End:").grid(
                row=1, column=4, padx=4, pady=4, sticky="e"
            )

            self.admin_reschedule_end_combo = ttk.Combobox(
                admin_frame,
                values=self.get_time_options(),
                state="readonly",
                width=8
            )
            self.admin_reschedule_end_combo.grid(
                row=1, column=5, padx=4, pady=4, sticky="w"
            )

            tk.Button(
                admin_frame,
                text="Reschedule Selected",
                bg="#FF9800",
                fg="white",
                width=20,
                command=self.reschedule_equipment_request
            ).grid(row=1, column=6, padx=4, pady=4)

        filter_frame = tk.Frame(self.requests_tab)
        filter_frame.pack(fill="x", padx=10, pady=5)

        tk.Label(filter_frame, text="Status:").pack(side="left")
        self.equipment_request_status_var = tk.StringVar(
            value="All Requests"
        )

        self.equipment_request_status_combo = ttk.Combobox(
            filter_frame,
            textvariable=self.equipment_request_status_var,
            values=[
                "All Requests",
                "Pending",
                "Approved",
                "Rejected",
                "Cancelled"
            ],
            state="readonly",
            width=16
        )
        self.equipment_request_status_combo.pack(side="left", padx=5)
        self.equipment_request_status_combo.bind(
            "<<ComboboxSelected>>",
            lambda event: self.load_equipment_requests()
        )

        tk.Button(
            filter_frame,
            text="Cancel Selected",
            bg="#795548",
            fg="white",
            width=16,
            command=self.cancel_equipment_request
        ).pack(side="left", padx=5)

        tk.Button(
            filter_frame,
            text="Refresh",
            width=12,
            command=self.load_equipment_requests
        ).pack(side="right", padx=5)

        request_table_frame = tk.Frame(self.requests_tab)
        request_table_frame.pack(
            fill="both", expand=True, padx=10, pady=(0, 10)
        )

        request_y_scroll = ttk.Scrollbar(
            request_table_frame,
            orient="vertical"
        )
        request_y_scroll.pack(side="right", fill="y")

        request_x_scroll = ttk.Scrollbar(
            request_table_frame,
            orient="horizontal"
        )
        request_x_scroll.pack(side="bottom", fill="x")

        request_columns = (
            "Request ID",
            "User",
            "Borrower ID",
            "Group Members",
            "Equipment",
            "Quantity",
            "Purpose",
            "Start",
            "End",
            "Status",
            "Admin Note",
            "Reviewed By"
        )

        self.request_tree = ttk.Treeview(
            request_table_frame,
            columns=request_columns,
            show="headings",
            yscrollcommand=request_y_scroll.set,
            xscrollcommand=request_x_scroll.set
        )

        request_y_scroll.config(command=self.request_tree.yview)
        request_x_scroll.config(command=self.request_tree.xview)

        request_widths = [
            80,
            100,
            115,
            210,
            155,
            70,
            220,
            130,
            130,
            85,
            180,
            100
        ]

        for column, width in zip(request_columns, request_widths):
            self.request_tree.heading(column, text=column)
            self.request_tree.column(column, width=width, anchor="center")

        self.request_tree.column("Purpose", anchor="w")
        self.request_tree.column("Group Members", anchor="w")
        self.request_tree.column("Admin Note", anchor="w")
        self.request_tree.tag_configure("pending", background="#fff2cc")
        self.request_tree.tag_configure("approved", background="#ccffcc")
        self.request_tree.tag_configure("rejected", background="#ffcccc")
        self.request_tree.tag_configure("cancelled", background="#e0e0e0")
        self.request_tree.pack(fill="both", expand=True)
        self.request_tree.bind(
            "<<TreeviewSelect>>",
            self.on_equipment_request_select
        )

        self.refresh_equipment_options()
        self.load_equipment_requests()

    # OPEN REQUESTS TAB
    def open_requests(self):

        self.refresh_equipment_options()
        self.load_equipment_requests()
        self.main_notebook.select(self.requests_tab)

    # LOAD EQUIPMENT REQUESTS
    def load_equipment_requests(self):

        selected = self.request_tree.selection()
        selected_id = None

        if selected:
            selected_id = self.request_tree.item(selected[0], "values")[0]

        for item in self.request_tree.get_children():
            self.request_tree.delete(item)

        rows = self.asset_controller.fetch_requests(
            self.username,
            self.role,
            self.equipment_request_status_var.get()
        )

        for row in rows:
            item = self.request_tree.insert(
                "",
                tk.END,
                values=row,
                tags=(row[9].lower(),)
            )

            if selected_id and str(row[0]) == str(selected_id):
                self.request_tree.selection_set(item)
                self.request_tree.focus(item)

    # SELECT REQUEST ROW
    def on_equipment_request_select(self, event):

        selected = self.request_tree.selection()

        if not selected:
            return

        values = self.request_tree.item(selected[0], "values")
        start_date, start_clock = values[7].split(" ")
        end_date, end_clock = values[8].split(" ")

        if self.role == "USER":
            self.select_equipment_by_name(
                self.request_equipment_combo,
                values[4]
            )
            self.request_quantity_entry.delete(0, tk.END)
            self.request_quantity_entry.insert(0, values[5])
            self.request_borrower_id_entry.delete(0, tk.END)
            self.request_borrower_id_entry.insert(0, values[2])
            self.request_group_members_entry.delete(0, tk.END)
            self.request_group_members_entry.insert(0, values[3])
            self.request_purpose_entry.delete(0, tk.END)
            self.request_purpose_entry.insert(0, values[6])
            self.request_date_entry.delete(0, tk.END)
            self.request_date_entry.insert(0, start_date)
            self.request_start_combo.set(start_clock)
            self.request_end_combo.set(end_clock)

        else:
            self.admin_request_note_entry.delete(0, tk.END)

            if values[10] != "-":
                self.admin_request_note_entry.insert(0, values[10])

            self.admin_reschedule_date_entry.delete(0, tk.END)
            self.admin_reschedule_date_entry.insert(0, start_date)
            self.admin_reschedule_start_combo.set(start_clock)
            self.admin_reschedule_end_combo.set(end_clock)

    # CLEAR USER REQUEST FORM
    def clear_request_form(self):

        if self.role != "USER":
            return

        self.request_quantity_entry.delete(0, tk.END)
        self.request_borrower_id_entry.delete(0, tk.END)
        self.request_group_members_entry.delete(0, tk.END)
        self.request_purpose_entry.delete(0, tk.END)
        self.request_date_entry.delete(0, tk.END)
        self.request_date_entry.insert(0, datetime.now().strftime("%Y-%m-%d"))
        self.request_start_combo.set("08:00")
        self.request_end_combo.set("09:00")

        for item in self.request_tree.selection():
            self.request_tree.selection_remove(item)

    # SUBMIT USER EQUIPMENT REQUEST
    def submit_equipment_request(self):

        item_id = self.get_equipment_id(self.request_equipment_combo)

        if item_id is None:
            messagebox.showwarning(
                "Equipment Request",
                "Select laboratory equipment first."
            )
            return

        try:
            quantity = int(self.request_quantity_entry.get().strip())

        except ValueError:
            messagebox.showwarning(
                "Equipment Request",
                "Quantity must be a whole number."
            )
            return

        start_time = self.combine_date_time(
            self.request_date_entry.get(),
            self.request_start_combo.get()
        )
        end_time = self.combine_date_time(
            self.request_date_entry.get(),
            self.request_end_combo.get()
        )

        success, message = self.asset_controller.submit_request(
            self.username,
            item_id,
            quantity,
            self.request_borrower_id_entry.get().strip(),
            self.request_group_members_entry.get().strip(),
            self.request_purpose_entry.get().strip(),
            start_time,
            end_time
        )

        if success:
            messagebox.showinfo("Equipment Request", message)
            self.clear_request_form()
            self.load_equipment_requests()

        else:
            messagebox.showerror("Equipment Request", message)

    # UPDATE USER EQUIPMENT REQUEST
    def update_equipment_request(self):

        selected = self.request_tree.selection()

        if not selected:
            messagebox.showwarning(
                "Equipment Request",
                "Select a pending request first."
            )
            return

        request_id = self.request_tree.item(selected[0], "values")[0]
        item_id = self.get_equipment_id(self.request_equipment_combo)

        if item_id is None:
            messagebox.showwarning(
                "Equipment Request",
                "Select laboratory equipment first."
            )
            return

        try:
            quantity = int(self.request_quantity_entry.get().strip())

        except ValueError:
            messagebox.showwarning(
                "Equipment Request",
                "Quantity must be a whole number."
            )
            return

        success, message = self.asset_controller.update_user_request(
            request_id,
            self.username,
            item_id,
            quantity,
            self.request_borrower_id_entry.get().strip(),
            self.request_group_members_entry.get().strip(),
            self.request_purpose_entry.get().strip(),
            self.combine_date_time(
                self.request_date_entry.get(),
                self.request_start_combo.get()
            ),
            self.combine_date_time(
                self.request_date_entry.get(),
                self.request_end_combo.get()
            )
        )

        if success:
            messagebox.showinfo("Equipment Request", message)
            self.clear_request_form()
            self.load_equipment_requests()

        else:
            messagebox.showerror("Equipment Request", message)

    # ADMIN APPROVE OR DECLINE REQUEST
    def review_equipment_request(self, decision):

        selected = self.request_tree.selection()

        if not selected:
            messagebox.showwarning(
                "Equipment Request",
                "Select a pending request first."
            )
            return

        values = self.request_tree.item(selected[0], "values")
        action = "approve" if decision == "Approved" else "decline"

        confirm = messagebox.askyesno(
            "Confirm Request Decision",
            f"Do you want to {action} request #{values[0]}?"
        )

        if not confirm:
            return

        success, message = self.asset_controller.review_request(
            values[0],
            self.username,
            decision,
            self.admin_request_note_entry.get().strip()
        )

        if success:
            messagebox.showinfo("Equipment Request", message)
            self.admin_request_note_entry.delete(0, tk.END)
            self.load_equipment_requests()

        else:
            messagebox.showerror("Equipment Request", message)

    # ADMIN RESCHEDULE REQUEST
    def reschedule_equipment_request(self):

        selected = self.request_tree.selection()

        if not selected:
            messagebox.showwarning(
                "Equipment Request",
                "Select a pending or approved request first."
            )
            return

        request_id = self.request_tree.item(selected[0], "values")[0]
        start_time = self.combine_date_time(
            self.admin_reschedule_date_entry.get(),
            self.admin_reschedule_start_combo.get()
        )
        end_time = self.combine_date_time(
            self.admin_reschedule_date_entry.get(),
            self.admin_reschedule_end_combo.get()
        )

        success, message = self.asset_controller.reschedule_request(
            request_id,
            self.username,
            start_time,
            end_time
        )

        if success:
            messagebox.showinfo("Equipment Request", message)
            self.load_equipment_requests()

        else:
            messagebox.showerror("Equipment Request", message)

    # USER OR ADMIN CANCEL REQUEST
    def cancel_equipment_request(self):

        selected = self.request_tree.selection()

        if not selected:
            messagebox.showwarning(
                "Equipment Request",
                "Select a pending or approved request first."
            )
            return

        values = self.request_tree.item(selected[0], "values")

        confirm = messagebox.askyesno(
            "Cancel Equipment Request",
            f"Cancel equipment request #{values[0]}?"
        )

        if not confirm:
            return

        success, message = self.asset_controller.cancel_request(
            values[0],
            self.username,
            self.role
        )

        if success:
            messagebox.showinfo("Equipment Request", message)
            self.load_equipment_requests()

        else:
            messagebox.showerror("Equipment Request", message)

    # BUILD MY PROFILE & SECURITY TAB
    def build_profile_security(self):

        tk.Label(
            self.profile_tab,
            text="My Profile & Security",
            font=("Arial", 20, "bold")
        ).pack(pady=(30, 15))

        # ACCOUNT INFORMATION
        profile_frame = tk.LabelFrame(
            self.profile_tab,
            text="Account Information",
            padx=20,
            pady=15
        )

        profile_frame.pack(
            fill="x",
            padx=100,
            pady=10
        )

        self.profile_username_var = tk.StringVar()
        self.profile_email_var = tk.StringVar()
        self.profile_role_var = tk.StringVar()

        profile_fields = [
            ("Username:", self.profile_username_var),
            ("Registered Email:", self.profile_email_var),
            ("Assigned Role:", self.profile_role_var)
        ]

        for row_number, (label_text, value_variable) in enumerate(
            profile_fields
        ):
            tk.Label(
                profile_frame,
                text=label_text,
                font=("Arial", 10, "bold")
            ).grid(
                row=row_number,
                column=0,
                sticky="e",
                padx=10,
                pady=7
            )

            tk.Label(
                profile_frame,
                textvariable=value_variable,
                anchor="w",
                width=35,
                relief="sunken",
                padx=8,
                pady=4
            ).grid(
                row=row_number,
                column=1,
                sticky="w",
                padx=10,
                pady=7
            )

        # DIRECT PASSWORD CHANGE
        security_frame = tk.LabelFrame(
            self.profile_tab,
            text="Change Account Password",
            padx=20,
            pady=15
        )

        security_frame.pack(
            fill="x",
            padx=100,
            pady=10
        )

        password_fields = [
            ("Current Password:", "current"),
            ("New Password:", "new"),
            ("Confirm New Password:", "confirm")
        ]

        for row_number, (label_text, field_name) in enumerate(
            password_fields
        ):
            tk.Label(
                security_frame,
                text=label_text
            ).grid(
                row=row_number,
                column=0,
                sticky="e",
                padx=8,
                pady=7
            )

            entry = tk.Entry(
                security_frame,
                show="*",
                width=32
            )

            entry.grid(
                row=row_number,
                column=1,
                padx=8,
                pady=7
            )

            if field_name == "current":
                self.entry_profile_current_password = entry

            elif field_name == "new":
                self.entry_profile_new_password = entry

            else:
                self.entry_profile_confirm_password = entry

        self.show_profile_passwords_var = tk.BooleanVar()

        tk.Checkbutton(
            security_frame,
            text="Show Passwords",
            variable=self.show_profile_passwords_var,
            command=self.toggle_profile_passwords
        ).grid(
            row=3,
            column=1,
            sticky="w",
            padx=8,
            pady=(0, 5)
        )

        tk.Label(
            security_frame,
            text=(
                "The new password must have 8+ characters, an uppercase "
                "letter,\n a number, and a special character (@#$%^&*)."
            ),
            font=("Arial", 8),
            fg="gray",
            justify="left"
        ).grid(
            row=4,
            column=0,
            columnspan=2,
            pady=(0, 10)
        )

        tk.Button(
            security_frame,
            text="Change Password",
            width=22,
            bg="#009688",
            fg="white",
            command=self.handle_direct_password_change
        ).grid(
            row=5,
            column=0,
            columnspan=2,
            pady=5
        )

        self.entry_profile_confirm_password.bind(
            "<Return>",
            lambda event: self.handle_direct_password_change()
        )

        self.refresh_profile_information()

    # OPEN MY PROFILE & SECURITY
    def open_profile_security(self):

        self.refresh_profile_information()
        self.main_notebook.select(self.profile_tab)
        self.entry_profile_current_password.focus_set()

    # REFRESH DISPLAYED PROFILE INFORMATION
    def refresh_profile_information(self):

        profile = self.auth_controller.get_user_profile(
            self.username
        )

        if profile:
            self.profile_username_var.set(profile[0])
            self.profile_email_var.set(profile[1])
            self.profile_role_var.set(profile[2])

        else:
            self.profile_username_var.set("Unavailable")
            self.profile_email_var.set("Unavailable")
            self.profile_role_var.set("Unavailable")

    # SHOW / HIDE PROFILE PASSWORD FIELDS
    def toggle_profile_passwords(self):

        show_value = "" if self.show_profile_passwords_var.get() else "*"

        self.entry_profile_current_password.config(show=show_value)
        self.entry_profile_new_password.config(show=show_value)
        self.entry_profile_confirm_password.config(show=show_value)

    # DIRECT PASSWORD-CHANGE BUTTON
    def handle_direct_password_change(self):

        current_password = (
            self.entry_profile_current_password.get()
        )

        new_password = self.entry_profile_new_password.get()
        confirm_password = self.entry_profile_confirm_password.get()

        success, message = self.auth_controller.change_password(
            self.username,
            current_password,
            new_password,
            confirm_password
        )

        if success:
            self.entry_profile_current_password.delete(0, tk.END)
            self.entry_profile_new_password.delete(0, tk.END)
            self.entry_profile_confirm_password.delete(0, tk.END)
            self.show_profile_passwords_var.set(False)
            self.toggle_profile_passwords()

            logout_now = messagebox.askyesno(
                "Password Changed",
                f"{message}\n\nLog out now?"
            )

            if logout_now:
                self.logout()

        else:
            messagebox.showerror(
                "Password Change Failed",
                message
            )

    # OPEN HARDWARE CATALOG
    def open_hardware_catalog(self):

        self.main_notebook.select(self.catalog_tab)
        self.load_data()
        self.entry_search.focus_set()

    # CLEAR SEARCH AND FILTERS
    def clear_filters(self):

        self.search_var.set("")
        self.category_filter_var.set("All Categories")
        self.status_filter_var.set("All Statuses")
        self.load_data()

    # REFRESH CATEGORY FILTER OPTIONS
    def refresh_category_filter(self):

        categories = self.controller.fetch_categories()
        values = ["All Categories"] + categories

        self.combo_category_filter.config(values=values)

        if self.category_filter_var.get() not in values:
            self.category_filter_var.set("All Categories")

    # CLEAR ADD FORM
    def clear_entries(self):

        self.entry_name.delete(0, tk.END)
        self.entry_category.delete(0, tk.END)
        self.entry_quantity.delete(0, tk.END)
        self.entry_price.delete(0, tk.END)

    # ADD HARDWARE
    def add_hardware(self):

        if self.role != "ADMIN":
            messagebox.showerror(
                "Access Denied",
                "Only an ADMIN may add hardware records."
            )
            return

        name = self.entry_name.get().strip()
        category = self.entry_category.get().strip()
        quantity_text = self.entry_quantity.get().strip()
        price_text = self.entry_price.get().strip()

        try:
            quantity = int(quantity_text)
            price = float(price_text)

        except ValueError:
            logger.warning(
                "Hardware validation failed - "
                "quantity or price was not numeric."
            )

            messagebox.showwarning(
                "Input Error",
                "Quantity must be an integer and "
                "Unit Price must be numeric."
            )

            return

        success, message = self.controller.add_hardware(
            name,
            category,
            quantity,
            price
        )

        if success:
            self.clear_entries()
            self.load_data()

            messagebox.showinfo(
                "Success",
                message
            )

        else:
            messagebox.showerror(
                "Error",
                message
            )

    # LOAD DATA
    def load_data(self):

        self.refresh_category_filter()

        # Save selected hardware ID
        selected = self.tree.selection()
        selected_id = None

        if selected:
            selected_id = self.tree.item(
                selected[0],
                "values"
            )[0]

        # Clear current rows
        for item in self.tree.get_children():
            self.tree.delete(item)

        rows = self.controller.fetch_all_hardware(
            self.search_var.get().strip(),
            self.category_filter_var.get(),
            self.status_filter_var.get()
        )

        # Reinsert rows
        for row in rows:
            item_id = row[0]
            name = row[1]
            category = row[2]
            quantity = row[3]
            price = row[4]
            status = row[5]

            # Row Color
            if status == "Out of Stock":
                tag = "out_of_stock"

            elif status == "Low Stock":
                tag = "low_stock"

            else:
                tag = "in_stock"

            if self.role == "ADMIN":
                display_values = (
                    item_id,
                    name,
                    category,
                    quantity,
                    f"${price:,.2f}",
                    status
                )

            else:
                display_values = (
                    item_id,
                    name,
                    category,
                    quantity,
                    status
                )

            item = self.tree.insert(
                "",
                tk.END,
                values=display_values,
                tags=(tag,)
            )

            # Restore previous selection
            if selected_id and str(item_id) == str(selected_id):
                self.tree.selection_set(item)
                self.tree.focus(item)

        # Inventory valuation is restricted to ADMIN accounts.
        if self.role == "ADMIN":
            self.update_total_value()

    # UPDATE TOTAL VALUE
    def update_total_value(self):

        total = self.controller.get_total_value()

        self.total_label.config(
            text=(
                "Total Inventory Value: "
                f"${total:,.2f}"
            )
        )

    # TREEVIEW SELECTION
    def on_select(self, event):

        if self.role != "ADMIN":
            return

        selected = self.tree.selection()

        if not selected:
            return

        values = self.tree.item(
            selected[0],
            "values"
        )

        self.entry_update_quantity.delete(0, tk.END)
        self.entry_update_quantity.insert(0, values[3])

        self.entry_update_price.delete(0, tk.END)
        self.entry_update_price.insert(
            0,
            values[4].replace("$", "").replace(",", "")
        )

    # UPDATE ITEM
    def update_item(self):

        if self.role != "ADMIN":
            messagebox.showerror(
                "Access Denied",
                "Only an ADMIN may update hardware records."
            )
            return

        selected = self.tree.selection()

        if not selected:
            messagebox.showwarning(
                "Selection",
                "Select an item first."
            )

            return

        try:
            quantity = int(
                self.entry_update_quantity.get()
            )

            price = float(
                self.entry_update_price.get()
            )

        except ValueError:
            logger.warning(
                "Hardware update validation failed - "
                "invalid quantity or unit price."
            )

            messagebox.showwarning(
                "Input Error",
                "Enter a valid quantity and unit price."
            )

            return

        item_id = self.tree.item(
            selected[0],
            "values"
        )[0]

        success, message = self.controller.update_hardware(
            item_id,
            quantity,
            price
        )

        if success:
            self.load_data()

            messagebox.showinfo(
                "Updated",
                message
            )

        else:
            messagebox.showerror(
                "Error",
                message
            )

    # DELETE ITEM
    def delete_item(self):

        if self.role != "ADMIN":
            messagebox.showerror(
                "Access Denied",
                "Only an ADMIN may delete hardware records."
            )
            return

        selected = self.tree.selection()

        if not selected:
            messagebox.showwarning(
                "Selection",
                "Select an item first."
            )

            return

        values = self.tree.item(
            selected[0],
            "values"
        )

        item_id = values[0]
        item_name = values[1]

        confirm = messagebox.askyesno(
            "Confirm Delete",
            f"Delete '{item_name}'?"
        )

        if not confirm:
            return

        success, message = self.controller.delete_hardware(
            item_id
        )

        if success:
            self.load_data()

            messagebox.showinfo(
                "Deleted",
                message
            )

        else:
            messagebox.showerror(
                "Error",
                message
            )

    # EXPORT CSV
    def export_csv(self):

        if self.role != "ADMIN":
            messagebox.showerror(
                "Access Denied",
                "Only an ADMIN may export inventory reports."
            )
            return

        success, message = self.controller.export_csv()

        if success:
            messagebox.showinfo(
                "CSV Export",
                message
            )

        else:
            messagebox.showerror(
                "CSV Export",
                message
            )

    # OPEN ADMIN APPROVALS
    def open_admin_approvals(self):

        if self.role != "ADMIN":
            messagebox.showerror(
                "Access Denied",
                "Only an ADMIN may open Admin Approvals."
            )
            return

        AdminApprovalsWindow(
            self.root,
            self.username
        )

    # LOGOUT
    def logout(self):

        logger.info(f"User logged out: '{self.username}' ({self.role})")
        self.on_logout()


# APPLICATION CONTROL
class Application:
    def __init__(self):
        init_db()
        self.root = tk.Tk()

        # Authentication data is stored in SQLite and remains available
        # after logout or after restarting the program.
        self.auth_controller = AuthController()
        self.show_login()
        self.root.mainloop()

    # SHOW LOGIN
    def show_login(self):
        login_window = LoginWindow(self.root, self.login_success)
        # Use the same authentication controller
        login_window.auth = self.auth_controller

    # LOGIN SUCCESS
    def login_success(self, username, role):
        InventoryWindow(self.root, username, role, self.logout)

    # LOGOUT
    def logout(self):
        self.show_login()


# main.py
#if __name__ == "__main__":
    #Application()

if __name__ == "__main__":
    if tk is None:
        raise RuntimeError(
            "Tkinter is unavailable. Run app.py for the Flask web version."
        )

    Application()