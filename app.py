# ==========================================================
# ENGINEERING LABORATORY ASSET TRACKING SYSTEM
# Flask Web Application
# ==========================================================

from dotenv import load_dotenv

load_dotenv()

from functools import wraps
import os

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    send_file
)

# Reuse the original desktop program
from engineering_laboratory import (
    init_db,
    get_connection,
    AuthController,
    HardwareController,
    AssetTrackingController,
    CSV_PATH
)


# ==========================================================
# CREATE FLASK APPLICATION
# ==========================================================


app = Flask(__name__)

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "lab1-development-secret-change-me"
)


# Create controller objects
auth_controller = AuthController()
hardware_controller = HardwareController()
asset_controller = AssetTrackingController()


# Initialize the existing database
init_db()


# ==========================================================
# HELPER FUNCTIONS
# ==========================================================

def normalize_datetime(value):
    """
    Convert an HTML datetime-local value:
    2026-09-11T14:30

    Into the format used by the desktop system:
    2026-09-11 14:30
    """

    return value.strip().replace("T", " ")[:16]


def get_selected_ids(field_name):
    """Convert selected form values into integer IDs."""

    raw_ids = request.form.getlist(field_name)
    selected_ids = []

    for raw_id in raw_ids:
        try:
            selected_ids.append(int(raw_id))
        except ValueError:
            continue

    return selected_ids

# QUANTITY-BASED BORROW AND RETURN FUNCTIONS

def create_borrow_request(
    username,
    item_id,
    quantity,
    borrower_id_number,
    group_members,
    purpose,
    start_time,
    end_time
):
    """
    Create a pending borrow request without deducting stock.
    """

    valid_time, message = (
        asset_controller.validate_time_range(
            start_time,
            end_time
        )
    )

    if not valid_time:
        return False, message

    if quantity < 1:
        return False, "Requested quantity must be at least 1."

    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT id, role
            FROM users
            WHERE username = ?
            """,
            (username,)
        )

        user = cursor.fetchone()

        if not user or user[1] != "USER":
            conn.close()
            return False, "Only USER accounts may borrow equipment."

        cursor.execute(
            """
            SELECT item_name, quantity
            FROM hardware
            WHERE item_id = ?
            """,
            (item_id,)
        )

        item = cursor.fetchone()

        if not item:
            conn.close()
            return False, "The selected equipment was not found."

        available_stock = item[1]

        if quantity > available_stock:
            conn.close()

            return False, (
                f"Only {available_stock} unit(s) of "
                f"{item[0]} are currently available."
            )

        cursor.execute(
            """
            INSERT INTO equipment_requests (
                user_id,
                borrower_id_number,
                group_members,
                item_id,
                quantity,
                purpose,
                start_time,
                end_time,
                status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'PENDING_BORROW')
            """,
            (
                user[0],
                borrower_id_number,
                group_members or "None",
                item_id,
                quantity,
                purpose,
                start_time,
                end_time
            )
        )

        request_id = cursor.lastrowid

        conn.commit()
        conn.close()

        return True, (
            f"Borrow request #{request_id} submitted. "
            "Stock will not be deducted until ADMIN approval."
        )

    except Exception as error:
        return False, f"Unable to submit borrow request: {error}"


def process_borrow_request(
    request_id,
    admin_username,
    approve,
    admin_note=""
):
    """
    Approve or reject a pending borrow request.

    Approval deducts the requested quantity.
    Rejection does not change the stock.
    """

    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("BEGIN IMMEDIATE")

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
            conn.rollback()
            conn.close()
            return False, "Only an ADMIN may review borrow requests."

        cursor.execute(
            """
            SELECT item_id, quantity, status
            FROM equipment_requests
            WHERE request_id = ?
            """,
            (request_id,)
        )

        borrow_request = cursor.fetchone()

        if not borrow_request:
            conn.rollback()
            conn.close()
            return False, f"Borrow request #{request_id} was not found."

        item_id = borrow_request[0]
        requested_quantity = borrow_request[1]
        current_status = borrow_request[2]

        if current_status != "PENDING_BORROW":
            conn.rollback()
            conn.close()

            return False, (
                f"Borrow request #{request_id} is no longer pending."
            )

        if not approve:
            cursor.execute(
                """
                UPDATE equipment_requests
                SET status = 'REJECTED',
                    admin_note = ?,
                    reviewed_by = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE request_id = ?
                """,
                (
                    admin_note,
                    admin_username,
                    request_id
                )
            )

            conn.commit()
            conn.close()

            return True, (
                f"Borrow request #{request_id} was rejected. "
                "Stock was not changed."
            )

        cursor.execute(
            """
            SELECT quantity
            FROM hardware
            WHERE item_id = ?
            """,
            (item_id,)
        )

        hardware = cursor.fetchone()

        if not hardware:
            conn.rollback()
            conn.close()
            return False, "The requested hardware was not found."

        available_stock = hardware[0]

        if requested_quantity > available_stock:
            conn.rollback()
            conn.close()

            return False, (
                f"Request #{request_id} cannot be approved. "
                f"Only {available_stock} unit(s) remain available."
            )

        new_quantity = (
            available_stock - requested_quantity
        )

        new_stock_status = (
            hardware_controller.get_status(new_quantity)
        )

        cursor.execute(
            """
            UPDATE hardware
            SET quantity = ?,
                status = ?
            WHERE item_id = ?
            """,
            (
                new_quantity,
                new_stock_status,
                item_id
            )
        )

        cursor.execute(
            """
            UPDATE equipment_requests
            SET status = 'BORROWED',
                admin_note = ?,
                reviewed_by = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE request_id = ?
            """,
            (
                admin_note,
                admin_username,
                request_id
            )
        )

        conn.commit()
        conn.close()

        return True, (
            f"Borrow request #{request_id} approved. "
            f"{requested_quantity} unit(s) were deducted."
        )

    except Exception as error:
        return False, f"Unable to process borrow request: {error}"


def submit_return_requests(request_ids, username):
    """
    Change the user's BORROWED records to RETURN_PENDING.
    Stock is not restored until ADMIN approval.
    """

    if not request_ids:
        return False, "Select at least one borrowed item."

    try:
        conn = get_connection()
        cursor = conn.cursor()

        changed = 0

        for request_id in request_ids:
            cursor.execute(
                """
                UPDATE equipment_requests
                SET status = 'RETURN_PENDING',
                    updated_at = CURRENT_TIMESTAMP
                WHERE request_id = ?
                  AND user_id = (
                      SELECT id
                      FROM users
                      WHERE username = ?
                  )
                  AND status = 'BORROWED'
                """,
                (
                    request_id,
                    username
                )
            )

            changed += cursor.rowcount

        conn.commit()
        conn.close()

        if changed == 0:
            return False, "No borrowed items were selected."

        return True, (
            f"{changed} item return request(s) submitted."
        )

    except Exception as error:
        return False, f"Unable to request return: {error}"


def process_return_request(
    request_id,
    admin_username,
    approve
):
    """
    Approve or reject a pending return.

    Approval restores stock and marks the request RETURNED.
    Rejection changes the request back to BORROWED.
    """

    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("BEGIN IMMEDIATE")

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
            conn.rollback()
            conn.close()
            return False, "Only an ADMIN may review returns."

        cursor.execute(
            """
            SELECT item_id, quantity, status
            FROM equipment_requests
            WHERE request_id = ?
            """,
            (request_id,)
        )

        return_request_record = cursor.fetchone()

        if not return_request_record:
            conn.rollback()
            conn.close()
            return False, f"Return request #{request_id} was not found."

        item_id = return_request_record[0]
        returned_quantity = return_request_record[1]
        current_status = return_request_record[2]

        if current_status != "RETURN_PENDING":
            conn.rollback()
            conn.close()

            return False, (
                f"Return request #{request_id} is no longer pending."
            )

        if not approve:
            cursor.execute(
                """
                UPDATE equipment_requests
                SET status = 'BORROWED',
                    reviewed_by = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE request_id = ?
                """,
                (
                    admin_username,
                    request_id
                )
            )

            conn.commit()
            conn.close()

            return True, (
                f"Return request #{request_id} was rejected. "
                "The item remains borrowed."
            )

        cursor.execute(
            """
            SELECT quantity
            FROM hardware
            WHERE item_id = ?
            """,
            (item_id,)
        )

        hardware = cursor.fetchone()

        if not hardware:
            conn.rollback()
            conn.close()
            return False, "The returned hardware was not found."

        new_quantity = (
            hardware[0] + returned_quantity
        )

        new_stock_status = (
            hardware_controller.get_status(new_quantity)
        )

        cursor.execute(
            """
            UPDATE hardware
            SET quantity = ?,
                status = ?
            WHERE item_id = ?
            """,
            (
                new_quantity,
                new_stock_status,
                item_id
            )
        )

        cursor.execute(
            """
            UPDATE equipment_requests
            SET status = 'RETURNED',
                reviewed_by = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE request_id = ?
            """,
            (
                admin_username,
                request_id
            )
        )

        conn.commit()
        conn.close()

        return True, (
            f"Return request #{request_id} approved. "
            f"{returned_quantity} unit(s) were restored."
        )

    except Exception as error:
        return False, f"Unable to process return request: {error}"

# ==========================================================
# LOGIN PROTECTION
# ==========================================================

def login_required(view):

    @wraps(view)
    def wrapped(*args, **kwargs):

        if "username" not in session:
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))

        return view(*args, **kwargs)

    return wrapped


def admin_required(view):

    @wraps(view)
    def wrapped(*args, **kwargs):

        if "username" not in session:
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))

        if session.get("role") != "ADMIN":
            flash("Administrator access required.", "danger")
            return redirect(url_for("dashboard"))

        return view(*args, **kwargs)

    return wrapped


# ==========================================================
# HOME
# ==========================================================

@app.route("/")
def index():

    if "username" in session:
        return redirect(url_for("dashboard"))

    return redirect(url_for("login"))


# ==========================================================
# LOGIN
# ==========================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "GET":
        return render_template("login.html")

    username = request.form.get(
        "username",
        ""
    ).strip()

    password = request.form.get(
        "password",
        ""
    )

    if not username or not password:
        flash(
            "Username and password are required.",
            "danger"
        )

        return render_template("login.html")

    ok, message, role, is_locked = (
        auth_controller.login_user(
            username,
            password
        )
    )

    if ok:
        profile = auth_controller.get_user_profile(
            username
        )

        session.clear()
        session["username"] = username
        session["role"] = role

        if profile:
            session["email"] = profile[1]
        else:
            session["email"] = ""

        flash(message, "success")
        return redirect(url_for("dashboard"))

    flash(message, "danger")

    return render_template(
        "login.html",
        locked=is_locked,
        locked_username=username
    )


# ==========================================================
# REGISTER
# ==========================================================

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "GET":
        return render_template("register.html")

    username = request.form.get(
        "username",
        ""
    ).strip()

    email = request.form.get(
        "email",
        ""
    ).strip()

    password = request.form.get(
        "password",
        ""
    )

    role = request.form.get(
        "role",
        "USER"
    ).strip().upper()

    if role not in ("ADMIN", "USER"):
        role = "USER"

    if not username or not email or not password:
        flash(
            "All registration fields are required.",
            "danger"
        )

        return redirect(url_for("register"))

    ok, message = auth_controller.register_user(
        username,
        email,
        password,
        role
    )

    flash(
        message,
        "success" if ok else "danger"
    )

    if ok:
        return redirect(url_for("login"))

    return redirect(url_for("register"))


# ==========================================================
# PASSWORD RESET REQUEST
# ==========================================================

@app.route(
    "/reset-request",
    methods=["GET", "POST"]
)
def reset_request():

    if request.method == "GET":
        return render_template("reset.html")

    email = request.form.get(
        "email",
        ""
    ).strip()

    new_password = request.form.get(
        "new_password",
        ""
    )

    confirm_password = request.form.get(
        "confirm_password",
        ""
    )

    if (
        not email
        or not new_password
        or not confirm_password
    ):
        flash(
            "All password-reset fields are required.",
            "danger"
        )

        return redirect(url_for("reset_request"))

    if new_password != confirm_password:
        flash(
            "New password and confirmation do not match.",
            "danger"
        )

        return redirect(url_for("reset_request"))

    ok, message = (
        auth_controller.submit_reset_request(
            email,
            new_password
        )
    )

    flash(
        message,
        "success" if ok else "danger"
    )

    if ok:
        return redirect(url_for("login"))

    return redirect(url_for("reset_request"))


# ==========================================================
# DASHBOARD
# ==========================================================

@app.route("/dashboard")
@login_required
def dashboard():

    search = request.args.get(
        "search",
        ""
    ).strip()

    category = request.args.get(
        "category",
        "All Categories"
    )

    status = request.args.get(
        "status",
        "All Statuses"
    )

    items = hardware_controller.fetch_all_hardware(
        search_text=search,
        category_filter=category,
        status_filter=status
    )

    categories = (
        hardware_controller.fetch_categories()
    )

    equipment_options = (
        asset_controller.fetch_hardware_options()
    )

    all_items = (
        hardware_controller.fetch_all_hardware()
    )

    total_stocks = sum(
        item[3]
        for item in all_items
    )


    username = session["username"]
    role = session["role"]

    equipment_requests = (
        asset_controller.fetch_requests(
            username,
            role
        )
    )

    pending_borrow_requests = []
    active_loans = []
    pending_returns = []
    history = []
    pending_borrows = []
    all_loans = []
    pending_resets = []

    if role == "USER":

        pending_borrow_requests = [
            row for row in equipment_requests
            if row[9] == "PENDING_BORROW"
        ]

        active_loans = [
            row for row in equipment_requests
            if row[9] == "BORROWED"
        ]

        pending_returns = [
            row for row in equipment_requests
            if row[9] == "RETURN_PENDING"
        ]

        history = [
            row for row in equipment_requests
            if row[9] in (
                "RETURNED",
                "REJECTED",
                "CANCELLED"
            )
        ]

    else:

        active_loans = [
            row for row in equipment_requests
            if row[9] == "BORROWED"
        ]

        pending_borrows = [
            row for row in equipment_requests
            if row[9] == "PENDING_BORROW"
        ]

        pending_returns = [
            row for row in equipment_requests
            if row[9] == "RETURN_PENDING"
        ]

        all_loans = equipment_requests

        pending_resets = (
            auth_controller.fetch_pending_reset_requests()
        )

    return render_template(
        "dashboard.html",
        items=items,
        categories=categories,
        equipment_options=equipment_options,
        search=search,
        selected_category=category,
        selected_status=status,
        total_stocks=total_stocks,
        equipment_requests=equipment_requests,
        pending_borrow_requests=pending_borrow_requests,
        active_loans=active_loans,
        pending_returns=pending_returns,
        history=history,
        pending_borrows=pending_borrows,
        all_loans=all_loans,
        pending_resets=pending_resets
    )


# ==========================================================
# USER — SUBMIT EQUIPMENT REQUEST
# ==========================================================

@app.route("/borrow", methods=["POST"])
@login_required
def borrow():

    if session["role"] != "USER":
        flash(
            "Only USER accounts may request equipment.",
            "danger"
        )

        return redirect(url_for("dashboard"))

    try:
        item_id = int(
            request.form.get("item_id", "")
        )

        quantity = int(
            request.form.get("quantity", "")
        )

    except ValueError:
        flash(
            "Select valid equipment and quantity.",
            "danger"
        )

        return redirect(url_for("dashboard"))

    borrower_id_number = request.form.get(
        "borrower_id_number",
        ""
    ).strip()

    group_members = request.form.get(
        "group_members",
        "None"
    ).strip()

    purpose = request.form.get(
        "purpose",
        ""
    ).strip()

    start_time = normalize_datetime(
        request.form.get("start_time", "")
    )

    end_time = normalize_datetime(
        request.form.get("end_time", "")
    )

    ok, message = create_borrow_request(
        session["username"],
        item_id,
        quantity,
        borrower_id_number,
        group_members,
        purpose,
        start_time,
        end_time
    )

    flash(
        message,
        "success" if ok else "danger"
    )

    return redirect(url_for("dashboard"))

# ==========================================================
# USER — CANCEL EQUIPMENT REQUEST
# ==========================================================

@app.route("/cancel-request", methods=["POST"])
@login_required
def cancel_request():

    try:
        request_id = int(
            request.form.get("request_id", "")
        )

    except ValueError:
        flash(
            "Select a valid equipment request.",
            "danger"
        )

        return redirect(url_for("dashboard"))

    ok, message = asset_controller.cancel_request(
        request_id,
        session["username"],
        session["role"]
    )

    flash(
        message,
        "success" if ok else "danger"
    )

    return redirect(url_for("dashboard"))


# ==========================================================
# USER — REQUEST RETURN
# ==========================================================

@app.route("/return-request", methods=["POST"])
@login_required
def return_request():

    if session["role"] != "USER":
        flash(
            "Only USER accounts may request returns.",
            "danger"
        )

        return redirect(url_for("dashboard"))

    request_ids = get_selected_ids("loan_ids")

    ok, message = submit_return_requests(
        request_ids,
        session["username"]
    )

    flash(
        message,
        "success" if ok else "warning"
    )

    return redirect(url_for("dashboard"))

# ==========================================================
# LOGGED-IN USER — CHANGE PASSWORD
# ==========================================================

@app.route(
    "/change-password",
    methods=["POST"]
)
@login_required
def change_password():

    current_password = request.form.get(
        "current_password",
        request.form.get("old_password", "")
    )

    new_password = request.form.get(
        "new_password",
        ""
    )

    confirm_password = request.form.get(
        "confirm_password",
        ""
    )

    if not confirm_password:
        confirm_password = new_password

    ok, message = auth_controller.change_password(
        session["username"],
        current_password,
        new_password,
        confirm_password
    )

    flash(
        message,
        "success" if ok else "danger"
    )

    return redirect(url_for("dashboard"))


# ==========================================================
# ADMIN — ADD HARDWARE
# ==========================================================

@app.route("/admin/add", methods=["POST"])
@admin_required
def admin_add():

    name = request.form.get(
        "item_name",
        ""
    ).strip()

    category = request.form.get(
        "category",
        ""
    ).strip()

    try:
        quantity = int(
            request.form.get("quantity", "")
        )

        unit_price = float(
            request.form.get("unit_price", "")
        )

    except ValueError:
        flash(
            "Quantity must be an integer and price must be numeric.",
            "danger"
        )

        return redirect(url_for("dashboard"))

    ok, message = hardware_controller.add_hardware(
        name,
        category,
        quantity,
        unit_price
    )

    flash(
        message,
        "success" if ok else "danger"
    )

    return redirect(url_for("dashboard"))


# ==========================================================
# ADMIN — UPDATE HARDWARE
# ==========================================================

@app.route("/admin/update", methods=["POST"])
@admin_required
def admin_update():

    try:
        item_id = int(
            request.form.get("item_id", "")
        )

        quantity = int(
            request.form.get("quantity", "")
        )

        unit_price = float(
            request.form.get("unit_price", "")
        )

    except ValueError:
        flash(
            "Select a valid item, quantity and price.",
            "danger"
        )

        return redirect(url_for("dashboard"))

    ok, message = (
        hardware_controller.update_hardware(
            item_id,
            quantity,
            unit_price
        )
    )

    flash(
        message,
        "success" if ok else "danger"
    )

    return redirect(url_for("dashboard"))


# ==========================================================
# ADMIN — DELETE HARDWARE
# ==========================================================

@app.route("/admin/delete", methods=["POST"])
@admin_required
def admin_delete():

    item_ids = get_selected_ids("item_ids")

    if not item_ids:
        single_id = request.form.get(
            "item_id",
            ""
        )

        try:
            item_ids = [int(single_id)]
        except ValueError:
            item_ids = []

    if not item_ids:
        flash(
            "Select at least one hardware item.",
            "warning"
        )

        return redirect(url_for("dashboard"))

    deleted = 0
    messages = []

    for item_id in item_ids:
        ok, message = (
            hardware_controller.delete_hardware(
                item_id
            )
        )

        messages.append(message)

        if ok:
            deleted += 1

    if deleted == len(item_ids):
        flash(
            f"{deleted} hardware item(s) deleted.",
            "success"
        )
    else:
        flash(
            " ".join(messages),
            "warning"
        )

    return redirect(url_for("dashboard"))


# ==========================================================
# ADMIN — APPROVE OR REJECT BORROW REQUESTS
# ==========================================================

@app.route(
    "/admin/borrow-action",
    methods=["POST"]
)
@admin_required
def admin_borrow_action():

    request_ids = get_selected_ids("loan_ids")

    action = request.form.get(
        "action",
        ""
    ).lower()

    admin_note = request.form.get(
        "admin_note",
        ""
    ).strip()

    if not request_ids:
        flash(
            "Select at least one borrow request.",
            "warning"
        )

        return redirect(url_for("dashboard"))

    approve = action == "approve"
    successful = 0
    messages = []

    for request_id in request_ids:
        ok, message = process_borrow_request(
            request_id,
            session["username"],
            approve,
            admin_note
        )

        messages.append(message)

        if ok:
            successful += 1

    flash(
        " ".join(messages),
        "success" if successful == len(request_ids)
        else "warning"
    )

    return redirect(url_for("dashboard"))

# ==========================================================
# ADMIN — APPROVE OR REJECT RETURNS
# ==========================================================

@app.route(
    "/admin/return-action",
    methods=["POST"]
)
@admin_required
def admin_return_action():

    request_ids = get_selected_ids("loan_ids")

    action = request.form.get(
        "action",
        ""
    ).lower()

    if not request_ids:
        flash(
            "Select at least one return request.",
            "warning"
        )

        return redirect(url_for("dashboard"))

    approve = action == "approve"
    successful = 0
    messages = []

    for request_id in request_ids:
        ok, message = process_return_request(
            request_id,
            session["username"],
            approve
        )

        messages.append(message)

        if ok:
            successful += 1

    flash(
        " ".join(messages),
        "success" if successful == len(request_ids)
        else "warning"
    )

    return redirect(url_for("dashboard"))

# ==========================================================
# ADMIN — PASSWORD RESET APPROVAL
# ==========================================================

@app.route(
    "/admin/reset-action",
    methods=["POST"]
)
@admin_required
def admin_reset_action():

    request_ids = get_selected_ids(
        "request_ids"
    )

    if not request_ids:
        single_id = request.form.get(
            "request_id",
            ""
        )

        try:
            request_ids = [int(single_id)]
        except ValueError:
            request_ids = []

    action = request.form.get(
        "action",
        ""
    ).lower()

    decision = (
        "Approved"
        if action == "approve"
        else "Rejected"
    )

    if not request_ids:
        flash(
            "Select at least one password-reset request.",
            "warning"
        )

        return redirect(url_for("dashboard"))

    successful = 0
    messages = []

    for request_id in request_ids:
        ok, message = (
            auth_controller.review_reset_request(
                request_id,
                session["username"],
                decision
            )
        )

        messages.append(message)

        if ok:
            successful += 1

    flash(
        " ".join(messages),
        "success" if successful == len(request_ids)
        else "warning"
    )

    return redirect(url_for("dashboard"))


# ==========================================================
# EXPORT INVENTORY REPORT
# ==========================================================

@app.route("/export")
@admin_required
def export():

    ok, message = (
        hardware_controller.export_csv()
    )

    if not ok:
        flash(message, "danger")
        return redirect(url_for("dashboard"))

    if not CSV_PATH.exists():
        flash(
            "The inventory report could not be found.",
            "danger"
        )

        return redirect(url_for("dashboard"))

    return send_file(
        CSV_PATH,
        as_attachment=True,
        download_name="inventory_report.csv"
    )


# ==========================================================
# LOGOUT
# ==========================================================

@app.route("/logout")
def logout():

    session.clear()

    flash(
        "You have been logged out.",
        "success"
    )

    return redirect(url_for("login"))


# ==========================================================
# START FLASK WEB SERVER
# ==========================================================

if __name__ == "__main__":

    print()
    print("=" * 60)
    print(" ENGINEERING LABORATORY ASSET TRACKING WEB SYSTEM")
    print("=" * 60)
    print(" Open a browser and visit:")
    print(" http://127.0.0.1:5000")
    print()
    print(" Press CTRL+C to stop the server.")
    print("=" * 60)
    print()

    app.run(debug=True)