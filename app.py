from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash
)
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps
import sqlite3
import re

from database import get_db, initialize_database


def valid_registration_id(value):
    return bool(re.fullmatch(r"[0-9]{9}", value))


def valid_strong_password(value):
    return (
        len(value) >= 8
        and bool(re.search(r"[A-Z]", value))
        and bool(re.search(r"[a-z]", value))
        and bool(re.search(r"[0-9]", value))
        and bool(re.search(r"[^A-Za-z0-9]", value))
    )


app = Flask(__name__)
app.secret_key = "replace-this-with-a-long-random-secret-key"


# -------------------- ACCESS CONTROL --------------------

def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return func(*args, **kwargs)
    return wrapper


def role_required(*roles):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if "user_id" not in session:
                return redirect(url_for("login"))
            if session.get("role") not in roles:
                return "403 - Access Denied", 403
            return func(*args, **kwargs)
        return wrapper
    return decorator


# -------------------- LOGIN --------------------

@app.route("/", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        role = request.form.get("role", "").strip()
        password = request.form.get("password", "")

        conn = get_db()
        user = None

        if role == "student":
            reg_id = request.form.get("reg_id", "").strip()
            if not valid_registration_id(reg_id):
                conn.close()
                flash("Student Registration ID must contain exactly 9 digits.")
                return render_template("login.html")
            user = conn.execute("""
                SELECT u.*, s.roll_number
                FROM users u
                JOIN students s ON s.user_id = u.user_id
                WHERE s.roll_number = ? AND u.role = 'student'
            """, (reg_id,)).fetchone()
            login_name = reg_id

        elif role in ("faculty", "admin"):
            username = request.form.get("username", "").strip()
            user = conn.execute("""
                SELECT * FROM users
                WHERE username = ? AND role = ?
            """, (username, role)).fetchone()
            login_name = username

        else:
            login_name = ""

        conn.close()

        if user and check_password_hash(user["password"], password):
            session.clear()
            session["user_id"] = user["user_id"]
            session["username"] = user["username"]
            session["login_name"] = login_name
            session["role"] = user["role"]
            return redirect(url_for("dashboard"))

        flash("Invalid role, login ID or password.")

    return render_template("login.html")


# -------------------- DASHBOARDS --------------------

@app.route("/dashboard")
@login_required
def dashboard():
    role = session["role"]

    if role == "admin":
        return redirect(url_for("admin_dashboard"))

    conn = get_db()
    profile = None

    if role == "student":
        profile = conn.execute("""
            SELECT * FROM students WHERE user_id = ?
        """, (session["user_id"],)).fetchone()
    elif role == "faculty":
        profile = conn.execute("""
            SELECT * FROM faculty WHERE user_id = ?
        """, (session["user_id"],)).fetchone()

    conn.close()

    return render_template(
        "dashboard.html",
        role=role,
        username=session.get("login_name", session["username"]),
        profile=profile
    )


@app.route("/admin")
@login_required
@role_required("admin")
def admin_dashboard():
    conn = get_db()
    stats = {
        "students": conn.execute("SELECT COUNT(*) FROM students").fetchone()[0],
        "faculty": conn.execute("SELECT COUNT(*) FROM faculty").fetchone()[0],
        "users": conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    }
    conn.close()

    return render_template(
        "dashboard.html",
        role="admin",
        username=session["username"],
        stats=stats,
        profile=None
    )


# -------------------- ADMIN: USERS --------------------

@app.route("/admin/users")
@login_required
@role_required("admin")
def admin_users():
    search = request.args.get("search", "").strip()
    like = f"%{search}%"
    conn = get_db()

    students = conn.execute("""
        SELECT u.user_id, u.role, s.roll_number, s.name,
               s.dept_class, s.year
        FROM users u
        JOIN students s ON s.user_id = u.user_id
        WHERE s.roll_number LIKE ?
           OR s.name LIKE ?
           OR s.dept_class LIKE ?
        ORDER BY s.roll_number
    """, (like, like, like)).fetchall()

    faculty = conn.execute("""
        SELECT u.user_id, u.username, f.name, f.department
        FROM users u
        JOIN faculty f ON f.user_id = u.user_id
        WHERE u.username LIKE ?
           OR f.name LIKE ?
           OR f.department LIKE ?
        ORDER BY f.name
    """, (like, like, like)).fetchall()

    admins = conn.execute("""
        SELECT user_id, username
        FROM users
        WHERE role = 'admin' AND username LIKE ?
        ORDER BY username
    """, (like,)).fetchall()

    conn.close()
    return render_template(
        "admin_users.html",
        students=students,
        faculty=faculty,
        admins=admins,
        search=search
    )


@app.route("/admin/create-user", methods=["GET", "POST"])
@login_required
@role_required("admin")
def create_user():
    if request.method == "POST":
        role = request.form.get("role", "").strip()
        password = request.form.get("password", "")
        name = request.form.get("name", "").strip()
        dept_class = request.form.get("dept_class", "").strip() if role == "student" else ""
        department = request.form.get("department", "").strip() if role == "faculty" else ""

        if role == "student":
            login_id = request.form.get("reg_id", "").strip()
            roll_number = login_id
            allowed_dept_classes = {"CSA/BSC Cyber Security", "CSA/BSC Data science", "CSA/ BCA", "CSA/ BSC Computer science", "CSA/MCA"}
            if dept_class not in allowed_dept_classes:
                flash("Select a valid Dept/Class.")
                return redirect(url_for("create_user"))
        else:
            login_id = request.form.get("username", "").strip()
            roll_number = ""

        if role not in ("admin", "faculty", "student"):
            flash("Select a valid user role.")
            return redirect(url_for("create_user"))

        if not login_id or not password:
            flash("Login ID and password are required.")
            return redirect(url_for("create_user"))

        if role == "student" and not valid_registration_id(login_id):
            flash("Student Registration ID must contain exactly 9 digits.")
            return redirect(url_for("create_user"))

        if not valid_strong_password(password):
            flash("Password must be at least 8 characters and include uppercase, lowercase, a number and a special character.")
            return redirect(url_for("create_user"))

        if role in ("student", "faculty") and not name:
            flash("Full name is required.")
            return redirect(url_for("create_user"))

        year = None
        if role == "student":
            try:
                year = int(request.form.get("year", ""))
                if year < 1 or year > 4:
                    raise ValueError
            except ValueError:
                flash("Select a valid academic year.")
                return redirect(url_for("create_user"))

        conn = get_db()
        try:
            cursor = conn.execute("""
                INSERT INTO users (username, password, role)
                VALUES (?, ?, ?)
            """, (login_id, generate_password_hash(password), role))
            user_id = cursor.lastrowid

            if role == "student":
                conn.execute("""
                    INSERT INTO students
                    (user_id, roll_number, name, dept_class, year)
                    VALUES (?, ?, ?, ?, ?)
                """, (user_id, roll_number, name, dept_class, year))

            elif role == "faculty":
                conn.execute("""
                    INSERT INTO faculty (user_id, name, department)
                    VALUES (?, ?, ?)
                """, (user_id, name, department))

            conn.commit()
            flash("User created successfully.")
            return redirect(url_for("admin_users"))

        except sqlite3.IntegrityError:
            conn.rollback()
            flash("That username or registration ID already exists.")
        except Exception:
            conn.rollback()
            app.logger.exception("Unable to create user")
            flash("Unable to create user. Check the entered details.")
        finally:
            conn.close()

        return redirect(url_for("create_user"))

    return render_template("user_form.html", user=None, profile=None)


@app.route("/admin/edit-user/<int:user_id>", methods=["GET", "POST"])
@login_required
@role_required("admin")
def edit_user(user_id):
    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE user_id = ?", (user_id,)
    ).fetchone()

    if not user:
        conn.close()
        return "User not found", 404

    student = None
    faculty_profile = None

    if user["role"] == "student":
        student = conn.execute(
            "SELECT * FROM students WHERE user_id = ?", (user_id,)
        ).fetchone()
    elif user["role"] == "faculty":
        faculty_profile = conn.execute(
            "SELECT * FROM faculty WHERE user_id = ?", (user_id,)
        ).fetchone()

    if request.method == "POST":
        password = request.form.get("password", "")
        name = request.form.get("name", "").strip()
        dept_class = request.form.get("dept_class", "").strip() if user["role"] == "student" else ""
        department = request.form.get("department", "").strip() if user["role"] == "faculty" else ""

        if user["role"] == "student":
            # Registration ID is immutable after account creation.
            login_id = student["roll_number"]
            year_raw = request.form.get("year", "").strip()
            allowed_dept_classes = {"CSA/BSC Cyber Security", "CSA/BSC Data science", "CSA/ BCA", "CSA/ BSC Computer science", "CSA/MCA"}
            if dept_class not in allowed_dept_classes:
                flash("Select a valid Dept/Class.")
                conn.close()
                return redirect(url_for("edit_user", user_id=user_id))
        else:
            login_id = request.form.get("username", "").strip()
            year_raw = ""

        if not login_id:
            flash("Login ID is required.")
            conn.close()
            return redirect(url_for("edit_user", user_id=user_id))

        if user["role"] == "student" and not valid_registration_id(login_id):
            flash("Student Registration ID must contain exactly 9 digits.")
            conn.close()
            return redirect(url_for("edit_user", user_id=user_id))

        if password and not valid_strong_password(password):
            flash("Password must be at least 8 characters and include uppercase, lowercase, a number and a special character.")
            conn.close()
            return redirect(url_for("edit_user", user_id=user_id))

        try:
            conn.execute(
                "UPDATE users SET username = ? WHERE user_id = ?",
                (login_id, user_id)
            )

            if password:
                conn.execute(
                    "UPDATE users SET password = ? WHERE user_id = ?",
                    (generate_password_hash(password), user_id)
                )

            if user["role"] == "student":
                year = int(year_raw)
                if not name or year < 1 or year > 4:
                    raise ValueError("Invalid student information")
                conn.execute("""
                    UPDATE students
                    SET name = ?, dept_class = ?, year = ?
                    WHERE user_id = ?
                """, (name, dept_class, year, user_id))

            elif user["role"] == "faculty":
                if not name:
                    raise ValueError("Faculty name is required")
                conn.execute("""
                    UPDATE faculty
                    SET name = ?, department = ?
                    WHERE user_id = ?
                """, (name, department, user_id))

            conn.commit()

            if user_id == session["user_id"]:
                session["username"] = login_id
                session["login_name"] = login_id

            flash("User updated successfully.")
            conn.close()
            return redirect(url_for("admin_users"))

        except (ValueError, sqlite3.IntegrityError):
            conn.rollback()
            flash("Invalid details or login ID already exists.")
        finally:
            if conn:
                conn.close()

        return redirect(url_for("edit_user", user_id=user_id))

    conn.close()
    profile = student if student else faculty_profile
    return render_template("user_form.html", user=user, profile=profile)


@app.route("/admin/delete-user/<int:user_id>", methods=["POST"])
@login_required
@role_required("admin")
def delete_user(user_id):
    if user_id == session["user_id"]:
        flash("You cannot delete your own admin account.")
        return redirect(url_for("admin_users"))

    conn = get_db()
    cursor = conn.execute("DELETE FROM users WHERE user_id = ?", (user_id,))
    conn.commit()
    deleted = cursor.rowcount
    conn.close()

    flash("User deleted successfully." if deleted else "User not found.")
    return redirect(url_for("admin_users"))


# -------------------- CHANGE OWN PASSWORD --------------------

@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")
        conn = get_db()
        user = conn.execute("SELECT password FROM users WHERE user_id = ?", (session["user_id"],)).fetchone()
        if not user or not check_password_hash(user["password"], current_password):
            conn.close(); flash("Current password is incorrect.")
            return redirect(url_for("change_password"))
        if not valid_strong_password(new_password):
            conn.close()
            flash("New password must be at least 8 characters and include uppercase, lowercase, a number and a special character.")
            return redirect(url_for("change_password"))
        if new_password != confirm_password:
            conn.close(); flash("New password and confirmation do not match.")
            return redirect(url_for("change_password"))
        conn.execute("UPDATE users SET password = ? WHERE user_id = ?", (generate_password_hash(new_password), session["user_id"]))
        conn.commit(); conn.close()
        flash("Your password has been changed successfully.")
        return redirect(url_for("dashboard"))
    return render_template("change_password.html")


# -------------------- STUDENT: VIEW MARKS --------------------

@app.route("/student/marks")
@login_required
@role_required("student")
def student_marks():
    conn = get_db()
    profile = conn.execute("""
        SELECT * FROM students WHERE user_id = ?
    """, (session["user_id"],)).fetchone()

    if not profile:
        conn.close()
        return "Student profile not found", 404

    marks = conn.execute("""
        SELECT * FROM marks
        WHERE student_id = ?
        ORDER BY subject
    """, (profile["student_id"],)).fetchall()
    conn.close()

    return render_template("student_marks.html", profile=profile, marks=marks)


# -------------------- FACULTY: STUDENTS --------------------

@app.route("/faculty/students")
@login_required
@role_required("faculty")
def faculty_students():
    search = request.args.get("search", "").strip()
    like = f"%{search}%"
    conn = get_db()
    students = conn.execute("""
        SELECT * FROM students
        WHERE name LIKE ? OR roll_number LIKE ? OR dept_class LIKE ?
        ORDER BY roll_number
    """, (like, like, like)).fetchall()
    conn.close()
    return render_template("faculty_students.html", students=students, search=search)


@app.route("/faculty/student/<int:student_id>")
@login_required
@role_required("faculty")
def faculty_student_details(student_id):
    conn = get_db()
    student = conn.execute("""
        SELECT s.*, u.username
        FROM students s
        JOIN users u ON u.user_id = s.user_id
        WHERE s.student_id = ?
    """, (student_id,)).fetchone()

    if not student:
        conn.close()
        return "Student not found", 404

    marks = conn.execute("""
        SELECT * FROM marks WHERE student_id = ? ORDER BY subject
    """, (student_id,)).fetchall()
    conn.close()

    return render_template(
        "faculty_student_details.html",
        student=student,
        marks=marks
    )


@app.route("/faculty/edit-student/<int:student_id>", methods=["GET", "POST"])
@login_required
@role_required("faculty")
def faculty_edit_student(student_id):
    conn = get_db()
    student = conn.execute(
        "SELECT * FROM students WHERE student_id = ?", (student_id,)
    ).fetchone()

    if not student:
        conn.close()
        return "Student not found", 404

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        roll_number = student["roll_number"]
        dept_class = request.form.get("dept_class", "").strip()

        try:
            year = int(request.form.get("year", ""))
            if not name or not valid_registration_id(roll_number) or year < 1 or year > 4:
                raise ValueError

            conn.execute("""
                UPDATE students
                SET name = ?, dept_class = ?, year = ?
                WHERE student_id = ?
            """, (name, dept_class, year, student_id))

            conn.commit()
            flash("Student details updated successfully.")
            conn.close()
            return redirect(url_for("faculty_student_details", student_id=student_id))

        except (ValueError, sqlite3.IntegrityError):
            conn.rollback()
            flash("Invalid details. Registration ID must contain exactly 9 digits.")
        finally:
            conn.close()

        return redirect(url_for("faculty_edit_student", student_id=student_id))

    conn.close()
    return render_template("faculty_edit_student.html", student=student)


# -------------------- FACULTY: MARKS --------------------

@app.route("/faculty/marks/<int:student_id>", methods=["GET", "POST"])
@login_required
@role_required("faculty")
def faculty_marks(student_id):
    conn = get_db()
    student = conn.execute(
        "SELECT * FROM students WHERE student_id = ?", (student_id,)
    ).fetchone()

    if not student:
        conn.close()
        return "Student not found", 404

    if request.method == "POST":
        subject = request.form.get("subject", "").strip()

        try:
            total = float(request.form.get("total", ""))

            if not subject or not (0 <= total <= 100):
                raise ValueError

            conn.execute("""
                INSERT INTO marks (student_id, subject, total)
                VALUES (?, ?, ?)
                ON CONFLICT(student_id, subject)
                DO UPDATE SET total = excluded.total
            """, (student_id, subject, total))

            conn.commit()
            flash("Marks saved successfully.")
        except ValueError:
            conn.rollback()
            flash("Enter valid marks between 0 and 100.")
        finally:
            conn.close()

        return redirect(url_for("faculty_marks", student_id=student_id))

    marks = conn.execute("""
        SELECT * FROM marks WHERE student_id = ? ORDER BY subject
    """, (student_id,)).fetchall()
    conn.close()

    return render_template("faculty_marks.html", student=student, marks=marks)


# -------------------- LOGOUT / HEALTH --------------------

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/health")
def health():
    return "College Management Portal is running!"


if __name__ == "__main__":
    initialize_database()
    app.run(debug=True)
