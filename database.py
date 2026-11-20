import os
import sqlite3
from werkzeug.security import generate_password_hash

DATABASE = os.path.join("database", "college.db")


def get_db():
    os.makedirs(os.path.dirname(DATABASE), exist_ok=True)
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def initialize_database():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin', 'faculty', 'student')),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS students (
            student_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER UNIQUE NOT NULL,
            roll_number TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            dept_class TEXT,
            year INTEGER,
            FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS faculty (
            faculty_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER UNIQUE NOT NULL,
            name TEXT NOT NULL,
            department TEXT,
            FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS marks (
            mark_id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL,
            subject TEXT NOT NULL,
            total REAL NOT NULL DEFAULT 0,
            FOREIGN KEY(student_id) REFERENCES students(student_id) ON DELETE CASCADE,
            UNIQUE(student_id, subject)
        );
    """)

    # Migrate only the student field from Department/Class to Dept/Class.
    student_columns = {
        row["name"] for row in conn.execute("PRAGMA table_info(students)").fetchall()
    }
    if "department" in student_columns and "dept_class" not in student_columns:
        conn.execute("ALTER TABLE students RENAME COLUMN department TO dept_class")
    elif "class_name" in student_columns and "dept_class" not in student_columns:
        conn.execute("ALTER TABLE students RENAME COLUMN class_name TO dept_class")

    # Faculty continues to use Department. Repair databases created by the
    # earlier all-roles Class change without changing existing faculty values.
    faculty_columns = {
        row["name"] for row in conn.execute("PRAGMA table_info(faculty)").fetchall()
    }
    if "class_name" in faculty_columns and "department" not in faculty_columns:
        conn.execute("ALTER TABLE faculty RENAME COLUMN class_name TO department")

    # Demo accounts are created only when they do not already exist.
    demo_accounts = (
        ("admin", "admin123", "admin"),
        ("faculty", "faculty123", "faculty"),
        ("student", "student123", "student"),
    )
    for username, password, role in demo_accounts:
        conn.execute(
            "INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)",
            (username, generate_password_hash(password), role),
        )

    faculty_user = conn.execute(
        "SELECT user_id FROM users WHERE username = 'faculty' AND role = 'faculty'"
    ).fetchone()
    student_user = conn.execute(
        "SELECT user_id FROM users WHERE username = 'student' AND role = 'student'"
    ).fetchone()

    if faculty_user:
        conn.execute("""
            INSERT OR IGNORE INTO faculty (user_id, name, department)
            VALUES (?, ?, ?)
        """, (faculty_user["user_id"], "Demo Faculty", "BSc Cyber Security"))

    if student_user:
        conn.execute("""
            INSERT OR IGNORE INTO students
                (user_id, roll_number, name, dept_class, year)
            VALUES (?, ?, ?, ?, ?)
        """, (
            student_user["user_id"],
            "123456789",
            "Demo Student",
            "BSc Cyber Security",
            3,
        ))

    conn.commit()
    conn.close()


if __name__ == "__main__":
    initialize_database()
    print("Database initialized successfully.")
