COLLEGE MANAGEMENT SYSTEM

PROJECT MODULES
- Admin: create, edit, search and delete Admin, Faculty and Student accounts.
- Faculty: search students, view/edit student details, change student passwords and add/update subject marks.
- Student: view personal details and subject-wise marks.
- Login: Student uses a 9-digit Registration ID; Faculty and Admin use usernames.
- Students use Dept/Class; Faculty continues to use Department.

FILES
- app.py: Flask routes, login, role checks and application logic.
- database.py: SQLite connection, table creation and safe student Department-to-Dept/Class column migration.
- templates/: HTML pages.
- static/css/style.css: basic page styling.
- static/js/script.js: show/hide password control.
- database/college.db: created automatically on first run.

SETUP (WINDOWS)
1. Open Command Prompt in this project folder.
2. Create a virtual environment (recommended):
   python -m venv venv
3. Activate it:
   venv\Scripts\activate
4. Install packages:
   pip install -r requirements.txt
5. Start the application:
   python app.py
6. Open http://127.0.0.1:5000 in your browser.

DEMO LOGIN ACCOUNTS
- Admin: username admin / password admin123
- Faculty: username faculty / password faculty123
- Student: Registration ID 123456789 / password student123

IMPORTANT
- Back up your existing database/college.db before replacing project files.
- The database migration renames only the student Department column to dept_class and preserves existing rows. Faculty Department remains unchanged.
- Registration IDs must contain exactly 9 digits.
- Demo passwords are for local testing only. Change them before using real student data.
- Set a strong, private Flask secret key before deployment. Do not deploy with debug mode enabled.
