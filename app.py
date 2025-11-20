from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import pandas as pd
import re
from flask_migrate import Migrate

app = Flask(__name__)
app.secret_key = 'ASHra123'

# Configuring the MySQL database
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://mid_marks_user:ASHra08@localhost/student_db3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db) 

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'admin' or 'student'

    # One-to-many relationship: One User can have many Students
    students = db.relationship('Student', back_populates='user')
class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    registration_no = db.Column(db.String(50), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    branch = db.Column(db.String(50), nullable=False)
    batch = db.Column(db.String(10), nullable=False)
    

    # Foreign key to link the student with a user (one-to-one relation)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    # Relationship: Each student is related to a user (no backref)
    user = db.relationship('User',back_populates='students')

    # Marks relationship (one student can have multiple marks)
    marks = db.relationship('Marks', backref='student', lazy=True)
class LabMarks(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('student.id'), nullable=False)
    semester = db.Column(db.String(20), nullable=False)
    subject = db.Column(db.String(50), nullable=False)
    marks = db.Column(db.Integer, nullable=False)  # Single exam marks


class Marks(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('student.id'), nullable=False)
    semester = db.Column(db.String(20), nullable=False)  # Now semester is in Marks table
    subject = db.Column(db.String(50), nullable=False)
    mid_1 = db.Column(db.Integer, nullable=False)
    mid_2 = db.Column(db.Integer, nullable=False)
    tmarks = db.Column(db.Integer, nullable=False)


# Initialize the database
@app.before_first_request
def setup_database():
    db.create_all()
    # Create default admin user if not exists
    if not User.query.filter_by(username='admin').first():
        hashed_password = generate_password_hash('admin123', method='pbkdf2:sha256')
        admin_user = User(username='admin', password=hashed_password, role='admin')
        db.session.add(admin_user)
        db.session.commit()

# Route for admin and student login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Query for user based on username
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            # Store user details in session
            session['user_id'] = user.username
            session['role'] = user.role
            return redirect(url_for('dashboard'))  # Redirect to the dashboard
        else:
            # Flash an error message if credentials are invalid
            flash('Invalid username or password.', 'error')
            return redirect(url_for('login'))  # Redirect back to login page

    return render_template('login.html')

# Route to handle logout
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('role', None)
    return redirect(url_for('login'))

# Admin or student dashboard
@app.route('/dashboard', methods=['GET'])
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if session['role'] == 'admin':
        return render_template('admin_dashboard.html')

    elif session['role'] == 'student':
        student = Student.query.filter_by(registration_no=(session['user_id'])).first()
        return render_template('student_dashboard1.html',student=student) 
    return jsonify({"error": "Unauthorized access"}), 403

#route for view marks
@app.route('/view_marks', methods=['GET'])
def view_marks():
    if 'user_id' not in session:
        return redirect(url_for('login'))  # Redirect to login if not logged in

    if session['role'] == 'student':
        # Fetch student data
        student = Student.query.filter_by(registration_no=session['user_id']).first()

        if not student:
            return jsonify({"error": "Student not found"}), 404  # Return error if no student found
        
        # Fetch marks for this student
        marks_query = Marks.query.filter_by(student_id=student.id)

        # Filter by semester if provided in the GET request
        semester_filter = request.args.get('semester')
        if semester_filter:
            marks_query = marks_query.filter_by(semester=semester_filter)

        # Get the selected mid mark filter (Mid 1, Mid 2, or Both)
        mid_filter = request.args.get('mid', 'both')  # Default to 'both'
        marks = marks_query.all()

        # Prepare filtered marks
        filtered_marks = []
        for mark in marks:
            if mid_filter == 'both':
                filtered_marks.append(mark)  # Include both Mid-1 and Mid-2 for 'both' filter
            elif mid_filter == 'mid_1':
                filtered_marks.append(mark)  # Include Mid-1 for 'mid_1' filter
            elif mid_filter == 'mid_2':
                filtered_marks.append(mark)  # Include Mid-2 for 'mid_2' filter

        # Render the View Marks template
        return render_template('view_marks.html', student=student, filtered_marks=filtered_marks, mid_type=mid_filter)

    return jsonify({"error": "Unauthorized access"}), 403
#Lab Marks View
@app.route('/view_lab_marks', methods=['GET'])
def view_lab_marks():
    if 'user_id' not in session:
        return redirect(url_for('login'))  # Redirect to login if not logged in

    if session['role'] == 'student':
        # Fetch student data
        student = Student.query.filter_by(registration_no=session['user_id']).first()

        if not student:
            return jsonify({"error": "Student not found"}), 404  # Return error if no student found

        # Get the semester filter from the request args
        semester_filter = request.args.get('semester')

        # Start the query for lab marks
        lab_marks_query = LabMarks.query.filter_by(student_id=student.id)

        # Apply semester filter if it's provided
        if semester_filter:
            lab_marks_query = lab_marks_query.filter_by(semester=semester_filter)

        # Execute the query to get the filtered lab marks
        filtered_lab_marks = lab_marks_query.all()

        # Render the template with the student and filtered lab marks
        return render_template('view_marks_labs.html', student=student, filtered_lab_marks=filtered_lab_marks)

#Route for student change password
@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' not in session or session['role'] != 'student':
        flash('Unauthorized access.', 'error')
        return redirect(url_for('login'))

    student = Student.query.filter_by(registration_no=session['user_id']).first()

    if request.method == 'POST':
        # Retrieve form data
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        # Validate the current password
        user = User.query.filter_by(username=session['user_id']).first()
        if not user or not check_password_hash(user.password, current_password):
            flash('Current password is incorrect.', 'error')
            return redirect(url_for('change_password'))

        # Validate the new password
        if len(new_password) < 8 :
            flash('New password must be at least 8 characters long and alphanumeric.', 'error')
            return redirect(url_for('change_password'))
        if not re.search(r'[A-Za-z]', new_password) or not re.search(r'[0-9]', new_password):
            flash('New password must contain both letters and numbers.', 'error')
            return render_template('change_password.html', student=student)

        if new_password != confirm_password:
            flash('New password and confirm password do not match.', 'error')
            return redirect(url_for('change_password'))

        # Update the password
        user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
        db.session.commit()
        flash('Password changed successfully.', 'success')
        return redirect(url_for('change_password'))

    return render_template('change_password.html', student=student)

# Route to upload and process Excel file (Admin only)
from flask import flash, redirect, url_for
#For Theory Subs
@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if 'user_id' not in session or session['role'] != 'admin':
        # Redirect to login if not logged in or not an admin
        flash("Please log in as admin to access this page.", "error")
        return redirect(url_for('login'))  # Assuming 'login' is the route for the login page

    if request.method == 'POST':
        if 'file' not in request.files:
            flash("No file uploaded.", "error")
            return redirect(url_for('upload_file'))

        file = request.files['file']
        if file.filename == '':
            flash("Empty filename.", "error")
            return redirect(url_for('upload_file'))

        # Validate the file format
        if not file.filename.endswith(('.xlsx', '.xls')):
            flash("Invalid file format. Please upload an Excel file.", "error")
            return redirect(url_for('upload_file'))

        try:
            # Read the Excel file
            data = pd.read_excel(file)

            # Expected columns
            expected_columns = ['REGISTERD NO', 'NAME', 'SUB', 'MID-1', 'MID-2','TOTAL', 'SEM','BRANCH','BATCH']

            # Validate column headers
            if list(data.columns) != expected_columns:
                flash(f"Invalid file format. Expected columns: {', '.join(expected_columns)}", "error")
                return redirect(url_for('upload_file'))

            for _, row in data.iterrows():
                # Check if user already exists based on registration number
                existing_user = User.query.filter_by(username=row['REGISTERD NO']).first()

                if not existing_user:
                    new_user = User(
                        username=row['REGISTERD NO'],
                        password=generate_password_hash(row['REGISTERD NO'], method='pbkdf2:sha256'),
                        role='student'
                    )
                    db.session.add(new_user)
                    db.session.commit()

                else:
                    new_user = existing_user

                student = Student.query.filter_by(registration_no=row['REGISTERD NO']).first()
                if not student:
                    student = Student(
                        registration_no=row['REGISTERD NO'],
                        name=row['NAME'],
                        user_id=new_user.id,
                        branch=row['BRANCH'],
                        batch=row['BATCH']
                    )
                    db.session.add(student)
                    db.session.flush()

                # Add or update marks
                existing_marks = Marks.query.filter_by(
                    student_id=student.id, 
                    subject=row['SUB'], 
                    semester=row['SEM']
                ).first()

                if existing_marks:
                    existing_marks.mid_1 = row['MID-1']
                    existing_marks.mid_2 = row['MID-2']
                    existing_marks.tmarks = row['TOTAL']
                else:
                    marks = Marks(
                        student_id=student.id,
                        subject=row['SUB'],
                        mid_1=row['MID-1'],
                        mid_2=row['MID-2'],
                        tmarks=row['TOTAL'],
                        semester=row['SEM']
                    )
                    db.session.add(marks)

            db.session.commit()
            flash("Data uploaded successfully.", "success")

        except Exception as e:
            flash(f"An error occurred: {str(e)}", "error")

        return redirect(url_for('upload_file'))

    return render_template('upload_file.html')

#For Labs
@app.route('/upload_lab', methods=['GET', 'POST'])
def upload_lab_marks():
    if 'user_id' not in session or session['role'] != 'admin':
        flash( "Unauthorized access",'error')
        return redirect(url_for('login'))
    if request.method == 'POST':
        if 'user_id' not in session or session['role'] != 'admin':
            flash('Unauthorized access.', 'error')
            return redirect(url_for('login'))

        if 'file' not in request.files:
            flash('No file uploaded.', 'error')
            return redirect(url_for('upload_lab_marks'))

        file = request.files['file']
        if file.filename == '':
            flash('Empty filename.', 'error')
            return redirect(url_for('upload_lab_marks'))

        if not file.filename.endswith(('.xlsx', '.xls')):
            flash('Invalid file format. Please upload an Excel file.', 'error')
            return redirect(url_for('upload_lab_marks'))

        try:
            data = pd.read_excel(file)
            expected_columns = ['REGISTERD NO', 'NAME', 'LAB', 'MARKS', 'SEM','BRANCH']

            if list(data.columns) != expected_columns:
                flash(f'Invalid file format. Expected columns: {", ".join(expected_columns)}', 'error')
                return redirect(url_for('upload_lab_marks'))

            for _, row in data.iterrows():
                student = Student.query.filter_by(registration_no=row['REGISTERD NO']).first()
                if not student:
                    flash(f"Student with registration no {row['REGISTERD NO']} not found.", 'error')
                    continue

                # Add or update lab marks
                existing_lab_marks = LabMarks.query.filter_by(
                    student_id=student.id,
                    subject=row['LAB'],
                    semester=row['SEM']
                ).first()

                if existing_lab_marks:
                    existing_lab_marks.marks = row['MARKS']
                else:
                    lab_marks = LabMarks(
                        student_id=student.id,
                        subject=row['LAB'],
                        marks=row['MARKS'],
                        semester=row['SEM']
                    )
                    db.session.add(lab_marks)

            db.session.commit()
            flash('Lab marks uploaded successfully.', 'success')

        except Exception as e:
            flash(f'An error occurred: {str(e)}', 'error')

        return redirect(url_for('upload_lab_marks'))

    return render_template('upload_lab.html')

# Route to view all students (Admin only)
@app.route('/students', methods=['GET'])
def get_students():
    if 'user_id' not in session or session['role'] != 'admin':
        flash( "Unauthorized access",'error')
        return redirect(url_for('login'))
    
    batch_filter = request.args.get('batch',type=str)
    branch_filter = request.args.get('branch',type=str)
    semester_filter = request.args.get('semester', type=int)

    query = Student.query

    if batch_filter:
        query = query.filter_by(batch=batch_filter)
    if branch_filter:
        query = query.filter_by(branch=branch_filter)
    if semester_filter:
        query = query.join(Marks).filter(Marks.semester == semester_filter)

    students = query.all()
    
    marks_type_filter = request.args.get('type', 'both')
    output = []

    for student in students:
        student_data = {
            'registration_no': student.registration_no,
            'name': student.name,
            'branch': student.branch,
            'batch': student.batch,
            'marks': []
        }
        if marks_type_filter in ['theory']:
            theory_marks_query = Marks.query.filter_by(student_id=student.id).all()
            for mark in theory_marks_query:
                student_data['marks'].append({
                    'type': 'theory',
                    'subject': mark.subject,
                    'mid_1': mark.mid_1,
                    'mid_2': mark.mid_2,
                    'total': mark.tmarks,
                    'semester': mark.semester
                })
        if marks_type_filter in ['lab']:
            lab_marks_query = LabMarks.query.filter_by(student_id=student.id).all()
            for lab_mark in lab_marks_query:
                student_data['marks'].append({
                    'type': 'lab',
                    'lab_name': lab_mark.subject,
                    'marks': lab_mark.marks,
                    'semester': lab_mark.semester
                })

        output.append(student_data)

    return render_template('view_students.html', students=output)

# Route to register users (Admin only)
@app.route('/register', methods=['GET', 'POST'])
def register_user():
    if 'user_id' not in session or session['role'] != 'admin':
        flash('Unauthorized access.', 'error')
        return redirect(url_for('login'))
    if request.method == 'GET':
        # Render the registration form for GET requests
        return render_template('register_user.html')
    if request.method == 'POST':
        if not request.is_json:
            return jsonify({"error": "Invalid Content-Type. Expected 'application/json'."}), 415
        # Parse the JSON data from the request
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        role = data.get('role')
        # Validate input
        if not username or not password or not role:
            return jsonify({"error": "All fields are required."}), 400
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return jsonify({"error": "Username already registered."}), 409 
        # Hash the password and save the user in the database
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()

        return jsonify({"message": "User registered successfully"}), 201

if __name__ == '__main__':
    app.run(debug=True)
