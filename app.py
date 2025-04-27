# app.py
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
import sqlite3
import os
import re
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

# Upload configuration
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS_IMG = {'png', 'jpg', 'jpeg'}
ALLOWED_EXTENSIONS_DOC = {'pdf', 'doc', 'docx'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Database initialization
def get_db_connection():
    conn = sqlite3.connect('taskbid.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    conn.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        name TEXT NOT NULL,
        phone TEXT NOT NULL,
        id_front TEXT NOT NULL,
        id_back TEXT NOT NULL,
        cv TEXT NOT NULL,
        test_score INTEGER DEFAULT 0,
        is_approved INTEGER DEFAULT 0,
        is_suspended INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    conn.execute('''
    CREATE TABLE IF NOT EXISTS tasks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        deadline TIMESTAMP,
        status TEXT DEFAULT 'open',
        winner_id INTEGER,
        FOREIGN KEY (winner_id) REFERENCES users (id)
    )
    ''')
    
    conn.execute('''
    CREATE TABLE IF NOT EXISTS bids (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        task_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        budget REAL NOT NULL,
        proposal TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (task_id) REFERENCES tasks (id),
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')
    
    # Create admin user if not exists
    admin_exists = conn.execute('SELECT 1 FROM users WHERE email = ?', 
                               ('asd@men.com',)).fetchone()
    if not admin_exists:
        admin_password = generate_password_hash('passreset11')
        conn.execute('''
        INSERT INTO users (email, password, name, phone, id_front, id_back, cv, test_score, is_approved)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', ('asd@men.com', admin_password, 'Admin', '12345678901', 'admin', 'admin', 'admin', 100, 1))
    
    conn.commit()
    conn.close()

init_db()

# Helper functions
def allowed_file(filename, file_type):
    allowed_extensions = ALLOWED_EXTENSIONS_IMG if file_type == 'image' else ALLOWED_EXTENSIONS_DOC
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

def save_file(file):
    if file and file.filename:
        filename = secure_filename(file.filename)
        timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        new_filename = f"{timestamp}_{filename}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
        file.save(file_path)
        return new_filename
    return None

def is_valid_phone(phone):
    # Basic validation for US and UK phone numbers
    us_pattern = re.compile(r'^\d{10}$')  # Simple US format: 1234567890
    uk_pattern = re.compile(r'^\d{11}$')  # Simple UK format: 01234567890
    return bool(us_pattern.match(phone) or uk_pattern.match(phone))

def check_user_status(user_id):
    conn = get_db_connection()
    user = conn.execute('SELECT is_approved, is_suspended FROM users WHERE id = ?', 
                       (user_id,)).fetchone()
    conn.close()
    
    if not user:
        return {'status': 'not_found'}
    
    if user['is_suspended'] == 1:
        return {'status': 'suspended'}
    
    if user['is_approved'] == 0:
        return {'status': 'not_approved'}
    
    return {'status': 'approved'}

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        if session.get('is_admin'):
            return redirect(url_for('admin_dashboard'))
        else:
            status = check_user_status(session['user_id'])
            if status['status'] == 'approved':
                return redirect(url_for('tasks'))
            elif status['status'] == 'suspended':
                flash('Your account has been suspended. Please contact the administrator.', 'danger')
                return render_template('suspended.html')
            else:
                return redirect(url_for('pending_approval'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Admin login check
        if email == 'asd@men.com' and password == 'passreset11':
            session['user_id'] = 1
            session['is_admin'] = True
            return redirect(url_for('admin_dashboard'))
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['is_admin'] = False
            
            status = check_user_status(user['id'])
            if status['status'] == 'suspended':
                flash('Your account has been suspended. Please contact the administrator.', 'danger')
                return render_template('suspended.html')
            elif status['status'] == 'not_approved':
                return redirect(url_for('pending_approval'))
            else:
                return redirect(url_for('tasks'))
        else:
            flash('Invalid email or password', 'danger')
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        name = request.form.get('name')
        phone = request.form.get('phone')
        password = request.form.get('password')
        
        # Validate phone
        if not is_valid_phone(phone):
            flash('Please enter a valid US or UK phone number', 'danger')
            return redirect(url_for('signup'))
        
        # Check for required files
        if 'id_front' not in request.files or 'id_back' not in request.files or 'cv' not in request.files:
            flash('All files are required', 'danger')
            return redirect(url_for('signup'))
        
        id_front = request.files['id_front']
        id_back = request.files['id_back']
        cv = request.files['cv']
        
        # Validate file types
        if not allowed_file(id_front.filename, 'image') or not allowed_file(id_back.filename, 'image'):
            flash('ID card images must be PNG, JPG, or JPEG files', 'danger')
            return redirect(url_for('signup'))
        
        if not allowed_file(cv.filename, 'document'):
            flash('CV must be PDF, DOC, or DOCX file', 'danger')
            return redirect(url_for('signup'))
        
        # Save files
        id_front_filename = save_file(id_front)
        id_back_filename = save_file(id_back)
        cv_filename = save_file(cv)
        
        if not all([id_front_filename, id_back_filename, cv_filename]):
            flash('Error saving files', 'danger')
            return redirect(url_for('signup'))
        
        # Save user to database
        conn = get_db_connection()
        try:
            hashed_password = generate_password_hash(password)
            conn.execute('''
            INSERT INTO users (email, password, name, phone, id_front, id_back, cv)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (email, hashed_password, name, phone, id_front_filename, id_back_filename, cv_filename))
            conn.commit()
            
            user_id = conn.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()['id']
            session['user_id'] = user_id
            session['is_admin'] = False
            
            conn.close()
            return redirect(url_for('skill_test'))
        except sqlite3.IntegrityError:
            flash('Email already exists', 'danger')
            conn.close()
            return redirect(url_for('signup'))
    
    return render_template('signup.html')

@app.route('/skill_test', methods=['GET', 'POST'])
def skill_test():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        # Simple scoring system
        score = 0
        if request.form.get('q1') == 'c':  # Example correct answer
            score += 33
        if request.form.get('q2') == 'b':  # Example correct answer
            score += 33
        if request.form.get('q3') == 'a':  # Example correct answer
            score += 34
        
        # Update user's test score
        conn = get_db_connection()
        conn.execute('UPDATE users SET test_score = ? WHERE id = ?', (score, session['user_id']))
        conn.commit()
        conn.close()
        
        return redirect(url_for('pending_approval'))
    
    return render_template('skill_test.html')

@app.route('/pending_approval')
def pending_approval():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    return render_template('pending_approval.html')

@app.route('/tasks')
def tasks():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    status = check_user_status(session['user_id'])
    if status['status'] != 'approved':
        return redirect(url_for('pending_approval'))
    
    conn = get_db_connection()
    tasks = conn.execute('SELECT * FROM tasks WHERE status = "open" ORDER BY created_at DESC').fetchall()
    
    # Get the user's existing bids
    user_bids = conn.execute('SELECT task_id FROM bids WHERE user_id = ?', 
                            (session['user_id'],)).fetchall()
    user_bid_task_ids = [bid['task_id'] for bid in user_bids]
    
    conn.close()
    
    return render_template('tasks.html', tasks=tasks, user_bid_task_ids=user_bid_task_ids)

@app.route('/task/<int:task_id>')
def task_detail(task_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    status = check_user_status(session['user_id'])
    if status['status'] != 'approved':
        return redirect(url_for('pending_approval'))
    
    conn = get_db_connection()
    task = conn.execute('SELECT * FROM tasks WHERE id = ?', (task_id,)).fetchone()
    
    if not task:
        conn.close()
        flash('Task not found', 'danger')
        return redirect(url_for('tasks'))
    
    # Check if user has already bid on this task
    existing_bid = conn.execute('SELECT * FROM bids WHERE task_id = ? AND user_id = ?', 
                               (task_id, session['user_id'])).fetchone()
    
    conn.close()
    
    return render_template('task_detail.html', task=task, existing_bid=existing_bid)

@app.route('/bid/<int:task_id>', methods=['GET', 'POST'])
def place_bid(task_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    status = check_user_status(session['user_id'])
    if status['status'] != 'approved':
        return redirect(url_for('pending_approval'))
    
    conn = get_db_connection()
    task = conn.execute('SELECT * FROM tasks WHERE id = ?', (task_id,)).fetchone()
    
    if not task:
        conn.close()
        flash('Task not found', 'danger')
        return redirect(url_for('tasks'))
    
    if task['status'] != 'open':
        conn.close()
        flash('This task is no longer accepting bids', 'danger')
        return redirect(url_for('tasks'))
    
    if request.method == 'POST':
        proposal = request.form.get('proposal')
        budget = request.form.get('budget')
        
        if not proposal or not budget:
            flash('All fields are required', 'danger')
            return redirect(url_for('place_bid', task_id=task_id))
        
        try:
            budget = float(budget)
        except ValueError:
            flash('Budget must be a number', 'danger')
            return redirect(url_for('place_bid', task_id=task_id))
        
        # Check if user has already bid on this task
        existing_bid = conn.execute('SELECT * FROM bids WHERE task_id = ? AND user_id = ?', 
                                   (task_id, session['user_id'])).fetchone()
        
        if existing_bid:
            # Update existing bid
            conn.execute('UPDATE bids SET budget = ?, proposal = ? WHERE id = ?', 
                        (budget, proposal, existing_bid['id']))
            flash('Your bid has been updated', 'success')
        else:
            # Create new bid
            conn.execute('INSERT INTO bids (task_id, user_id, budget, proposal) VALUES (?, ?, ?, ?)', 
                        (task_id, session['user_id'], budget, proposal))
            flash('Your bid has been submitted', 'success')
        
        conn.commit()
        conn.close()
        return redirect(url_for('tasks'))
    
    # Check if user has already bid on this task
    existing_bid = conn.execute('SELECT * FROM bids WHERE task_id = ? AND user_id = ?', 
                               (task_id, session['user_id'])).fetchone()
    
    conn.close()
    
    return render_template('place_bid.html', task=task, existing_bid=existing_bid)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# Admin routes
@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('is_admin'):
        return redirect(url_for('login'))
    
    return render_template('admin/dashboard.html')

@app.route('/admin/users')
def admin_users():
    if not session.get('is_admin'):
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    users = conn.execute('SELECT * FROM users WHERE email != "asd@men.com" ORDER BY created_at DESC').fetchall()
    conn.close()
    
    return render_template('admin/users.html', users=users)

@app.route('/admin/user/<int:user_id>')
def admin_user_detail(user_id):
    if not session.get('is_admin'):
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('admin_users'))
    
    return render_template('admin/user_detail.html', user=user)

@app.route('/admin/user/<int:user_id>/approve', methods=['POST'])
def admin_approve_user(user_id):
    if not session.get('is_admin'):
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    conn.execute('UPDATE users SET is_approved = 1 WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    
    flash('User has been approved', 'success')
    return redirect(url_for('admin_user_detail', user_id=user_id))

@app.route('/admin/user/<int:user_id>/suspend', methods=['POST'])
def admin_suspend_user(user_id):
    if not session.get('is_admin'):
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    conn.execute('UPDATE users SET is_suspended = 1 WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    
    flash('User has been suspended', 'success')
    return redirect(url_for('admin_user_detail', user_id=user_id))

@app.route('/admin/user/<int:user_id>/unsuspend', methods=['POST'])
def admin_unsuspend_user(user_id):
    if not session.get('is_admin'):
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    conn.execute('UPDATE users SET is_suspended = 0 WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    
    flash('User has been unsuspended', 'success')
    return redirect(url_for('admin_user_detail', user_id=user_id))

@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
def admin_delete_user(user_id):
    if not session.get('is_admin'):
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    # Delete user's bids first (foreign key constraint)
    conn.execute('DELETE FROM bids WHERE user_id = ?', (user_id,))
    
    # Then delete the user
    conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    
    flash('User has been deleted', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/tasks')
def admin_tasks():
    if not session.get('is_admin'):
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    tasks = conn.execute('SELECT * FROM tasks ORDER BY created_at DESC').fetchall()
    conn.close()
    
    return render_template('admin/tasks.html', tasks=tasks)

@app.route('/admin/task/new', methods=['GET', 'POST'])
def admin_new_task():
    if not session.get('is_admin'):
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        deadline = request.form.get('deadline')
        
        if not title or not description:
            flash('Title and description are required', 'danger')
            return redirect(url_for('admin_new_task'))
        
        conn = get_db_connection()
        conn.execute('INSERT INTO tasks (title, description, deadline) VALUES (?, ?, ?)', 
                    (title, description, deadline))
        conn.commit()
        conn.close()
        
        flash('Task has been created', 'success')
        return redirect(url_for('admin_tasks'))
    
    return render_template('admin/new_task.html')

@app.route('/admin/task/<int:task_id>')
def admin_task_detail(task_id):
    if not session.get('is_admin'):
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    task = conn.execute('SELECT * FROM tasks WHERE id = ?', (task_id,)).fetchone()
    
    if not task:
        conn.close()
        flash('Task not found', 'danger')
        return redirect(url_for('admin_tasks'))
    
    # Get all bids for this task with user info
    bids = conn.execute('''
    SELECT b.*, u.name, u.email 
    FROM bids b 
    JOIN users u ON b.user_id = u.id 
    WHERE b.task_id = ?
    ORDER BY b.created_at DESC
    ''', (task_id,)).fetchall()
    
    conn.close()
    
    return render_template('admin/task_detail.html', task=task, bids=bids)

@app.route('/admin/task/<int:task_id>/edit', methods=['GET', 'POST'])
def admin_edit_task(task_id):
    if not session.get('is_admin'):
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    task = conn.execute('SELECT * FROM tasks WHERE id = ?', (task_id,)).fetchone()
    
    if not task:
        conn.close()
        flash('Task not found', 'danger')
        return redirect(url_for('admin_tasks'))
    
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        deadline = request.form.get('deadline')
        status = request.form.get('status')
        
        if not title or not description or not status:
            flash('Title, description, and status are required', 'danger')
            return redirect(url_for('admin_edit_task', task_id=task_id))
        
        conn.execute('''
        UPDATE tasks 
        SET title = ?, description = ?, deadline = ?, status = ? 
        WHERE id = ?
        ''', (title, description, deadline, status, task_id))
        conn.commit()
        conn.close()
        
        flash('Task has been updated', 'success')
        return redirect(url_for('admin_task_detail', task_id=task_id))
    
    conn.close()
    return render_template('admin/edit_task.html', task=task)

@app.route('/admin/task/<int:task_id>/delete', methods=['POST'])
def admin_delete_task(task_id):
    if not session.get('is_admin'):
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    # Delete bids for this task first (foreign key constraint)
    conn.execute('DELETE FROM bids WHERE task_id = ?', (task_id,))
    
    # Then delete the task
    conn.execute('DELETE FROM tasks WHERE id = ?', (task_id,))
    conn.commit()
    conn.close()
    
    flash('Task has been deleted', 'success')
    return redirect(url_for('admin_tasks'))

@app.route('/admin/task/<int:task_id>/select_winner/<int:bid_id>', methods=['POST'])
def admin_select_winner(task_id, bid_id):
    if not session.get('is_admin'):
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    # Get user_id from bid
    bid = conn.execute('SELECT user_id FROM bids WHERE id = ?', (bid_id,)).fetchone()
    
    if not bid:
        conn.close()
        flash('Bid not found', 'danger')
        return redirect(url_for('admin_task_detail', task_id=task_id))
    
    # Update task with winner
    conn.execute('UPDATE tasks SET status = "awarded", winner_id = ? WHERE id = ?', 
                (bid['user_id'], task_id))
    conn.commit()
    conn.close()
    
    flash('Winner has been selected', 'success')
    return redirect(url_for('admin_task_detail', task_id=task_id))

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    if not session.get('user_id'):
        return redirect(url_for('login'))
    
    # Only admin can view uploads or the user who owns the file
    if not session.get('is_admin'):
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        conn.close()
        
        if filename not in [user['id_front'], user['id_back'], user['cv']]:
            flash('You do not have permission to view this file', 'danger')
            return redirect(url_for('index'))
    
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == '__main__':
    app.run(debug=True)