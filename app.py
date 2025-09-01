from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_wtf import FlaskForm, CSRFProtect
from flask_wtf.csrf import validate_csrf
from wtforms import StringField, PasswordField, TextAreaField, SubmitField, SelectField, URLField
from wtforms.validators import DataRequired, Length, URL, Optional
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import json
import os
from datetime import datetime
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-change-in-production')
csrf = CSRFProtect(app)

# Database setup
DATABASE = 'portal.db'

def init_db():
    """Initialize the database with tables"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Resources table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS resources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            url TEXT NOT NULL,
            description TEXT,
            category TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # User resources table (many-to-many relationship)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_resources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            resource_id INTEGER,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (resource_id) REFERENCES resources (id),
            UNIQUE(user_id, resource_id)
        )
    ''')
    
    # Create default admin user if it doesn't exist
    cursor.execute('SELECT COUNT(*) FROM users WHERE username = ?', ('admin',))
    if cursor.fetchone()[0] == 0:
        admin_password_hash = generate_password_hash('admin123')
        cursor.execute(
            'INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)',
            ('admin', admin_password_hash, True)
        )
    
    conn.commit()
    conn.close()

def get_db_connection():
    """Get database connection"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def login_required(f):
    """Decorator to require login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to require admin privileges"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        
        conn = get_db_connection()
        user = conn.execute('SELECT is_admin FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        conn.close()
        
        if not user or not user['is_admin']:
            flash('Admin access required.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Forms
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=50)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class ResourceForm(FlaskForm):
    name = StringField('Resource Name', validators=[DataRequired(), Length(max=100)])
    url = URLField('URL', validators=[DataRequired(), URL()])
    description = TextAreaField('Description', validators=[Optional(), Length(max=500)])
    category = StringField('Category', validators=[Optional(), Length(max=50)])
    submit = SubmitField('Add Resource')

class UserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=50)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    is_admin = SelectField('Role', choices=[('0', 'User'), ('1', 'Admin')], coerce=int)
    submit = SubmitField('Create User')

class AssignResourceForm(FlaskForm):
    user_id = SelectField('User', coerce=int, validators=[DataRequired()])
    resource_id = SelectField('Resource', coerce=int, validators=[DataRequired()])
    submit = SubmitField('Assign Resource')

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT id, username, password_hash, is_admin FROM users WHERE username = ?',
            (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = bool(user['is_admin'])
            flash(f'Welcome, {username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'error')
    
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db_connection()
    
    # Get user's assigned resources
    resources = conn.execute('''
        SELECT r.id, r.name, r.url, r.description, r.category
        FROM resources r
        JOIN user_resources ur ON r.id = ur.resource_id
        WHERE ur.user_id = ?
        ORDER BY r.category, r.name
    ''', (session['user_id'],)).fetchall()
    
    conn.close()
    
    # Group resources by category
    resources_by_category = {}
    for resource in resources:
        category = resource['category'] or 'General'
        if category not in resources_by_category:
            resources_by_category[category] = []
        resources_by_category[category].append(resource)
    
    return render_template('dashboard.html', resources_by_category=resources_by_category)

@app.route('/admin')
@admin_required
def admin_dashboard():
    conn = get_db_connection()
    
    # Get stats
    user_count = conn.execute('SELECT COUNT(*) as count FROM users').fetchone()['count']
    resource_count = conn.execute('SELECT COUNT(*) as count FROM resources').fetchone()['count']
    
    # Get recent users
    recent_users = conn.execute('''
        SELECT username, created_at, is_admin 
        FROM users 
        ORDER BY created_at DESC 
        LIMIT 5
    ''').fetchall()
    
    # Get recent resources
    recent_resources = conn.execute('''
        SELECT name, url, category, created_at 
        FROM resources 
        ORDER BY created_at DESC 
        LIMIT 5
    ''').fetchall()
    
    conn.close()
    
    return render_template('admin/dashboard.html', 
                         user_count=user_count,
                         resource_count=resource_count,
                         recent_users=recent_users,
                         recent_resources=recent_resources)

@app.route('/admin/users')
@admin_required
def admin_users():
    conn = get_db_connection()
    users = conn.execute('''
        SELECT id, username, is_admin, created_at,
               (SELECT COUNT(*) FROM user_resources WHERE user_id = users.id) as resource_count
        FROM users 
        ORDER BY created_at DESC
    ''').fetchall()
    conn.close()
    
    return render_template('admin/users.html', users=users)

@app.route('/admin/users/new', methods=['GET', 'POST'])
@admin_required
def admin_create_user():
    form = UserForm()
    
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        is_admin = bool(form.is_admin.data)
        
        conn = get_db_connection()
        
        # Check if username already exists
        existing_user = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
        if existing_user:
            flash('Username already exists.', 'error')
        else:
            password_hash = generate_password_hash(password)
            conn.execute(
                'INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)',
                (username, password_hash, is_admin)
            )
            conn.commit()
            flash(f'User {username} created successfully.', 'success')
            conn.close()
            return redirect(url_for('admin_users'))
        
        conn.close()
    
    return render_template('admin/create_user.html', form=form)

@app.route('/admin/resources')
@admin_required
def admin_resources():
    conn = get_db_connection()
    resources = conn.execute('''
        SELECT id, name, url, description, category, created_at,
               (SELECT COUNT(*) FROM user_resources WHERE resource_id = resources.id) as user_count
        FROM resources 
        ORDER BY category, name
    ''').fetchall()
    conn.close()
    
    return render_template('admin/resources.html', resources=resources)

@app.route('/admin/resources/new', methods=['GET', 'POST'])
@admin_required
def admin_create_resource():
    form = ResourceForm()
    
    if form.validate_on_submit():
        name = form.name.data
        url = form.url.data
        description = form.description.data
        category = form.category.data
        
        conn = get_db_connection()
        conn.execute(
            'INSERT INTO resources (name, url, description, category) VALUES (?, ?, ?, ?)',
            (name, url, description, category)
        )
        conn.commit()
        conn.close()
        
        flash(f'Resource {name} created successfully.', 'success')
        return redirect(url_for('admin_resources'))
    
    return render_template('admin/create_resource.html', form=form)

@app.route('/admin/assign', methods=['GET', 'POST'])
@admin_required
def admin_assign_resource():
    form = AssignResourceForm()
    
    # Populate form choices
    conn = get_db_connection()
    users = conn.execute('SELECT id, username FROM users ORDER BY username').fetchall()
    resources = conn.execute('SELECT id, name FROM resources ORDER BY name').fetchall()
    
    form.user_id.choices = [(user['id'], user['username']) for user in users]
    form.resource_id.choices = [(resource['id'], resource['name']) for resource in resources]
    
    if form.validate_on_submit():
        user_id = form.user_id.data
        resource_id = form.resource_id.data
        
        try:
            conn.execute(
                'INSERT INTO user_resources (user_id, resource_id) VALUES (?, ?)',
                (user_id, resource_id)
            )
            conn.commit()
            
            # Get user and resource names for flash message
            user = conn.execute('SELECT username FROM users WHERE id = ?', (user_id,)).fetchone()
            resource = conn.execute('SELECT name FROM resources WHERE id = ?', (resource_id,)).fetchone()
            
            flash(f'Resource "{resource["name"]}" assigned to user "{user["username"]}" successfully.', 'success')
        except sqlite3.IntegrityError:
            flash('Resource is already assigned to this user.', 'error')
        
        conn.close()
        return redirect(url_for('admin_assign_resource'))
    
    conn.close()
    return render_template('admin/assign_resource.html', form=form)

@app.route('/admin/assignments')
@admin_required
def admin_assignments():
    conn = get_db_connection()
    assignments = conn.execute('''
        SELECT ur.id, u.username, r.name as resource_name, r.url
        FROM user_resources ur
        JOIN users u ON ur.user_id = u.id
        JOIN resources r ON ur.resource_id = r.id
        ORDER BY u.username, r.name
    ''').fetchall()
    conn.close()
    
    return render_template('admin/assignments.html', assignments=assignments)

@app.route('/admin/assignments/<int:assignment_id>/delete', methods=['POST'])
@admin_required
def admin_delete_assignment(assignment_id):
    try:
        validate_csrf(request.form.get('csrf_token'))
        
        conn = get_db_connection()
        conn.execute('DELETE FROM user_resources WHERE id = ?', (assignment_id,))
        conn.commit()
        conn.close()
        
        flash('Assignment removed successfully.', 'success')
    except Exception as e:
        flash('Error removing assignment.', 'error')
    
    return redirect(url_for('admin_assignments'))

@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    try:
        validate_csrf(request.form.get('csrf_token'))
        
        # Prevent deleting the current user
        if user_id == session['user_id']:
            flash('Cannot delete your own account.', 'error')
            return redirect(url_for('admin_users'))
        
        conn = get_db_connection()
        
        # Delete user assignments first
        conn.execute('DELETE FROM user_resources WHERE user_id = ?', (user_id,))
        
        # Delete user
        conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()
        conn.close()
        
        flash('User deleted successfully.', 'success')
    except Exception as e:
        flash('Error deleting user.', 'error')
    
    return redirect(url_for('admin_users'))

@app.route('/admin/resources/<int:resource_id>/delete', methods=['POST'])
@admin_required
def admin_delete_resource(resource_id):
    try:
        validate_csrf(request.form.get('csrf_token'))
        
        conn = get_db_connection()
        
        # Delete resource assignments first
        conn.execute('DELETE FROM user_resources WHERE resource_id = ?', (resource_id,))
        
        # Delete resource
        conn.execute('DELETE FROM resources WHERE id = ?', (resource_id,))
        conn.commit()
        conn.close()
        
        flash('Resource deleted successfully.', 'success')
    except Exception as e:
        flash('Error deleting resource.', 'error')
    
    return redirect(url_for('admin_resources'))

@app.errorhandler(404)
def not_found(error):
    return render_template('errors/404.html'), 404

@app.errorhandler(403)
def forbidden(error):
    return render_template('errors/403.html'), 403

@app.errorhandler(500)
def internal_error(error):
    return render_template('errors/500.html'), 500

#if __name__ == '__main__':
#    init_db()
#    app.run(debug=True, host='0.0.0.0', port=8080)
