#!/usr/bin/env python3
"""
Bulk User Creation Script for WebProxy Login Portal

This script allows administrators to create multiple user accounts from a CSV file.
The CSV file should contain columns: username, password, is_admin, resources (optional)

Usage:
    python bulk_create_users.py users.csv
    python bulk_create_users.py users.csv --dry-run
    python bulk_create_users.py users.csv --force

CSV Format:
    username,password,is_admin,resources
    john_doe,secure123,0,"Resource1,Resource2"
    jane_admin,admin456,1,
    bob_user,password789,0,Resource3
    
Notes:
    - resources column is optional
    - multiple resources can be separated by commas
    - resource names or IDs are supported
    - empty resources field is allowed
"""

import csv
import sqlite3
import argparse
import sys
import os
from werkzeug.security import generate_password_hash
from datetime import datetime


# Database configuration (should match app.py)
DATABASE = "portal.db"


def get_db_connection():
    """Get database connection - matches app.py implementation"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def validate_csv_format(csv_file):
    """Validate CSV file format and return list of user records"""
    users = []
    errors = []
    
    try:
        with open(csv_file, 'r', newline='', encoding='utf-8') as file:
            # Check if file is empty
            if os.path.getsize(csv_file) == 0:
                errors.append("CSV file is empty")
                return users, errors
                
            # Reset file pointer
            file.seek(0)
            reader = csv.DictReader(file)
            
            # Validate headers
            required_headers = {'username', 'password', 'is_admin'}
            optional_headers = {'resources'}
            actual_headers = set(reader.fieldnames) if reader.fieldnames else set()
            
            if not required_headers.issubset(actual_headers):
                missing = required_headers - actual_headers
                errors.append(f"Missing required columns: {', '.join(missing)}")
                return users, errors
            
            # Validate each row
            for row_num, row in enumerate(reader, start=2):  # Start at 2 because of header
                username = row.get('username', '').strip()
                password = row.get('password', '').strip()
                is_admin = row.get('is_admin', '').strip()
                resources_str = row.get('resources', '').strip()
                
                row_errors = []
                
                # Validate username
                if not username:
                    row_errors.append("username cannot be empty")
                elif len(username) < 3:
                    row_errors.append("username must be at least 3 characters")
                elif len(username) > 50:
                    row_errors.append("username must be no more than 50 characters")
                
                # Validate password
                if not password:
                    row_errors.append("password cannot be empty")
                elif len(password) < 6:
                    row_errors.append("password must be at least 6 characters")
                
                # Validate is_admin
                if is_admin not in ['0', '1', 'true', 'false', 'True', 'False']:
                    row_errors.append("is_admin must be 0, 1, true, or false")
                
                # Parse resources
                resource_list = []
                if resources_str:
                    # Split by comma and clean up whitespace
                    resource_list = [r.strip() for r in resources_str.split(',') if r.strip()]
                
                if row_errors:
                    errors.append(f"Row {row_num}: {', '.join(row_errors)}")
                else:
                    # Convert is_admin to boolean
                    admin_bool = is_admin.lower() in ['1', 'true']
                    users.append({
                        'username': username,
                        'password': password,
                        'is_admin': admin_bool,
                        'resources': resource_list
                    })
    
    except FileNotFoundError:
        errors.append(f"File not found: {csv_file}")
    except csv.Error as e:
        errors.append(f"CSV parsing error: {e}")
    except Exception as e:
        errors.append(f"Unexpected error reading file: {e}")
    
    return users, errors


def check_existing_users(users):
    """Check which usernames already exist in the database"""
    if not users:
        return set()
    
    try:
        conn = get_db_connection()
        usernames = [user['username'] for user in users]
        placeholders = ','.join(['?' for _ in usernames])
        query = f"SELECT username FROM users WHERE username IN ({placeholders})"
        
        existing = conn.execute(query, usernames).fetchall()
        conn.close()
        
        return {row['username'] for row in existing}
    
    except Exception as e:
        print(f"Error checking existing users: {e}")
        return set()


def get_all_resources():
    """Get all resources from the database (name and ID mapping)"""
    try:
        conn = get_db_connection()
        resources = conn.execute("SELECT id, name FROM resources ORDER BY name").fetchall()
        conn.close()
        
        # Create both name->id and id->name mappings
        name_to_id = {row['name']: row['id'] for row in resources}
        id_to_name = {row['id']: row['name'] for row in resources}
        
        return name_to_id, id_to_name
    
    except Exception as e:
        print(f"Error fetching resources: {e}")
        return {}, {}


def validate_user_resources(users):
    """Validate that all specified resources exist and convert names to IDs"""
    if not users:
        return [], []
    
    # Get resource mappings
    name_to_id, id_to_name = get_all_resources()
    
    validated_users = []
    errors = []
    
    for user in users:
        username = user['username']
        resource_list = user.get('resources', [])
        validated_resources = []
        user_errors = []
        
        for resource in resource_list:
            # Try to parse as integer ID first
            try:
                resource_id = int(resource)
                if resource_id in id_to_name:
                    validated_resources.append(resource_id)
                else:
                    user_errors.append(f"Resource ID {resource_id} does not exist")
            except ValueError:
                # Not an integer, treat as resource name
                if resource in name_to_id:
                    validated_resources.append(name_to_id[resource])
                else:
                    user_errors.append(f"Resource '{resource}' does not exist")
        
        if user_errors:
            errors.append(f"User '{username}': {', '.join(user_errors)}")
        
        # Create new user dict with validated resource IDs
        validated_user = user.copy()
        validated_user['resource_ids'] = validated_resources
        validated_users.append(validated_user)
    
    return validated_users, errors


def create_users(users, force=False):
    """Create users in the database"""
    if not users:
        print("No users to create.")
        return
    
    # Check for existing users
    existing_users = check_existing_users(users)
    
    if existing_users and not force:
        print(f"\nFound existing usernames: {', '.join(existing_users)}")
        print("Use --force to skip existing users and create only new ones.")
        return
    
    conn = get_db_connection()
    created_count = 0
    skipped_count = 0
    failed_count = 0
    resource_assignments = 0
    
    print(f"\nCreating {len(users)} users...")
    print("-" * 50)
    
    for user in users:
        username = user['username']
        password = user['password']
        is_admin = user['is_admin']
        resource_ids = user.get('resource_ids', [])
        
        try:
            # Skip if user exists and force is enabled
            if username in existing_users:
                if force:
                    print(f"SKIPPED: {username} (already exists)")
                    skipped_count += 1
                    continue
                else:
                    print(f"FAILED: {username} (already exists)")
                    failed_count += 1
                    continue
            
            # Create password hash
            password_hash = generate_password_hash(password)
            
            # Insert user
            cursor = conn.execute(
                "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)",
                (username, password_hash, is_admin)
            )
            user_id = cursor.lastrowid
            
            # Create resource assignments
            resources_assigned = 0
            for resource_id in resource_ids:
                try:
                    conn.execute(
                        "INSERT INTO user_resources (user_id, resource_id) VALUES (?, ?)",
                        (user_id, resource_id)
                    )
                    resources_assigned += 1
                    resource_assignments += 1
                except sqlite3.IntegrityError:
                    # Resource assignment already exists (shouldn't happen for new users)
                    pass
            
            role = "Admin" if is_admin else "User"
            resource_msg = f" with {resources_assigned} resources" if resources_assigned > 0 else ""
            print(f"CREATED: {username} ({role}){resource_msg}")
            created_count += 1
            
        except sqlite3.IntegrityError:
            print(f"FAILED: {username} (username already exists)")
            failed_count += 1
        except Exception as e:
            print(f"FAILED: {username} (error: {e})")
            failed_count += 1
    
    # Commit all changes
    conn.commit()
    conn.close()
    
    print("-" * 50)
    print(f"Summary: {created_count} created, {skipped_count} skipped, {failed_count} failed")
    if resource_assignments > 0:
        print(f"Resource assignments: {resource_assignments} created")


def dry_run(users):
    """Show what would be created without actually creating users"""
    if not users:
        print("No users to create.")
        return
    
    existing_users = check_existing_users(users)
    
    # Get resource name mappings for display
    _, id_to_name = get_all_resources()
    
    print(f"\nDRY RUN: Would create {len(users)} users...")
    print("-" * 50)
    
    total_resource_assignments = 0
    
    for user in users:
        username = user['username']
        is_admin = user['is_admin']
        resource_ids = user.get('resource_ids', [])
        role = "Admin" if is_admin else "User"
        
        # Create resource names list for display
        resource_names = [id_to_name.get(rid, f"ID:{rid}") for rid in resource_ids]
        resource_msg = f" with resources: {', '.join(resource_names)}" if resource_names else ""
        
        if username in existing_users:
            print(f"WOULD SKIP: {username} ({role}){resource_msg} - already exists")
        else:
            print(f"WOULD CREATE: {username} ({role}){resource_msg}")
            total_resource_assignments += len(resource_ids)
    
    print("-" * 50)
    new_users = [u for u in users if u['username'] not in existing_users]
    existing_count = len(users) - len(new_users)
    print(f"Summary: {len(new_users)} would be created, {existing_count} would be skipped")
    if total_resource_assignments > 0:
        print(f"Resource assignments: {total_resource_assignments} would be created")


def main():
    parser = argparse.ArgumentParser(
        description="Bulk create users from CSV file",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
CSV Format:
    username,password,is_admin,resources
    john_doe,secure123,0,"Resource1,Resource2"
    jane_admin,admin456,1,
    bob_user,password789,0,Resource3

Notes:
    - is_admin can be: 0, 1, true, false (case insensitive)
    - resources column is optional
    - multiple resources can be separated by commas
    - resource names or IDs are supported
    - usernames must be 3-50 characters
    - passwords must be at least 6 characters
    - existing usernames will be skipped unless --force is used
        """
    )
    
    parser.add_argument('csv_file', help='Path to CSV file containing user data')
    parser.add_argument('--dry-run', action='store_true', 
                       help='Show what would be created without actually creating users')
    parser.add_argument('--force', action='store_true',
                       help='Skip existing users and create only new ones')
    
    args = parser.parse_args()
    
    # Check if database exists
    if not os.path.exists(DATABASE):
        print(f"Error: Database file '{DATABASE}' not found.")
        print("Make sure you're running this script from the same directory as app.py")
        sys.exit(1)
    
    # Validate CSV and load users
    print(f"Reading CSV file: {args.csv_file}")
    users, errors = validate_csv_format(args.csv_file)
    
    if errors:
        print("\nValidation errors:")
        for error in errors:
            print(f"  - {error}")
        sys.exit(1)
    
    if not users:
        print("No valid users found in CSV file.")
        sys.exit(1)
    
    print(f"Found {len(users)} valid users in CSV file.")
    
    # Validate resources and convert to IDs
    users, resource_errors = validate_user_resources(users)
    
    if resource_errors:
        print("\nResource validation errors:")
        for error in resource_errors:
            print(f"  - {error}")
        sys.exit(1)
    
    # Execute action
    if args.dry_run:
        dry_run(users)
    else:
        create_users(users, force=args.force)


if __name__ == "__main__":
    main()