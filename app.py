from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import smtplib
from email.mime.text import MIMEText
import os
from datetime import datetime, timedelta # Import timedelta for expiry date
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.secret_key = "sri123"  # Change in production
DB_NAME = "jeevanlink.db"

# Helper function to get user info by ID
def get_user_info(user_id):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT id, name, email, phone FROM users WHERE id = ?", (user_id,))
    user_info = c.fetchone()
    conn.close()
    if user_info:
        return {
            'id': user_info[0],
            'name': user_info[1],
            'email': user_info[2],
            'phone': user_info[3]
        }
    return None

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()

    print("Initializing database...")

    # 1. 'users' table schema: Add 'phone', ensure 'email' is unique
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        phone TEXT NOT NULL DEFAULT 'N/A'
    )''')
    conn.commit()
    print("Table 'users' ensured to exist.")

    # 2. 'donors' table remains the same (as per latest provided donor.html)
    c.execute('''CREATE TABLE IF NOT EXISTS donors (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        phone TEXT NOT NULL,
        email TEXT NOT NULL,
        organ TEXT NOT NULL,
        organ_other TEXT,
        blood_group TEXT NOT NULL,
        city TEXT NOT NULL
    )''')
    conn.commit()
    print("Table 'donors' ensured to exist.")

    # 3. 'requests' table schema: Add 'requester_user_id', 'expiry_date'
    # and adjust 'city' to 'requester_address'
    c.execute('''CREATE TABLE IF NOT EXISTS requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        requester_user_id INTEGER NOT NULL,
        blood_group TEXT NOT NULL,
        organ TEXT NOT NULL,
        organ_other TEXT,
        requester_address TEXT NOT NULL,
        requester_phone TEXT NOT NULL,
        urgent INTEGER DEFAULT 0,
        requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expiry_date TEXT NOT NULL DEFAULT (STRFTIME('%Y-%m-%d %H:%M:%S', DATE('now', '+30 days'))),
        FOREIGN KEY (requester_user_id) REFERENCES users(id)
    )''')
    conn.commit()
    print("Table 'requests' ensured to exist and updated.")

    # 4. Create 'messages' table for in-app messaging (if not exists)
    c.execute('''CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_id INTEGER NOT NULL,
        sender_user_id INTEGER NOT NULL,
        message_content TEXT NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (request_id) REFERENCES requests(id),
        FOREIGN KEY (sender_user_id) REFERENCES users(id)
    )''')
    conn.commit()
    print("Table 'messages' ensured to exist.")
    print("Database initialization complete.")


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        phone = request.form['phone']
        confirm = request.form['confirm']

        if password != confirm:
            flash("Passwords do not match!")
            return render_template('signup.html')

        hashed_pw = generate_password_hash(password)

        with sqlite3.connect(DB_NAME) as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM users WHERE email = ?", (email,))
            if cur.fetchone():
                flash("Email already registered!")
                return render_template('signup.html')

            cur.execute("INSERT INTO users (name, email, password, phone) VALUES (?, ?, ?, ?)",
                        (name, email, hashed_pw, phone))
            conn.commit()

        flash("Signup successful! Please login.")
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        with sqlite3.connect(DB_NAME) as conn:
            cur = conn.cursor()
            cur.execute("SELECT id, name, email, password, phone FROM users WHERE email = ?", (email,))
            user = cur.fetchone()

            if user and check_password_hash(user[3], password):
                session['user_id'] = user[0]
                session['user_name'] = user[1]
                session['user_email'] = user[2]
                session['user_phone'] = user[4]
                flash("Login successful!")
                return redirect(url_for('home'))
            else:
                flash("Invalid email or password")

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('user_name', None)
    session.pop('user_email', None)
    session.pop('user_phone', None)
    flash("Logged out successfully")
    return redirect(url_for('home'))


@app.route('/donor', methods=['GET', 'POST'])
def donor():
    if 'user_id' not in session:
        flash("Please login to access the donor form.")
        return redirect(url_for('login'))

    if request.method == 'POST':
        name = request.form.get('name')
        phone = request.form.get('phone')
        email = request.form.get('email') or request.form.get('contact')
        organ = request.form.get('organ')
        organ_other = request.form.get('other_organ') if organ == 'Other' else ''
        blood_group = request.form.get('blood_group')
        city = request.form.get('city')

        if not (name and phone and email and organ and blood_group and city):
            flash("Please fill in all required fields.", "error")
            return redirect(url_for('donor'))

        try:
            conn = sqlite3.connect(DB_NAME)
            c = conn.cursor()
            c.execute('''
                INSERT INTO donors (name, phone, email, organ, organ_other, blood_group, city)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (name, phone, email, organ, organ_other, blood_group, city))
            conn.commit()
            conn.close()
        except Exception as e:
            flash(f"Database error: {e}", "error")
            return redirect(url_for('donor'))

        flash("Thank you for registering as a donor!", "success")
        return redirect(url_for('thankyou', donor_name=name))

    return render_template('donor.html')


@app.route('/thankyou')
def thankyou():
    donor_name = request.args.get('donor_name', 'Donor')
    return render_template('thankyou.html', donor_name=donor_name)

@app.route('/find_match', methods=['GET', 'POST'])
def find_match():
    searched = False
    matches = []
    form_data = {
        'organ': '',
        'blood_group': '',
        'city': '',
        'organ_other': ''
    }

    if request.method == 'POST':
        searched = True
        organ = request.form.get('organ', '')
        organ_other = request.form.get('organ_other', '')
        blood_group = request.form.get('blood_group', '')
        city = request.form.get('city', '')

        form_data.update({
            'organ': organ,
            'organ_other': organ_other,
            'blood_group': blood_group,
            'city': city
        })

        if not any([organ, organ_other, blood_group, city]):
            flash("Please enter at least one field to search.", "error")
            searched = False
            return render_template('find_match.html', matches=[], form_data=form_data, searched=searched)

        conn = None
        try:
            conn = sqlite3.connect(DB_NAME)
            c = conn.cursor()

            query = "SELECT name, phone, email, organ, organ_other, blood_group, city FROM donors WHERE 1=1"
            params = []

            if organ == "Other" and organ_other:
                query += " AND organ = 'Other' AND organ_other LIKE ?"
                params.append(f"%{organ_other}%")
            elif organ:
                query += " AND organ = ?"
                params.append(organ)

            if blood_group:
                query += " AND blood_group = ?"
                params.append(blood_group)

            c.execute(query, tuple(params))
            all_matches = c.fetchall()

            if city:
                matches = [m for m in all_matches if city.lower() in m[6].lower()]
            else:
                matches = all_matches

            if not matches:
                flash("No matches found for your criteria.", "error")

        except Exception as e:
            flash(f"Error: {e}", "error")
        finally:
            if conn:
                conn.close()

    if request.args.get('from_home') == '1' and not searched:
        searched = False

    return render_template('find_match.html', matches=matches, form_data=form_data, searched=searched)


@app.route('/receiver')
def receiver_redirect():
    return redirect(url_for('find_match'))


def notify_all_donors_of_urgent_request(requester_info):
    sender = os.getenv('EMAIL_USER')
    password = os.getenv('EMAIL_PASS')

    if not sender or not password:
        print("ERROR: Email configuration is missing. Cannot send urgent notifications.")
        return False

    conn = None
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("SELECT email FROM donors")
        donor_emails = c.fetchall()
    except Exception as e:
        print(f"ERROR: Failed to fetch donor emails: {e}")
        return False
    finally:
        if conn:
            conn.close()

    if not donor_emails:
        print("INFO: No registered donors to send urgent request notification to.")
        return True

    subject = "URGENT: New Organ/Blood Request on JeevanLink!"
    
    request_id = requester_info.get('request_id')
    if request_id:
        request_details_link = url_for('request_details', request_id=request_id, _external=True)
        link_text = f"View this urgent request's details: {request_details_link}\n\n"
    else:
        link_text = "Please check the donor dashboard for new urgent requests.\n\n"


    body = (
        f"Hello Donor,\n\n"
        f"There's a new URGENT request posted on JeevanLink. Your help is needed!\n\n"
        f"  Requester Name: {requester_info['requester_name']}\n"
        f"  Needed: {requester_info['organ']} (Blood Group: {requester_info['blood_group']})\n"
        f"  Address: {requester_info['requester_address']}\n"
        f"  Mobile: {requester_info['requester_phone']}\n\n"
        f"{link_text}"
        f"Thanks,\nJeevanLink Team"
    )

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(sender, password)
            for email_tuple in donor_emails:
                donor_email = email_tuple[0]
                msg = MIMEText(body)
                msg['Subject'] = subject
                msg['From'] = sender
                msg['To'] = donor_email
                smtp.send_message(msg)
                print(f"Sent urgent notification to {donor_email}")
        return True
    except Exception as e:
        print(f"ERROR: Failed to send urgent notifications to all donors: {str(e)}")
        return False


@app.route('/post_request', methods=['GET', 'POST'])
def post_request():
    if 'user_id' not in session:
        flash("Please login to post requests.", "error")
        return redirect(url_for('login'))

    form_data = {
        'request_type': request.args.get('request_type', 'organ'),
        'organ': request.args.get('organ', ''),
        'organ_other': request.args.get('organ_other', ''),
        'blood_group': request.args.get('blood_group', ''),
        'requester_address': session.get('user_address', ''), # This will be empty for new users
        'requester_phone': session.get('user_phone', ''),
        'urgent': request.args.get('urgent', '0')
    }

    if request.method == 'POST':
        requester_user_id = session['user_id']
        requester_name = session['user_name']
        blood_group = request.form.get('blood_group')
        request_type = request.form.get('request_type')
        requester_address = request.form.get('requester_address')
        requester_phone = request.form.get('requester_phone')
        urgent = 1 if request.form.get('urgent') == 'on' else 0
        
        organ_for_db = ''
        organ_other_for_db = ''
        validation_error_message = None

        if request_type == 'organ':
            organ_for_db = request.form.get('organ')
            organ_other_for_db = request.form.get('other_organ') if organ_for_db == 'Other' else ''
            if not (organ_for_db and blood_group and requester_address and requester_phone):
                validation_error_message = "Please fill in all required fields for organ request: Organ, Blood Group, Address, and Mobile Number."
        elif request_type == 'blood':
            organ_for_db = 'Blood Request'
            organ_other_for_db = ''
            if not (blood_group and requester_address and requester_phone):
                validation_error_message = "Please fill in all required fields for blood request: Blood Group, Address, and Mobile Number."
        else:
            validation_error_message = "Invalid request type selected. Please choose either Organ or Blood."
            
        if validation_error_message:
            flash(validation_error_message, "error")
            form_data.update({
                'request_type': request_type,
                'organ': request.form.get('organ', '') if request_type == 'organ' else '',
                'organ_other': request.form.get('other_organ', '') if request_type == 'organ' and request.form.get('organ') == 'Other' else '',
                'blood_group': blood_group,
                'requester_address': requester_address,
                'requester_phone': requester_phone,
                'urgent': str(urgent)
            })
            return render_template('post_request.html', form_data=form_data)

        conn = None
        try:
            conn = sqlite3.connect(DB_NAME)
            c = conn.cursor()
            expiry_date = datetime.now() + timedelta(days=30)
            expiry_date_str = expiry_date.strftime('%Y-%m-%d %H:%M:%S')

            c.execute('''
                INSERT INTO requests (requester_user_id, blood_group, organ, organ_other, requester_address, requester_phone, urgent, expiry_date)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (requester_user_id, blood_group, organ_for_db, organ_other_for_db, requester_address, requester_phone, urgent, expiry_date_str))
            conn.commit()
            last_request_id = c.lastrowid
            
            if urgent == 1:
                requester_info = {
                    'request_id': last_request_id,
                    'requester_user_id': requester_user_id,
                    'requester_name': requester_name,
                    'blood_group': blood_group,
                    'organ': organ_for_db,
                    'organ_other': organ_other_for_db,
                    'requester_address': requester_address,
                    'requester_phone': requester_phone
                }
                if notify_all_donors_of_urgent_request(requester_info):
                    flash("Your urgent request has been posted successfully and donors have been notified via email!", "success")
                else:
                    flash("Your urgent request has been posted, but there was an issue notifying all donors via email.", "warning")
            else:
                flash("Your request has been posted successfully! Donors will be able to see it.", "success")
            
            return redirect(url_for('donor_dashboard'))
        except Exception as e:
            flash(f"An error occurred while posting your request: {str(e)}", "error")
            print(f"Error posting request: {e}")
            form_data.update({
                'request_type': request_type,
                'organ': request.form.get('organ', '') if request_type == 'organ' else '',
                'organ_other': request.form.get('other_organ', '') if request_type == 'organ' and request.form.get('organ') == 'Other' else '',
                'blood_group': blood_group,
                'requester_address': requester_address,
                'requester_phone': requester_phone,
                'urgent': str(urgent)
            })
            return render_template('post_request.html', form_data=form_data)
        finally:
            if conn:
                conn.close()

    return render_template('post_request.html', form_data=form_data)


@app.route("/send_interest_message", methods=["POST"])
def send_interest_message():
    if 'user_id' not in session:
        flash("Please login to send interest message.", "error")
        return redirect(url_for('login'))

    sender_user_id = session['user_id']
    donor_name = session['user_name']
    donor_email = session['user_email']
    donor_phone = session['user_phone']

    request_id = request.form.get('request_id')
    requester_user_id_for_message = request.form.get('requester_user_id_for_message') 

    if not request_id:
        flash("Invalid request to send message.", "error")
        return redirect(url_for('donor_dashboard'))

    conn = None
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()

        c.execute("""
            SELECT
                r.requester_user_id,
                r.organ,
                r.organ_other,
                r.blood_group,
                u.name,
                u.email,
                u.phone,
                r.requester_address
            FROM requests r
            JOIN users u ON r.requester_user_id = u.id
            WHERE r.id = ?
        """, (request_id,))
        requester_data = c.fetchone()

        if not requester_data:
            flash("Requester details not found for this request.", "error")
            return redirect(url_for('donor_dashboard')) 

        requester_user_id_actual = requester_data[0]
        needed_organ = requester_data[1]
        needed_organ_other = requester_data[2]
        needed_blood_group = requester_data[3]
        requester_name = requester_data[4]
        requester_email = requester_data[5]
        requester_phone_contact = requester_data[6]
        requester_address_contact = requester_data[7]

        message_content = (
            f"Hello {requester_name},\n\n"
            f"I'm {donor_name}, a registered donor on JeevanLink, and I'm interested in your request for '{needed_organ if needed_organ != 'Other' else needed_organ_other}' "
            f"(Blood Group: {needed_blood_group}).\n\n"
            f"You can contact me at:\n"
            f"  Email: {donor_email}\n"
            f"  Mobile: {donor_phone}\n\n"
            f"Looking forward to hearing from you.\n\n"
            f"Thanks,\n{donor_name}"
        )

        c.execute('''
            INSERT INTO messages (request_id, sender_user_id, message_content)
            VALUES (?, ?, ?)
        ''', (request_id, sender_user_id, message_content))
        conn.commit()

        flash(f"Your interest message has been sent to {requester_name}!", "success")
        
        if requester_user_id_for_message and str(requester_user_id_for_message) == str(requester_user_id_actual):
            return redirect(url_for('request_details', request_id=request_id))
        else:
            return redirect(url_for('donor_dashboard'))

    except Exception as e:
        flash(f"An error occurred while sending your message: {str(e)}", "error")
        print(f"Error sending interest message: {e}")
        if requester_user_id_for_message:
            return redirect(url_for('request_details', request_id=request_id))
        else:
            return redirect(url_for('donor_dashboard'))
    finally:
        if conn:
            conn.close()


@app.route('/donor_dashboard')
def donor_dashboard():
    if 'user_id' not in session:
        flash("Please login first.")
        return redirect(url_for('login'))

    conn = None
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        current_datetime_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        c.execute(f"""
            SELECT
                r.id,
                u.name,
                r.blood_group,
                r.organ,
                r.organ_other,
                r.requester_address,
                r.requester_phone,
                r.urgent,
                r.requested_at,
                r.requester_user_id
            FROM requests r
            JOIN users u ON r.requester_user_id = u.id
            WHERE r.expiry_date > '{current_datetime_str}' OR r.expiry_date IS NULL
            ORDER BY r.urgent DESC, r.requested_at DESC
        """)
        requests = c.fetchall()
    except Exception as e:
        flash(f"Error loading donor dashboard: {str(e)}", "error")
        print(f"Error in donor_dashboard: {e}")
        requests = [] # Ensure requests is an empty list on error
    finally:
        if conn:
            conn.close()
    return render_template('donor_dashboard.html', requests=requests)


@app.route('/my_requests')
def my_requests():
    if 'user_id' not in session:
        flash("Please login to view your requests and messages.", "error")
        return redirect(url_for('login'))

    current_user_id = session['user_id']
    user_requests = []
    conn = None
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()

        c.execute("""
            SELECT
                r.id,
                r.blood_group,
                r.organ,
                r.organ_other,
                r.requester_address,
                r.requester_phone,
                r.urgent,
                r.requested_at,
                r.expiry_date
            FROM requests r
            WHERE r.requester_user_id = ?
            ORDER BY r.requested_at DESC
        """, (current_user_id,))
        requests_data = c.fetchall()

        for req in requests_data:
            request_id = req[0]
            is_expired = False
            if req[8]:
                expiry_dt = datetime.strptime(req[8], '%Y-%m-%d %H:%M:%S')
                if datetime.now() > expiry_dt:
                    is_expired = True

            c.execute("""
                SELECT
                    m.message_content,
                    m.timestamp,
                    s.name,
                    s.email,
                    s.phone
                FROM messages m
                JOIN users s ON m.sender_user_id = s.id
                WHERE m.request_id = ?
                ORDER BY m.timestamp DESC
            """, (request_id,))
            messages = c.fetchall()
            
            user_requests.append({
                'id': req[0],
                'blood_group': req[1],
                'organ': req[2],
                'organ_other': req[3],
                'requester_address': req[4],
                'requester_phone': req[5],
                'urgent': req[6],
                'requested_at': req[7],
                'expiry_date': req[8],
                'is_expired': is_expired,
                'messages': messages
            })
        
    except Exception as e:
        flash(f"Error loading your requests: {str(e)}", "error")
        print(f"Error in my_requests: {e}")
    finally:
        if conn:
            conn.close()

    return render_template('my_requests.html', user_requests=user_requests)


@app.route('/delete_request', methods=['POST'])
def delete_request():
    if 'user_id' not in session:
        flash("Please login to delete requests.", "error")
        return redirect(url_for('login'))

    request_id_to_delete = request.form.get('request_id')
    current_user_id = session['user_id']
    conn = None
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        
        c.execute("SELECT requester_user_id FROM requests WHERE id = ?", (request_id_to_delete,))
        requester_id_from_db = c.fetchone()

        if requester_id_from_db and requester_id_from_db[0] == current_user_id:
            c.execute("DELETE FROM messages WHERE request_id = ?", (request_id_to_delete,))
            c.execute("DELETE FROM requests WHERE id = ?", (request_id_to_delete,))
            conn.commit()
            flash("Request successfully deleted!", "success")
        else:
            flash("You are not authorized to delete this request.", "error")
        
    except Exception as e:
        flash(f"An error occurred while deleting the request: {str(e)}", "error")
        print(f"Error deleting request: {e}")
    finally:
        if conn:
            conn.close()

    return redirect(url_for('my_requests'))


@app.route("/send_interest", methods=["POST"])
def send_interest():
    if 'user_id' not in session:
        flash("Please login to send interest email.", "error")
        return redirect(url_for('login'))

    donor_email = request.form.get('donor_email')
    donor_name = request.form.get('donor_name')
    requester_name = session.get('user_name', 'Someone')
    requester_email = session.get('user_email', '')
    requester_phone = session.get('user_phone', '')


    if not donor_email or not donor_name:
        flash("Missing information to send email.", "error")
        return redirect(url_for('find_match'))

    sender = os.getenv('EMAIL_USER')
    password = os.getenv('EMAIL_PASS')

    if not sender or not password:
        flash("Email configuration is missing. Please check your .env file.", "error")
        return redirect(url_for('find_match'))

    subject = f"JeevanLink: {requester_name} is interested in your organ donation!"
    body = (
        f"Hello {donor_name},\n\n"
        f"{requester_name} (Email: {requester_email}, Mobile: {requester_phone}) "
        f"is interested in your organ/blood donation listed on JeevanLink.\n\n"
        f"Please contact them directly to discuss further.\n\n"
        f"Thanks,\nJeevanLink Team"
    )

    # FIX 1: Define 'msg' before sending it
    msg = MIMEText(body) # <--- ADDED THIS LINE
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = donor_email

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(sender, password)
            smtp.send_message(msg)
        flash("Interest email sent successfully!", "success")
    except Exception as e:
        print("Email failed:", e)
        flash("Failed to send interest email.", "error")

    return redirect(url_for('find_match'))

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        flash("Please login to view your profile.", "error")
        return redirect(url_for('login'))

    current_user_id = session['user_id']
    user_info = get_user_info(current_user_id) # Fetch user's own details

    expressed_interests = []
    user_requests = [] # To store requests posted by this user
    conn = None
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()

        # Fetch requests that the current user (as a donor) has sent messages for
        c.execute("""
            SELECT
                r.id,
                u_req.name, -- Requester's name
                r.organ,
                r.organ_other,
                r.blood_group,
                r.requester_address,
                r.requester_phone,
                r.urgent,
                r.requested_at,
                r.expiry_date,
                m.timestamp AS interest_timestamp, -- When interest was sent
                u_sender.name AS donor_name, -- Sender's name (current user)
                u_sender.email AS donor_email,
                u_sender.phone AS donor_phone
            FROM messages m
            JOIN requests r ON m.request_id = r.id
            JOIN users u_req ON r.requester_user_id = u_req.id
            JOIN users u_sender ON m.sender_user_id = u_sender.id
            WHERE m.sender_user_id = ?
            ORDER BY m.timestamp DESC
        """, (current_user_id,))
        interests_data = c.fetchall()

        for interest in interests_data:
            is_expired = False
            if interest[9]: # expiry_date
                expiry_dt = datetime.strptime(interest[9], '%Y-%m-%d %H:%M:%S')
                if datetime.now() > expiry_dt:
                    is_expired = True

            expressed_interests.append({
                'request_id': interest[0],
                'requester_name': interest[1],
                'organ': interest[2],
                'organ_other': interest[3],
                'blood_group': interest[4],
                'requester_address': interest[5],
                'requester_phone': interest[6],
                'urgent': interest[7],
                'requested_at': interest[8],
                'expiry_date': interest[9],
                'is_expired': is_expired,
                'interest_timestamp': interest[10],
                'donor_name': interest[11],
                'donor_email': interest[12],
                'donor_phone': interest[13]
            })

        # Fetch requests posted by the current user
        c.execute("""
            SELECT
                r.id,
                r.blood_group,
                r.organ,
                r.organ_other,
                r.requester_address,
                r.requester_phone,
                r.urgent,
                r.requested_at,
                r.expiry_date
            FROM requests r
            WHERE r.requester_user_id = ?
            ORDER BY r.requested_at DESC
        """, (current_user_id,))
        requests_data = c.fetchall()

        for req in requests_data:
            request_id = req[0]
            is_expired = False
            if req[8]:
                expiry_dt = datetime.strptime(req[8], '%Y-%m-%d %H:%M:%S')
                if datetime.now() > expiry_dt:
                    is_expired = True

            # Fetch messages for each of the user's requests
            c.execute("""
                SELECT
                    m.message_content,
                    m.timestamp,
                    s.name, -- Sender's name (donor)
                    s.email, -- Sender's email (donor)
                    s.phone  -- Sender's phone (donor)
                FROM messages m
                JOIN users s ON m.sender_user_id = s.id
                WHERE m.request_id = ?
                ORDER BY m.timestamp DESC
            """, (request_id,))
            messages = c.fetchall()
            
            user_requests.append({
                'id': req[0],
                'blood_group': req[1],
                'organ': req[2],
                'organ_other': req[3],
                'requester_address': req[4],
                'requester_phone': req[5],
                'urgent': req[6],
                'requested_at': req[7],
                'expiry_date': req[8],
                'is_expired': is_expired,
                'messages': messages
            })
        
    except Exception as e:
        flash(f"Error loading your requests: {str(e)}", "error")
        print(f"Error in my_requests: {e}")
    finally:
        if conn:
            conn.close()

    return render_template('profile.html',
                           user_info=user_info,
                           expressed_interests=expressed_interests,
                           user_requests=user_requests)

@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'user_id' not in session:
        flash("Please login to edit your profile.", "error")
        return redirect(url_for('login'))

    current_user_id = session['user_id']
    user_info = get_user_info(current_user_id)

    if not user_info:
        flash("User not found.", "error")
        return redirect(url_for('profile'))

    if request.method == 'POST':
        new_name = request.form.get('name')
        new_phone = request.form.get('phone')
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_new_password = request.form.get('confirm_new_password')

        conn = None
        try:
            conn = sqlite3.connect(DB_NAME)
            c = conn.cursor()

            # Update name and phone
            updated = False
            if new_name and new_name != user_info['name']:
                c.execute("UPDATE users SET name = ? WHERE id = ?", (new_name, current_user_id))
                session['user_name'] = new_name # Update session
                updated = True
            if new_phone and new_phone != user_info['phone']:
                c.execute("UPDATE users SET phone = ? WHERE id = ?", (new_phone, current_user_id))
                session['user_phone'] = new_phone # Update session
                updated = True

            # Handle password change
            if current_password or new_password or confirm_new_password:
                # Fetch current user's password hash
                c.execute("SELECT password FROM users WHERE id = ?", (current_user_id,))
                stored_password_hash = c.fetchone()[0]

                if not check_password_hash(stored_password_hash, current_password):
                    flash("Current password incorrect.", "error")
                    return render_template('edit_profile.html', user_info=user_info)

                if not new_password:
                    flash("New password cannot be empty if you're changing it.", "error")
                    return render_template('edit_profile.html', user_info=user_info)
                
                if new_password != confirm_new_password:
                    flash("New password and confirmation do not match.", "error")
                    return render_template('edit_profile.html', user_info=user_info)

                hashed_new_pw = generate_password_hash(new_password)
                c.execute("UPDATE users SET password = ? WHERE id = ?", (hashed_new_pw, current_user_id))
                flash("Password updated successfully!", "success")
                updated = True # Mark as updated for flash message
            
            conn.commit()

            if updated:
                flash("Profile updated successfully!", "success")
            else:
                flash("No changes were made to the profile.", "info")

            # Refresh user_info after updates for rendering
            user_info = get_user_info(current_user_id) # Re-fetch updated info
            return redirect(url_for('profile'))

        except Exception as e:
            flash(f"An error occurred while updating profile: {str(e)}", "error")
            print(f"Error updating profile: {e}")
            # Ensure user_info is passed back on error
            return render_template('edit_profile.html', user_info=user_info)
        finally:
            if conn:
                conn.close()

    return render_template('edit_profile.html', user_info=user_info)


@app.route('/request_details/<int:request_id>')
def request_details(request_id):
    if 'user_id' not in session:
        flash("Please login to view request details.", "error")
        return redirect(url_for('login'))

    request_info = None
    requester_info = None
    conn = None
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()

        # Fetch specific request details
        c.execute(f"""
            SELECT
                r.id,
                r.blood_group,
                r.organ,
                r.organ_other,
                r.requester_address,
                r.requester_phone,
                r.urgent,
                r.requested_at,
                r.expiry_date,
                r.requester_user_id,
                u.name AS requester_name,
                u.email AS requester_email,
                u.phone AS requester_phone_from_user
            FROM requests r
            JOIN users u ON r.requester_user_id = u.id
            WHERE r.id = ?
        """, (request_id,))
        req_data = c.fetchone()

        if req_data:
            # Check if request is expired
            is_expired = False
            if req_data[8]:
                expiry_dt = datetime.strptime(req_data[8], '%Y-%m-%d %H:%M:%S')
                if datetime.now() > expiry_dt:
                    is_expired = True

            request_info = {
                'id': req_data[0],
                'blood_group': req_data[1], # FIX 2: Changed 'req[1]' to 'req_data[1]'
                'organ': req_data[2],
                'organ_other': req_data[3],
                'requester_address': req_data[4],
                'requester_phone': req_data[5],
                'urgent': req_data[6],
                'requested_at': req_data[7],
                'expiry_date': req_data[8],
                'is_expired': is_expired,
                'requester_user_id': req_data[9]
            }

            requester_info = {
                'id': req_data[9],
                'name': req_data[10],
                'email': req_data[11],
                'phone': req_data[12]
            }
        
    except Exception as e:
        flash(f"Error loading request details: {str(e)}", "error")
        print(f"Error in request_details route: {e}")
    finally:
        if conn:
            conn.close()

    if not request_info:
        flash("Request not found or details are unavailable.", "error")
        return redirect(url_for('donor_dashboard'))

    return render_template('request_details.html',
                           request_info=request_info,
                           requester_info=requester_info)


if __name__ == '__main__':
    init_db()
    app.run(debug=True)
