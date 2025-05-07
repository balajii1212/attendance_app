git init
import os
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_session import Session
import bcrypt
from geopy.distance import geodesic
from datetime import datetime
from pymongo import MongoClient
from bson import ObjectId 

app = Flask(__name__, template_folder="templates")
app.secret_key = 'secure_key'
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

# MongoDB setup
MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017')  # Use environment variable or fallback to localhost
client = MongoClient(MONGO_URI)
db = client['attendance_db']
users = db['users']
settings = db['settings']
attendance_records = db['attendance_records']


@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password').encode('utf-8')
        device_id = request.form.get('device_id')

        user = users.find_one({'username': username})
        if user and bcrypt.checkpw(password, user['password']):
            if not user.get('device_id'):
                users.update_one({'username': username}, {'$set': {'device_id': device_id}})
            elif user['device_id'] != device_id:
                return render_template('login.html', error='Unauthorized device!')

            session['username'] = username
            session['role'] = user['role']
            session.permanent = True

            return redirect(url_for("employee_dashboard") if user['role'] == "employee" else url_for("admin_dashboard"))

        return render_template('login.html', error='Invalid username or password')

    return render_template('login.html')

@app.route('/employee_dashboard', methods=['GET', 'POST'])
def employee_dashboard():
    if 'username' not in session or session['role'] != 'employee':
        return redirect(url_for('login'))  # Redirect unauthorized users
    return render_template('employee.html', name=session['username'])




@app.route('/checkin', methods=['POST'])
def checkin():
    try:
        # Validate session
        print("Session Data:", session)
        if 'username' not in session or session.get('role') != 'employee':
            print("Unauthorized user!")
            return jsonify({"message": "Unauthorized user!"}), 401

        # Validate latitude and longitude
        lat = request.form.get('lat')
        lon = request.form.get('lon')
        print("Latitude received:", lat)
        print("Longitude received:", lon)

        if not lat or not lon:
            print("Location data missing!")
            return jsonify({"message": "Location data missing!"}), 400

        try:
            lat, lon = float(lat), float(lon)
            if not (-90 <= lat <= 90 and -180 <= lon <= 180):
                return jsonify({"message": "Invalid latitude or longitude values."}), 400
        except ValueError:
            return jsonify({"message": "Latitude and longitude must be numeric."}), 400

        # Validate geofence settings
        geofence_settings = settings.find_one({})
        if not geofence_settings or 'geofence' not in geofence_settings:
            print("Geofence settings not configured!")
            return jsonify({"message": "Geofence settings not configured. Please contact admin."}), 500

        geofence = geofence_settings['geofence']
        distance = geodesic((geofence['lat'], geofence['lon']), (lat, lon)).meters

        print(f"Distance from geofence center: {distance:.2f} meters")
        if distance > geofence['radius']:
            print("User out of geofence bounds!")
            return jsonify({"message": f"Out of geofence bounds. Distance: {distance:.2f} meters"}), 403

        # Prepare and insert check-in record
        record = {
            'username': session['username'],
            'checkin_time': datetime.now(),
            'checkin_location': {'lat': lat, 'lon': lon},
            'checkout_time': None,
            'checkout_location': None
        }
        print("Inserting Record:", record)

        attendance_records.insert_one(record)
        print("Record successfully inserted into the database!")
        return jsonify({"message": "Check-in successful!"}), 200

    except Exception as e:
        print(f"Error occurred during check-in: {str(e)}")
        return jsonify({"message": f"An error occurred: {str(e)}"}), 500
       

# Check-Out Route
@app.route('/checkout', methods=['POST'])
def checkout():
    try:
        # Validate session
        if 'username' not in session or session.get('role', '') != 'employee':
            return jsonify({"message": "Unauthorized user!"}), 401

        # Validate latitude and longitude inputs
        lat = request.form.get('lat')
        lon = request.form.get('lon')
        if not lat or not lon:
            return jsonify({"message": "Location data missing!"}), 400

        try:
            lat, lon = float(lat), float(lon)
            if not (-90 <= lat <= 90 and -180 <= lon <= 180):
                return jsonify({"message": "Invalid latitude or longitude values."}), 400
        except ValueError:
            return jsonify({"message": "Latitude and longitude must be numeric."}), 400

        # Retrieve geofence settings
        geofence_settings = settings.find_one({})
        if not geofence_settings or 'geofence' not in geofence_settings:
            return jsonify({"message": "Geofence settings not configured. Contact admin!"}), 500

        geofence = geofence_settings['geofence']
        distance = geodesic((geofence['lat'], geofence['lon']), (lat, lon)).meters

        if distance > geofence['radius']:
            return jsonify({"message": f"Out of geofence bounds. Distance: {distance:.2f} meters"}), 403

        # Locate active check-in record
        checkin_record = attendance_records.find_one({'username': session['username'], 'checkout_time': None})
        if not checkin_record:
            return jsonify({"message": "No active check-in record found!"}), 400

        # Update check-out details in MongoDB
        result = attendance_records.update_one(
            {'_id': checkin_record['_id']},
            {'$set': {
                'checkout_time': datetime.now(),
                'checkout_location': {'lat': lat, 'lon': lon}
            }}
        )

        if result.modified_count == 0:
            return jsonify({"message": "❌ Check-out failed. Try again."}), 500

        return jsonify({"message": "✅ Check-out successful!"}), 200

    except Exception as e:
        return jsonify({"message": f"An error occurred during check-out: {str(e)}"}), 500

       
# Admin Dashboard
@app.route('/admin_dashboard', methods=['GET'])
def admin_dashboard():
    if 'username' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))  # Redirect unauthorized users to login

    try:
        # Fetch all attendance records for display
        attendance_data = list(attendance_records.find({}))
        for record in attendance_data:
            record['_id'] = str(record['_id'])  # Convert ObjectId to string for JSON serialization

        return render_template('admin.html', attendance=attendance_data)
    except Exception as e:
        print("Error Fetching Attendance Data:", str(e))  # Debugging log
        return render_template('admin.html', error="Unable to fetch data")
    
# Add Employee
@app.route('/add_employee', methods=['POST'])
def add_employee():
    username = request.form.get('username')
    password = request.form.get('password')
    if not username or not password:
        return redirect(url_for('admin_dashboard', error="Fields are missing!"))

    if users.find_one({'username': username}):
        return redirect(url_for('admin_dashboard', error="User already exists!"))

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    users.insert_one({'username': username, 'password': hashed_password, 'role': 'employee'})
    return redirect(url_for('admin_dashboard', message="Employee added!"))


@app.route('/update_leave/<request_id>/<status>', methods=['POST'])
def update_leave(request_id, status):
    if 'username' not in session or session.get('role', '') != 'admin':
        return jsonify({"message": "Unauthorized user!"}), 401

    if status not in ['Approved', 'Rejected']:
        return jsonify({"message": "Invalid status!"}), 400

    db.leave_requests.update_one({'_id': ObjectId(request_id)}, {'$set': {'status': status}})
    return jsonify({"message": f"Leave request {status}"}), 200

@app.route('/geofence_alert', methods=['POST'])
def geofence_alert():
    lat = request.form.get('lat')
    lon = request.form.get('lon')

    geofence_settings = db.settings.find_one({})
    geofence = geofence_settings['geofence']
    distance = geodesic((geofence['lat'], geofence['lon']), (float(lat), float(lon))).meters

    active_request = db.leave_requests.find_one({'username': session['username'], 'status': 'Approved'})

    if distance > geofence['radius'] and not active_request:
        db.alerts.insert_one({'username': session['username'], 'alert_type': 'Unauthorized Movement', 'timestamp': datetime.now()})
        return jsonify({"message": "🚨 Unauthorized movement detected! Admin alerted."}), 403

    return jsonify({"message": "✔ Movement within geofence or leave approved."}), 200

@app.route('/request_leave', methods=['POST'])
def request_leave():
    if 'username' not in session or session.get('role', '') != 'employee':
        return jsonify({"message": "Unauthorized user!"}), 401

    reason = request.form.get('reason')
    duration = request.form.get('duration')

    if not reason or not duration:
        return jsonify({"message": "Reason and duration are required!"}), 400

    leave_request = {
        'username': session['username'],
        'reason': reason,
        'duration': int(duration),
        'status': 'Pending',
        'requested_at': datetime.now()
    }
    db.leave_requests.insert_one(leave_request)

    return jsonify({"message": "Leave request submitted! Waiting for admin approval."}), 200

@app.route('/get_leave_requests', methods=['GET'])
def get_leave_requests():
    if 'username' not in session or session.get('role', '') != 'admin':
        return jsonify({"message": "Unauthorized access!"}), 401

    leave_requests = list(db.leave_requests.find({}, {"_id": 1, "username": 1, "reason": 1, "duration": 1, "status": 1}))
    for request in leave_requests:
        request['_id'] = str(request['_id'])  # Convert ObjectId for JSON response

    return jsonify(leave_requests), 200

@app.route('/get_my_leave_status', methods=['GET'])
def get_my_leave_status():
    if 'username' not in session or session.get('role', '') != 'employee':
        return jsonify({"message": "Unauthorized access!"}), 401

    leave_request = db.leave_requests.find_one(
        {'username': session['username']}, 
        sort=[("requested_at", -1)]
    )

    if not leave_request:
        return jsonify({"message": "No leave requests found."}), 404

    return jsonify({
        "status": leave_request.get('status', 'Pending'),
        "reason": leave_request['reason'],
        "duration": leave_request['duration']
    }), 200



@app.route('/get_attendance', methods=['GET'])
def get_attendance():
    records = list(attendance_records.find({}, {'_id': 0}))  # Exclude MongoDB ID
    print("Attendance Data:", records)  # Debugging
    return jsonify(records)


if __name__ == '__main__':
    app.run(debug=True)