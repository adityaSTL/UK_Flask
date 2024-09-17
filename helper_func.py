import requests
import json
from email_validator import validate_email, EmailNotValidError



def send_welcome_email(to_email,password,name):

    url = 'https://gsbmail.pythonanywhere.com/send_email'
    
    # Headers specifying content type as JSON
    headers = {'Content-Type': 'application/json'}

    subject = 'Welcome to XX Portal'
    body = '''
    Hi {name},

    We welcome you to STL UK project management portal. 
    
    Here are your credential to login the portal

    Portal Link: "http://10.100.130.76:5000"
    Username: {name}
    Email id: {to_email}
    Password: {password}

    Kindly change password after login for security reasons and update your profile. 
    
    Happy Exploring!!
    Team Automation
    automation.gsb@stl.tech
    '''.format(name=name, to_email=to_email, password=password)
    
    # Data to be sent in the POST request
    data = {
        "to_email": to_email,
        "subject": subject,
        "body": body
    }
    
    # Make the POST request
    try:
        response = requests.post(url, headers=headers, data=json.dumps(data))
        
        # Check if the request was successful
        if response.status_code == 200:
            print("Email sent successfully!")
            print("Response:", response.json())
        else:
            print(f"Failed to send email: {response.status_code}")
            print("Error:", response.text)
    
    except Exception as e:
        print(f"An error occurred: {e}")


def validate_email_id(email):
    try:
        # Step 1: Validate the syntax of the email
        valid = validate_email(email)
        normalized_email = valid.email  # Get the normalized form of the email (lowercase, no extra spaces, etc.)

        # Step 2: Check if the domain and email exist (MX and SMTP check)
        # if validate_existence(email, verify=True):
        #     print(f"Email '{normalized_email}' is valid and exists.")
        #     return 1

        if valid:
            print(f"Email '{normalized_email}' has a valid syntax but may not exist (SMTP check not done).")
            return 1
    
    except EmailNotValidError as e:
        # Handle invalid email syntax
        print(f"Invalid email syntax: {str(e)}")
        return 0


def format_date(date):
    if date:
        return date.strftime('%d-%m-%Y')  # Format the date as day-month-year
    return None        