

from email_validator import validate_email, EmailNotValidError
from validate_email_address import validate_email as validate_existence



def validate_email_id(email):
    try:
        # Step 1: Validate the syntax of the email
        valid = validate_email(email)
        normalized_email = valid.email  # Get the normalized form of the email (lowercase, no extra spaces, etc.)

        # # Step 2: Check if the domain and email exist (MX and SMTP check)
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

print(validate_email_id('aditya.gupta1@stl.tech'))
