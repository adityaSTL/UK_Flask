import pandas as pd
from sqlalchemy import create_engine

# Replace with your MySQL credentials
# db_username = 'your_username'
# db_password = 'your_password'
# db_host = 'localhost'
# db_name = 'eod'

# Create a connection to the database
engine = create_engine("mysql+mysqldb://root:Admin%40123@10.100.130.76/eod")

# SQL query to fetch the first 5 rows from the eod_dump table
query = "SELECT * FROM eod_dump LIMIT 5"

# Load data into a pandas DataFrame
df = pd.read_sql(query, engine)

# Convert the DataFrame to a CSV file
csv_file_path = 'eod_dump_first_5_rows.csv'
df.to_csv(csv_file_path, index=False)

print(f"CSV file created: {csv_file_path}")
