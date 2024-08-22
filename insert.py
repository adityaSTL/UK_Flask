import pandas as pd
from sqlalchemy import create_engine
import os


db_user = os.getenv('DB_USER')
db_password = os.getenv('DB_PASSWORD')
db_host = 'localhost'
db_name = os.getenv('DB_NAME')

db_password_encoded = db_password.replace('@', '%40')


# app.config['SQLALCHEMY_DATABASE_URI'] = f"mysql+mysqldb://{db_user}:{db_password}@{db_host}/{db_name}"
# Database connection setup
DATABASE_URI = "mysql+mysqldb://root:Admin%40123@10.100.130.76/eod"
engine = create_engine(DATABASE_URI)

# Read data from Excel file
df = pd.read_excel('Copy of East Midlands Weekly CVR - ANCHOR WORKBOOK.xlsx')

column_mapping = {
    'Date': 'Date',
    'TeamLeader': 'TeamLeader',
    'Gang': 'Gang',
    'Work_Type': 'Work_Type',
    'Item Description': 'Item_Description',
    'Activity': 'Activity',
    'WeekNumber': 'WeekNumber',
    'Output_Date_MonthYear': 'Output_Date_MonthYear',
    'Qty': 'Qty',
    'UOM': 'UOM',
    'Rate': 'Rate',
    'Total': 'Total',
    'Area': 'Area',
    'Mst_Item_Rpt_Group1': 'Mst_Item_Rpt_Group1',
    'Project_ID': 'Project_ID',
    'Project_Name': 'Project_Name',
    'Seed': 'Seed',
    'Comment': 'Comment',
    'Planning_KPI1': 'Planning_KPI1',
    'Email_ID': 'Email_ID',
    'User_Name': 'User_Name',
    'AuditLog': 'AuditLog',
    'Work_Period': 'Work_Period',
    'Job_Pack_No': 'Job_Pack_No',
    'Route': 'Route',
    'Work_Category': 'Work_Category',
    'Approved_Status': 'Approved_Status',
    'PMO_Coordinator': 'PMO_Coordinator',
    'QA_remarks': 'QA_remarks',
    'Span_length': 'Span_length',
    # 'Qty': 'Qty_2',  # Note: Assuming the 2nd Qty column maps to Qty_2
    'Taken To Revenue': 'Taken_To_Revenue'
}

# Rename DataFrame columns to match MySQL table columns
df.rename(columns=column_mapping, inplace=True)

# Insert data into MySQL table
# df.to_sql('eod_dump', con=engine, if_exists='append', index=False)
print(df['Gang'])
print(df)