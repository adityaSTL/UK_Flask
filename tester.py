import pandas as pd
import mysql.connector
from mysql.connector import errorcode

# Read data from Excel file
df = pd.read_excel('Copy of East Midlands Weekly CVR - ANCHOR WORKBOOK.xlsx')
df['Gang'] = df['Gang'].astype(str).str[:255]  # Truncate to 255 characters

df['Date'] = pd.to_datetime(df['Date'], errors='coerce').dt.strftime('%Y-%m-%d')


# Database connection setup
config = {
    'user': 'root',
    'password': 'Admin@123',
    'host': 'localhost',
    'database': 'eod',
}

try:
    cnx = mysql.connector.connect(**config)
    cursor = cnx.cursor()

    # Prepare SQL query
    add_eod_dump = '''
    INSERT INTO eod_dump (
        Date, TeamLeader, Gang, Work_Type, Item_Mst_ID, Item_Description, Activity,
        WeekNumber, Output_Date_MonthYear, Qty, UOM, Rate, Total, Area, Mst_Item_Rpt_Group1,
        Project_ID, Project_Name, Seed, Comment, Planning_KPI1, Email_ID, User_Name, AuditLog,
        Work_Period, Job_Pack_No, Route, Work_Category, Approved_Status, PMO_Coordinator, QA_remarks,
        Span_length, Taken_To_Revenue
    ) VALUES (
        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
    )
    '''

    # Iterate over DataFrame rows and insert into the database
    for i, row in df.iterrows():
        data = (
            row['Date'], row['TeamLeader'], row['Gang'], row['Work_Type'], row['Item_Mst_ID'], row['Item_Description'],
            row['Activity'], row['WeekNumber'], row['Output_Date_MonthYear'], row['Qty'], row['UOM'],
            row['Rate'], row['Total'], row['Area'], row['Mst_Item_Rpt_Group1'], row['Project_ID'],
            row['Project_Name'], row['Seed'], row['Comment'], row['Planning_KPI1'], row['Email_ID'],
            row['User_Name'], row['AuditLog'], row['Work_Period'], row['Job_Pack_No'], row['Route'],
            row['Work_Category'], row['Approved_Status'], row['PMO_Coordinator'], row['QA_remarks'],
            row['Span_length'], row['Taken_To_Revenue']
        )
        cursor.execute(add_eod_dump, data)

    # Commit the changes
    cnx.commit()

except mysql.connector.Error as err:
    print(f"Error: {err}")
finally:
    # Close the cursor and connection
    cursor.close()
    cnx.close()
