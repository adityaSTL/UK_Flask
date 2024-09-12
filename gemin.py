import pandas as pd
import pymysql

# Database connection details (replace with your credentials)
host = 'localhost'
user = 'root'
password = 'Admin@123'
database = 'eod'

# Excel file path
excel_file = 'Copy of East Midlands Weekly CVR - ANCHOR WORKBOOK.xlsx'

# Function to read Excel data into a Pandas DataFrame
def read_excel_data(file_path):
    df = pd.read_excel(file_path)
    return df

def truncate_dataframe(df, max_length=255):
  """Truncates all text columns in a DataFrame to a specified maximum length.

  Args:
    df: The Pandas DataFrame to truncate.
    max_length: The maximum character length for text columns.

  Returns:
    A new DataFrame with truncated text columns.
  """

  df_truncated = df.copy()
  for col in df_truncated.select_dtypes(include=['object']).columns:
    df_truncated[col] = df_truncated[col].astype(str).str[:max_length]
  return df_truncated

# Function to insert data into SQL database
def insert_data(df):
    try:
        conn = pymysql.connect(host=host, user=user, password=password, database=database)
        cursor = conn.cursor()

        # Assuming column names match database table columns
        for index, row in df.iterrows():
            sql = """
            INSERT INTO eod_dump (
                Date, TeamLeader, Gang, Work_Type, Item_Mst_ID, Item_Description, Activity, WeekNumber, 
                Output_Date_MonthYear, Qty, UOM, Rate, Total, Area, Mst_Item_Rpt_Group1, Project_ID, 
                Project_Name, Seed, Comment, Planning_KPI1, Email_ID, User_Name, AuditLog, Work_Period, 
                Job_Pack_No, Route, Work_Category, Approved_Status, PMO_Coordinator, QA_remarks, Span_length, 
                Taken_To_Revenue
            ) 
            VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
            )
            """
            values = (
                row['Date'], row['TeamLeader'], row['Gang'], row['Work_Type'], row['Item_Mst_ID'],
                row['Item_Description'], row['Activity'], row['WeekNumber'], row['Output_Date_MonthYear'],
                row['Qty'], row['UOM'], row['Rate'], row['Total'], row['Area'], row['Mst_Item_Rpt_Group1'], 
                row['Project_ID'], row['Project_Name'], row['Seed'], row['Comment'], row['Planning_KPI1'],
                row['Email_ID'], row['User_Name'], row['AuditLog'], row['Work_Period'], row['Job_Pack_No'],
                row['Route'], row['Work_Category'], row['Approved_Status'], row['PMO_Coordinator'], 
                row['QA_remarks'], row['Span_length'], row['Taken_To_Revenue']
            )
            cursor.execute(sql, values)

        conn.commit()
        print("Data inserted successfully")
    except Exception as e:
        print(f"Error inserting data: {e}")
    finally:
        cursor.close()
        conn.close()

# Main execution
if __name__ == "__main__":
    df = read_excel_data(excel_file)
    df.fillna(value=0, inplace=True)  # Replace NaN with 0
    df=truncate_dataframe(df,255)
    insert_data(df)