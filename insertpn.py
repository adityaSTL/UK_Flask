from app2 import db  # Assuming app2.py is where your Flask app and db are defined
from app2 import PnRaw,app  # Replace with the correct import path for your PnRaw model
from datetime import datetime


def convert_date(date_str):
    try:
        return datetime.strptime(date_str, '%d/%m/%Y').strftime('%Y-%m-%d')
    except ValueError:
        return None  # Handle invalid date formats

def convert_currency(value_str):
    if value_str:
        try:
            # Remove currency symbols and commas, then convert to float
            return float(value_str.replace('£', '').replace(',', ''))
        except ValueError:
            return None
    return None


def insert_data():
    data = [
        ('12480', 'STL_BURNTWOOD_PN_106', 'AFP576', '25/06/2024', '6/21/2024', 'PO-014511', 'West Midlands', '140760', 'BURNTWOOD ATE', 'stl_wm', 'L2', '242887', '117113', '7', 'TRR001', 'Feed Rod & Rope (From Telephone Exchange To L0/L1/L2/L3)', 'Per 100M', '£108.53', '1', '£108.53', '0', 'OK', None, '1', '£108.53', '242887117113TRR001', '1.00', '£108.53', 'Y', 'PO-014511', None),
        ('12481', 'STL_BURNTWOOD_PN_106', 'AFP576', '25/06/2024', '6/21/2024', 'PO-014509', 'West Midlands', '140760', 'BURNTWOOD ATE', 'stl_wm', 'L2', '242080', '738338', '7', 'TRR001', 'Feed Rod & Rope (From Telephone Exchange To L0/L1/L2/L3)', 'Per 100M', '£108.53', '2', '£217.06', '0', 'OK', None, '2', '£217.06', '242080738338TRR001', '2.00', '£108.53', 'N', 'PO-014509', None),
        ('12482', 'STL_BURNTWOOD_PN_106', 'AFP576', '25/06/2024', '6/21/2024', 'PO-014509', 'West Midlands', '140760', 'BURNTWOOD ATE', 'stl_wm', 'L2', '242080', '738551', '7', 'H&D121', 'BLUE POLYPROP 6mm x 500m ROPE', '0', '£4.40', '1', '£4.40', '0', 'OK', None, '1', '£4.40', '242080738551H&D121', '1.00', '£4.40', 'N', 'PO-014509', None),
        ('12483', 'STL_BURNTWOOD_PN_106', 'AFP576', '25/06/2024', '6/21/2024', 'PO-014508', 'West Midlands', '140760', 'BURNTWOOD ATE', 'stl_wm', 'L2', '242685', '69902', '7', 'H&D121', 'BLUE POLYPROP 6mm x 500m ROPE', '0', '£4.40', '4', '£17.60', '0', 'OK', None, '4', '£17.60', '24268569902H&D121', '4.00', '£4.40', 'N', 'PO-014508', None)
    ]

    # Convert date formats
    converted_data = []
    for row in data:
        converted_row = list(row)
        converted_row[3] = convert_date(row[3])  # pn_date_issued_to_contractor
        converted_row[4] = convert_date(row[4])  # date_of_application
        converted_row[17] = convert_currency(row[17])  # price
        converted_row[19] = convert_currency(row[19])  # total
        converted_row[24] = convert_currency(row[24])  # approved_total
        converted_row[26] = convert_currency(row[26])  # qgis_rate
        converted_row[27] = convert_currency(row[27])
        # Print out to debug
        print(f"Converted row: {converted_row}")
        converted_data.append(tuple(converted_row))
    
    with app.app_context():
        try:
            for row in converted_data:
                record = PnRaw(
                    unique_id=row[0],
                    payment_notice_id=row[1],
                    contractor_afp_ref=row[2],
                    pn_date_issued_to_contractor=row[3],
                    date_of_application=row[4],
                    purchase_order_id=row[5],
                    region=row[6],
                    exchange_id=row[7],
                    town=row[8],
                    contractor=row[9],
                    polygon_type=row[10],
                    polygon_id=row[11],
                    feature_id=row[12],
                    build_status=row[13],
                    code=row[14],
                    item=row[15],
                    unit=row[16],
                    price=row[17],
                    quantity=row[18],
                    total=row[19],
                    comments=row[20],
                    afp_claim_ok_nok=row[21],
                    nok_reason_code=row[22],
                    approved_quantity=row[23],
                    approved_total=row[24],
                    concate=row[25],
                    qgis_quant=row[26],
                    qgis_rate=row[27],
                    qgis_url=row[28],
                    po_check=row[29],
                    comment=row[30]
                )
                db.session.add(record)

            db.session.commit()
            print("Rows inserted successfully.")

        except Exception as e:
            db.session.rollback()
            print(f"An error occurred: {e}")

if __name__ == "__main__":
    insert_data()