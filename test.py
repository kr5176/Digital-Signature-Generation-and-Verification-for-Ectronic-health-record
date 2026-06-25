from db_utils import get_connection

try:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT DATABASE();")
    result = cursor.fetchone()
    print(f"Connected to database: {result[0]}")
    cursor.close()
    conn.close()
except Exception as e:
    print("Database connection failed:", e)
