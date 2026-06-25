import os
import getpass
import mysql.connector

def main():
    password = os.environ.get("DB_PASSWORD") or getpass.getpass("MySQL root password: ")
    host = os.environ.get("DB_HOST", "127.0.0.1")
    port = int(os.environ.get("DB_PORT", 3306))

    conn = mysql.connector.connect(host=host, port=port, user="root", password=password)
    cursor = conn.cursor()

    sql_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "database.sql")
    with open(sql_path, "r", encoding="utf-8") as f:
        sql_script = f.read()

   
    statement_count = 0
    for result in cursor.execute(sql_script, multi=True):
        statement_count += 1
        if result.with_rows:
            print(f"  -> {result.fetchall()}")

    conn.commit()
    cursor.close()
    conn.close()
    print(f"\nSchema loaded successfully ({statement_count} statements executed).")

if __name__ == "__main__":
    main()
