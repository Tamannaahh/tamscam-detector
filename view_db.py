import sqlite3

def check_database():
    conn = sqlite3.connect('instance/tamscam_detector.db')
    cursor = conn.cursor()

    print("\n" + "="*50)
    print(" 1. ACCOUNTS TABLE RECORDS")
    print("="*50)
    cursor.execute("SELECT id, username, email, role, created_at FROM accounts")
    users = cursor.fetchall()
    for u in users:
        print(f"ID: {u[0]} | User: {u[1]:<12} | Email: {u[2]:<30} | Role: {u[3]:<6} | Joined: {u[4]}")

    print("\n" + "="*50)
    print(" 2. SCAN LOGS TABLE RECORDS")
    print("="*50)
    cursor.execute("SELECT id, user_id, job_title, scam_score, verdict, created_at FROM scan_logs")
    scans = cursor.fetchall()
    if not scans:
        print("No scan history logged yet.")
    for s in scans:
        print(f"Scan ID: {s[0]} | User ID: {s[1]} | Title: {s[2]:<25} | Score: {s[3]}/100 | Verdict: {s[4]:<10} | Date: {s[5]}")
    print("="*50 + "\n")

    conn.close()

if __name__ == "__main__":
    check_database()