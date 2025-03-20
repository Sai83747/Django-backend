import time
import MySQLdb
from django.db import connections
from django.db.utils import OperationalError

print("Waiting for database to be ready...")

while True:
    try:
        conn = MySQLdb.connect(
            host="db",
            user="event_user",
            passwd="event_pass",
            db="event_management"
        )
        conn.close()
        print("Database is ready!")
        break
    except OperationalError:
        print("Database is not ready yet. Retrying in 5 seconds...")
        time.sleep(5)
