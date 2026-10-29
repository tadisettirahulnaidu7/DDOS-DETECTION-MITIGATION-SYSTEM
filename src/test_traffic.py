import requests
import time

url = "http://127.0.0.1:8000/api/data"

print("Sending 30 safe local test requests...")

for i in range(30):
    try:
        response = requests.get(url, timeout=3)
        print(response.json())
    except Exception as error:
        print("Error:", error)
    time.sleep(0.1)

print("Test completed.")