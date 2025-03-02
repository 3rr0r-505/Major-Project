# import requests
import datetime

# # Target URL
# url = "http://honeypotter.aws:8080/wp-login.php"

# try:
#     response = requests.get(url, timeout=5)  # No proxy, direct request
#     print(f"Response Status: {response.status_code}")
#     print(response.text[:500])  # Print first 500 characters of response
# except requests.exceptions.RequestException as e:
#     print(f"Request failed: {e}")

dir  = "/index.html"
url = f"http://ip:port{dir}"
print(url)

print(datetime.datetime.now().strftime("%Y-%m-%d::%H:%M:%S"))