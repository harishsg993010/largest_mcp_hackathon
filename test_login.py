import requests
import json

def test_login():
    """Test login functionality directly against the backend API"""
    print("Testing login functionality...")
    
    # API endpoint
    url = "http://localhost:5000/api/auth/login/"
    
    # Login credentials
    data = {
        "username": "admin",
        "password": "admin"
    }
    
    # Headers
    headers = {
        "Content-Type": "application/json"
    }
    
    try:
        # First, test the health endpoint
        health_response = requests.get("http://localhost:5000/api/auth/health/")
        print(f"Health check status: {health_response.status_code}")
        print(f"Health check response: {health_response.json()}")
        
        # Now try the login
        print(f"\nSending login request to: {url}")
        print(f"With data: {data}")
        
        response = requests.post(url, data=json.dumps(data), headers=headers)
        
        print(f"Login status code: {response.status_code}")
        
        if response.status_code == 200:
            print("Login successful!")
            print(f"Response: {response.json()}")
            return True
        else:
            print(f"Login failed with status code: {response.status_code}")
            print(f"Response: {response.text}")
            return False
    except Exception as e:
        print(f"Error during login test: {str(e)}")
        return False

if __name__ == "__main__":
    test_login()
