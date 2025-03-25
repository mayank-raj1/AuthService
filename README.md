# Testing in postman

## 1. Register a New User

**Request:**
- Method: POST
- URL: `http://localhost:8080/api/auth/register`
- Headers: `Content-Type: application/json`
- Body:
```json
{
  "firstName": "Test",
  "lastName": "User",
  "email": "testuser@example.com",
  "password": "Test@123"
}
```

**Expected Response:**
- Status: 200 OK
- Body containing JWT tokens and user details

## 2. Login

**Request:**
- Method: POST
- URL: `http://localhost:8080/api/auth/login`
- Headers: `Content-Type: application/json`
- Body:
```json
{
  "email": "testuser@example.com",
  "password": "Test@123"
}
```

**Expected Response:**
- Status: 200 OK
- Body with access token, refresh token, and user details

## 3. Get Current User Profile

**Request:**
- Method: GET
- URL: `http://localhost:8080/api/users/me`
- Headers: `Authorization: Bearer {access_token}`

**Expected Response:**
- Status: 200 OK
- User profile information

## 4. Update User Profile

**Request:**
- Method: PUT
- URL: `http://localhost:8080/api/users/me`
- Headers: 
  - `Authorization: Bearer {access_token}`
  - `Content-Type: application/json`
- Body:
```json
{
  "firstName": "Updated",
  "lastName": "Name",
  "profileImageUrl": "https://example.com/profile.jpg"
}
```

**Expected Response:**
- Status: 200 OK
- Updated user details

## 5. Change Password

**Request:**
- Method: POST
- URL: `http://localhost:8080/api/users/me/change-password`
- Headers: 
  - `Authorization: Bearer {access_token}`
  - `Content-Type: application/json`
- Body:
```json
{
  "currentPassword": "Test@123",
  "newPassword": "NewTest@456"
}
```

**Expected Response:**
- Status: 200 OK

## 6. Request Password Reset

**Request:**
- Method: POST
- URL: `http://localhost:8080/api/auth/forgot-password?email=testuser@example.com`
- No body required

**Expected Response:**
- Status: 200 OK

## 7. Refresh Token

**Request:**
- Method: POST
- URL: `http://localhost:8080/api/auth/refresh-token?refreshToken={refresh_token}`
- No body required

**Expected Response:**
- Status: 200 OK
- New tokens

## Postman Collection Setup

You can create a Postman collection with these requests and use environment variables to store and reuse the JWT tokens:

1. Create a new environment with variables:
   - `baseUrl`: `http://localhost:8080/api`
   - `accessToken`: (leave empty initially)
   - `refreshToken`: (leave empty initially)

2. For requests that need the token, use: `Authorization: Bearer {{accessToken}}`

3. Create a test script for login/register to automatically save tokens:
```javascript
// Add to Tests tab for login/register requests
if (pm.response.code === 200) {
    var jsonData = pm.response.json();
    pm.environment.set("accessToken", jsonData.accessToken);
    pm.environment.set("refreshToken", jsonData.refreshToken);
}
```

Would you like me to explain how to test any specific endpoint in more detail?
