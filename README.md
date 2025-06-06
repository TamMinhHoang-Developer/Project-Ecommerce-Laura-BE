# Overview
This is a simple API project built using Node.js, Express, and Supabase.

# Features
- User authentication using Supabase
- API endpoints for getting token and user information

# Members
- Hoang Minh Tam
- Le Thanh Tuan

# Prerequisites
- Node.js
- Express
- Supabase

# Installation
1. Clone the repository
2. Install dependencies: `npm install`
3. Set up Supabase:
   - Create a new Supabase project
   - Create a new API key with full access
   - Set the `SUPABASE_URL` and `SUPABASE_KEY` environment variables
4. Run the server: `npm start`

# API Documentation
## 1. Authentication
| Header  | Details |
| ------------- | ------------- |
| API Method    | ```POST```    |
| Endpoint      | ```/api/auth/login```|
| Purpose       | **API Login User**   |
| Request Body  | ```{ "email": "email", "password": "password", "rememberMe": false }``` |
| Response Body | ```{ "message": "Login successful.", "accessToken": "eyJhb..." }``` |

## 2. API Get Token
- Endpoint: /api/auth/token

## 3. API Get User
- Endpoint: /api/auth/user

# Update at 06/06/2025