# FastAPI Authentication Service

## Overview

This is a FastAPI-based authentication service that provides functionalities for user registration, email verification, login, and token refresh. The application uses JWT (JSON Web Token) for secure authentication and authorization.

## Features

- **User Registration**: Register a new user and send a verification email.
- **Email Verification**: Verify user email addresses using a verification token.
- **User Login**: Authenticate users and provide access and refresh tokens.
- **Token Refresh**: Refresh access tokens using refresh tokens.

## Endpoints

- **POST /signup** - Register a new user
- **POST /login** - Login an existing user
- **POST /refresh_token** - Refresh access token
- **GET /verify_email/{token}** - Verify user email
- **GET /user/{user_id}** - Get user details
- **PUT /user/{user_id}** - Update or Delete user details
- **GET /users** - List users with optional filters

## How to Use

### Prerequisites

- Python 3.10+
- MongoDB
- Docker (for containerization)
- Kubernetes (for deployment)

### How to Run the App

- cd app
python3 main.py

### How to Run Unit Tests

- cd ..
- pytest

### How to Build Docker Image and Run Containers

- docker-compose build
- docker-compose up


### Environment Variables

Create a `.env` file in the root directory and add the following variables:

```env
SECRET_KEY=your_secret_key
ACCESS_TOKEN_EXPIRES_IN=15 # Access token expiration time in minutes
REFRESH_TOKEN_EXPIRES_IN=1440 # Refresh token expiration time in minutes
MONGO_URI=mongodb://localhost:27017/yourdbname
JWT_ALGORITHM=HS256