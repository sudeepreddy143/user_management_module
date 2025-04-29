# User Management System

A comprehensive solution for user management with enhanced validation, security features, and performance optimizations.

## Overview

This repository contains enhancements, test coverage, and bug fixes for a user management system. The project focuses on:

- Improving data validation
- Enhancing security measures
- Optimizing performance
- Resolving critical issues

## Resolved QA Issues

| Issue | Description | Resources |
|-------|-------------|-----------|
| **Input Validation** | Enhanced validation for email formats and password complexity | [Code](https://github.com/sudeepreddy143/user_management_module/tree/main/app/schemas/user_schemas.py) • [Issue #1](https://github.com/sudeepreddy143/user_management_module/issues/1) |
| **JWT Security** | Fixed token validation for proper expiration and signature checks | [Code](https://github.com/sudeepreddy143/user_management_module/tree/main/app/services/jwt_service.py) • [Issue #2](https://github.com/sudeepreddy143/user_management_module/issues/2) |
| **Input Sanitization** | Implemented sanitization to prevent injection attacks | [Code](https://github.com/sudeepreddy143/user_management_module/tree/main/app/schemas/user_schemas.py) • [Issue #3](https://github.com/sudeepreddy143/user_management_module/issues/3) |
| **Database Performance** | Added indexes for frequently queried fields | [Code](https://github.com/sudeepreddy143/user_management_module/tree/main/app/models/user_model.py) • [Issue #4](https://github.com/sudeepreddy143/user_management_module/issues/4) |
| **Email Service Robustness** | Added proper exception handling for email operations | [Code](https://github.com/sudeepreddy143/user_management_module/tree/main/app/services/email_service.py) • [Issue #5](https://github.com/sudeepreddy143/user_management_module/issues/5) |

## New Features

### User Search and Filtering
Advanced search capabilities allowing administrators to efficiently locate and manage users based on multiple criteria.

### User Profile Management
Enhanced profile management system enabling:
- Users to update their profile information
- Managers to modify user roles
- Administrators to upgrade accounts to professional status

## Testing Framework

Our comprehensive test suite uses PyTest with the `pytest-asyncio` plugin for asynchronous testing. [View test code](https://github.com/sudeepreddy143/user_management_module/tree/main/tests/test_api/test_users_api.py)

### Authentication Tests
- **Account Locking**: Verifies account lockout after multiple failed login attempts
- **User Login**: Tests various login scenarios with valid and invalid credentials

### Registration Tests
- **Valid Registration**: Confirms successful user creation with proper data
- **Data Validation**: Ensures input validation functions correctly

### Verification Tests
- **Token Validation**: Tests verification flows with both valid and invalid tokens
- **Account Status**: Verifies account status changes after verification

### Password Management
- **Reset Flow**: Tests the complete password reset workflow
- **Security Checks**: Validates token-based password reset mechanisms

### Profile Management
- **Self-Updates**: Tests user's ability to modify their own information
- **Administrative Controls**: Verifies role-based access for profile modifications
- **Session Management**: Tests user logout and session invalidation

## DockerHub Link

You can view the user mangement module tags on DockerHub here: [View DockerHub Repository](https://hub.docker.com/repository/docker/sudeeppanyam/user_management_module/general)



