# GophKeeper Server
## Overview
GophKeeper is a secure server application for storing and managing sensitive user data like passwords, credentials, and other secrets. It provides:

- User authentication (registration/login)
- Secure secret storage
- Versioned secret management

## gRPC Endpoints
### Registration
`/Auth/Register`

Register a new user

**Request:**

```json
{
  "login": "username",
  "password": "securepassword123"
}
```
Response (Success):

```json
{
  "token": "jwt.token.string"
}
```
**Response (Error):**

`400 Bad Request` - Invalid input

`409 Conflict` - Login already exists

`500 Internal Server Error` - Server error

### Login
`/Auth/Login`

Authenticate an existing user

**Request:**

```json
{
  "login": "username",
  "password": "securepassword123"
}
```
**Response:**

```json
{
  "token": "jwt.token.string"
}
```

## Secrets Management

### Create secret

`/SecretService/CreateSecret`

Create a new secret.

**Metadata:**

```json
{
    "Authorization": "Bearer <jwt_token>"
}
```

**Request:**

```json
{
  "name": "mysecret",
  "type": "CREDENTIALS",
  "data": "base64_encoded_data",
  "metadata": "{}"
}
```

**Response:**

```json
{}
```

### Create a secret stream
`/SecretService/GetSecretStreamByVersion`

Creates a new large file/text secret.

**Metadata:**

```json
{
    "Authorization": "Bearer <jwt_token>"
}
```

**Request:**

1. First chunk:
```json
{
    "info": {
        "metadata": "{}",
        "name": "secret_name",
        "type": "BINARY"
    }
}
```
2. Next chunks:
```json
{
    "data": "base64_encoded_data"
}
```

**Response:**

```json
{}
```

### List secrest
`/SecretService/ListSecrets`

List all secret names for user

**Metadata:**

```json
{
    "Authorization": "Bearer <jwt_token>"
}
```

**Request:**

```json
{}
```

**Response:**

```json
{
    "Data": [
        "secret_name_1",
        "secret_name_2",
        "secret_name_3",
    ]
}
```

### Get latest secret version
`/SecretService/GetLatestSecret`

Gets latest version of a secret

**Metadata:**

```json
{
    "Authorization": "Bearer <jwt_token>"
}
```

**Request:**

```json
{
    "name": "secret_name"
}
```

**Response:**

```json
{
    "info": {
        "name": "secret_name",
        "type": "",
        "metadata": "",
        "version": 4,
        "created_at": "",
    },
    "data": "base64_encoded_data"
}
```

### Get secret version
`/SecretService/GetLatestSecret`

Gets a specific version of a secret

**Metadata:**

```json
{
    "Authorization": "Bearer <jwt_token>"
}
```

**Request:**

```json
{
    "name": "secret_name",
    "version": 2
}
```

**Response:**

```json
{
    "info": {
        "name": "secret_name",
        "type": "",
        "metadata": "",
        "version": 2,
        "created_at": "",
    },
    "data": "base64_encoded_data"
}
```

### Get latest secret stream
`/SecretService/GetLatestSecretStream`

Gets the latest version of a large file/text secret

**Metadata:**

```json
{
    "Authorization": "Bearer <jwt_token>"
}
```

**Request:**

```json
{
    "name": "secret_name"
}
```

**Response:**

1. First chunk:
```json
{
    "info": {
        "metadata": "{}",
        "name": "secret_name",
        "type": "BINARY"
    }
}
```
2. Next chunks:
```json
{
    "data": "base64_encoded_data"
}
```

### Get secret stream by version
`/SecretService/GetSecretStreamByVersion`

Gets a specific version of a large file/text secret.

**Metadata:**

```json
{
    "Authorization": "Bearer <jwt_token>"
}
```

**Request:**

```json
{
    "name": "secret_name",
    "version": 2
}
```

**Response:**

1. First chunk:
```json
{
    "info": {
        "metadata": "{}",
        "name": "secret_name",
        "type": "BINARY"
    }
}
```
2. Next chunks:
```json
{
    "data": "base64_encoded_data"
}
```

### Delete secret
`/SecretService/DeleteSecret`

Deletes al versions of a secret

**Metadata:**

```json
{
    "Authorization": "Bearer <jwt_token>"
}
```

**Request:**

```json
{
    "name": "secret_name"
}
```

**Response:**

```json
{}
```