# PETSTRACK

A web app to track info about ur pets

## Front

## Back

### .env

| name    | description                | required |
| ------- | -------------------------- | -------- |
| JWT_KEY | Secret key for JWT signing | y        |
| DB_URL  | Supabase project URL       | y        |
| DB_KEY  | Supabase anon/public key   | y        |

### Endpoints

All endpoints start with **/api/** prefix, currently there are the followings:

- **login/**:

```JSON
{
  "method":"POST",
  "headers":[{"content-type":"application/json"}]
  "body":{
    "email":"string",
    "pass":"string"
  }
  "response": {
    "status": 200,
    "body": "JWT_TOKEN_STRING"
  }
  "errors":[{"400":"Bad request (content-type)"},{"401","Invalid credentials"},{"422":"Invalid email format / Empty password"},{"500":"Unexpected error"}]
}
```

**_NOTES_**:

- The password must be sent in plain text
- Returns JWT token as plain text string

---

- **singin/**:

```JSON
{
  "method": "POST",
  "headers": [{ "content-type": "application/json" }],
  "body": {
    "name": "string",
    "email": "string",
    "pass": "string"
  },
  "response": {
    "status": 201,
    "body": "JWT_TOKEN_STRING"
  },
  "errors": [
    { "400": "Bad request (content-type)" },
    { "409": "Email already exists" },
    { "422": "Invalid email format / Empty name or password" },
    { "500": "Failed to create user / Unexpected error" }
  ]
}
```

**_NOTES_**:

- Name is trimmed automatically

- Password is hashed with bcrypt before storage

- Returns JWT token as plain text string

- Email is converted to lowercase before storage

---

- **pets/**:

```JSON
{
  "method": "POST",
  "headers": [
    { "content-type": "application/json" },
    { "authorization": "Bearer JWT_TOKEN" }
  ],
  "body": {
    "name": "string"
  },
  "response": {
    "status": 201,
    "body": ""
  },
  "errors": [
    { "400": "Bad request / Missing or invalid Authorization header / Invalid JWT" },
    { "422": "Missing required fields" },
    { "500": "Failed to create pet / Failed to create ownership relation / Unexpected error" }
  ]
}
```

**_NOTES_**:

- Creates a new pet and automatically assigns ownership to the authenticated user

- Requires valid JWT token in Authorization header

- Creates relationship in ownership table linking user and pet

- Returns empty body on success

---

- **health/**:

```JSON
{
  "method": "GET",
  "response": {
    "status": 200,
    "body": "Server: Alive\nDb: Connected to db"
  },
  "errors": [{ "403": "Not found (fallback)" }]
}
```

**_NOTES_**:

- Checks both server status and database connectivity

- Returns plain text with connection status

- Does not require authentication

### Deps

- JWT: npm:jose@5.9.6
- Database: npm:@supabase/supabase-js@2
- Hashing: npm:bcryptjs@2.4.3
