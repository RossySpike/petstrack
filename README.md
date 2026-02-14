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

- **signin/**:

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
    { "401":  Invalid JWT" },
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

- **pets?id={petId}**:

```JSON
{
  "method": "GET",
  "headers": [{ "authorization": "Bearer JWT_TOKEN" }],
  "query": {
    "id": "number (required)"
  },
  "response": {
    "status": 200,
    "body": {
      "pet": {
        "id": "number",
        "name": "string"
      },
      "activities": [
        {
          "id": "number",
          "name": "string",
          "description": "string",
          "times": "number",
          "progress": "number",
          "completed": "boolean",
          "created_at": "timestamp"
        }
      ]
    }
  },
  "errors": [
    { "400": "Bad request / Missing Authorization header / id must be a number / Invalid parameters" },
    { "401": "Invalid JWT" },
    { "404": "Pet not found or you don't own it" },
    { "500": "Failed to read ownership / Unexpected error" }
  ]
}
```

**_NOTES:_**

- Returns a specific pet owned by the authenticated user along with ALL its activities

- Requires valid JWT token in Authorization header

- Single query: Uses nested select with `pets!inner` to validate ownership AND fetch activities in one database call

- Activities are automatically ordered by `created_at` in descending order (newest first)

- The `id` query parameter is required and must be numeric

- Returns 404 if pet doesn't exist or user doesn't own it (PGRST116)

- Response structure: `{ pet: { id, name }, activities: [...] }`

- Returns empty array `[]` if pet has no activities

  ***

- **activity/** :

```json
{
  "method": "POST",
  "headers": [
    { "content-type": "application/json" },
    { "authorization": "Bearer JWT_TOKEN" }
  ],
  "body": {
    "pet": "string (number as string)",
    "name": "string",
    "times": "string (number as string)",
    "description": "string (optional)"
  },
  "response": {
    "status": 201,
    "body": {
      "id": "number",
      "starter": "number",
      "pet": "number",
      "name": "string",
      "description": "string",
      "times": "number",
      "progress": "number",
      "completed": "boolean",
      "created_at": "timestamp"
    }
  },
  "errors": [
    {
      "400": "Bad request / pet must be a number / times must be a number / Name cannot be empty / Missing or invalid Authorization header"
    },
    { "401": "Invalid JWT" },
    { "403": "You are not the owner of this pet (trigger validation)" },
    { "422": "Missing required fields / Invalid JSON body" },
    { "500": "Failed to create activity / Unexpected error" }
  ]
}
```

**_NOTES_**:

- Creates a new activity for a specific `pet` owned by the authenticated user

- Requires valid JWT token in Authorization header

- `pet` and `times` are received as strings but must be numeric values (automatically converted)

- `description` is optional, defaults to empty string

- `progress` defaults to 0, `completed` defaults to false

- Database trigger validation: Automatically verifies that the authenticated user (`starter`) actually owns the `pet` via `ownership` table

- Returns the complete created activity object on success

- Returns 403 if the trigger detects the user doesn't own the specified `pet`

---

- **users/** :

```JSON
{
  "method": "GET",
  "headers": [{ "authorization": "Bearer JWT_TOKEN" }],
  "response": {
    "status": 200,
    "body": {
      "userId": "number",
      "username": "string"
    }
  },
  "errors": [
    { "400": "Bad request -->Authorization: Bearer \"token\"" },
    { "401": "Invalid jwt" }
  ]
}
```

**_NOTES_**:

- Returns the authenticated user's id and username extracted from JWT.
- Requires valid JWT token in Authorization header.
- No request body required.

---

- **activity/increment?id={id}** :

```JSON
{
  "method": "POST",
  "headers": [{ "authorization": "Bearer JWT_TOKEN" }],
  "query": {
    "id": "number (required)"
  },
  "response": {
    "status": 200,
    "body": {
      "id": "number",
      "progress": "number",
      "completed": "boolean"
    }
  },
  "errors": [
    { "400": "Missing token / Invalid activity id" },
    { "401": "Invalid jwt" },
    { "404": "Activity not found or unauthorized" },
    { "500": "Failed to increment / Unexpected error" }
  ]
}
```

**_NOTES_**:

- Increments progress for a specific activity owned by the authenticated user.
- Requires valid JWT token in Authorization header.
- Activity id is passed as query parameter.
- Returns updated activity progress and completion status.

---

- **activity?id={id}** :

```JSON
{
  "method": "DELETE",
  "headers": [{ "authorization": "Bearer JWT_TOKEN" }],
  "query": {
    "id": "number (required)"
  },
  "response": {
    "status": 200,
    "body": {
      "id": "number",
      "deleted": "boolean"
    }
  },
  "errors": [
    { "400": "Missing token / Invalid activity id / Activity already deleted" },
    { "401": "Invalid jwt" },
    { "403": "You are not an owner of this pet" },
    { "404": "Activity not found" },
    { "500": "Failed to delete activity / Unexpected error" }
  ]
}
```

**_NOTES_**:

- Deletes (marks as deleted) a specific activity owned by the authenticated user.
- Requires valid JWT token in Authorization header.
- Activity id is passed as query parameter.
- Returns deletion status.

---

- **pets/share/** :

```JSON
{
  "method": "POST",
  "headers": [
    { "content-type": "application/json" },
    { "authorization": "Bearer JWT_TOKEN" }
  ],
  "body": {
    "newOwner": "number",
    "petId": "number"
  },
  "response": {
    "status": 201,
    "body": {
      "success": "boolean",
      "message": "string"
    }
  },
  "errors": [
    { "400": "Missing token / Invalid parameters / Supabase error" },
    { "401": "Invalid jwt" },
    { "500": "Unexpected error" }
  ]
}
```

**_NOTES_**:

- Shares a pet with another user (adds new ownership).
- Requires valid JWT token in Authorization header.
- Body must include newOwner (user id) and petId.
- Returns success and message.

---

- **pets/ownership?id={id}** :

```JSON
{
  "method": "DELETE",
  "headers": [{ "authorization": "Bearer JWT_TOKEN" }],
  "query": {
    "id": "number (required)"
  },
  "response": {
    "status": 200,
    "body": ""
  },
  "errors": [
    { "400": "Bad request -->Authorization: Bearer \"token\" / Invalid pet id" },
    { "401": "Invalid jwt" },
    { "404": "Relation not found" },
    { "500": "Unexpected error" }
  ]
}
```

**_NOTES_**:

- Removes ownership relation for a pet and authenticated user.
- Requires valid JWT token in Authorization header.
- Pet id is passed as query parameter.
- Returns empty body on success.

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
