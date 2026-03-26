# Secure Lab (Node/Express)

This mini app contains *several security issues* for you to find by reading the code and trying requests.

## Setup

```bash
npm install
npm run seed
npm start
```

The app runs at `http://localhost:3000`.

## Useful tips

- Use the `X-User` header to simulate a logged-in user:
  - `X-User: alice` (admin)
  - `X-User: bob` (regular user)
- Routes:
  - `GET /users?name=<term>`
  - `GET /search?q=<term>`
  - `POST /admin/deleteUser` with JSON body `{ "userId": 1 }`
  - `POST /login` with JSON `{ "username", "password" }`
- Check **all files** — including templates in `views/` and the database setup in `db.js` and `seed.js`.

## Reset

To reset the database to its original state:

```bash
npm run reset
```
