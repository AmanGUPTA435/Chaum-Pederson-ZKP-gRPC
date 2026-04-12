# 🔐 Zero-Knowledge Authentication System

### Rust • gRPC • PostgreSQL • Chaum-Pedersen ZKP

---

![image](https://github.com/user-attachments/assets/77cbe475-68c6-4d04-89bd-a7de1ed27c13)

## 🚀 What is this?

A **production-style authentication service** that replaces traditional password-based login with a **Zero-Knowledge Proof (ZKP)** protocol.

👉 Users prove they know a secret **without ever sending it to the server**.

---

## ❗ Why this matters

Traditional authentication systems:

- Store password hashes → vulnerable to leaks
- Transmit secrets → risk interception
- Require trust in server security

This system:

- ❌ Never stores passwords
- ❌ Never transmits secrets
- ✅ Uses cryptographic proofs instead

---

## 🧠 Key Idea

Uses the **Chaum-Pedersen Zero-Knowledge Proof** to verify:

```
User knows x such that:
Y1 = g^x
Y2 = h^x
```

Without revealing `x`.

---

## 🏗️ Architecture

```
CLI Client (Prover)
        ↓ gRPC
Auth Server (Verifier)
        ↓
PostgreSQL
```

---

## ⚙️ Tech Stack

- **Rust (Tokio + Tonic)** → async gRPC server/client
- **SQLx + PostgreSQL** → compile-time checked DB queries
- **Tracing** → structured observability
- **DashMap / async primitives** → concurrent state handling

---

## 🔄 Authentication Flow

### 1. Register

- Client computes `(Y1, Y2)`
- Server stores commitments

---

### 2. Challenge Phase

- Client sends `(R1, R2)`
- Server generates challenge `c`
- Temporary auth session created

---

### 3. Verification

- Client sends proof `s`
- Server verifies:

```
g^s = R1 * Y1^c
h^s = R2 * Y2^c
```

- On success:
  - Session created
  - Logs recorded

---

### 4. Session Management

- Session stored in DB with expiry
- Validation checks DB state

---

### 5. Logout

- Session invalidated

---

## 🗄️ Database Design

### `users`

Stores public commitments (no secrets)

```
user_name | y1 | y2 | created_at
```

### `sessions`

Tracks active sessions

```
session_id | user_name | auth_id | expires_at | is_active
```

### `auth_logs`

Audit trail of all attempts

```
user_name | auth_id | session_id | success | failure_reason | created_at
```

---

## 🧠 Design Decisions

### 🔐 Security-first design

- No passwords stored or transmitted
- ZKP ensures zero knowledge leakage

---

### 🔄 Separation of concerns

- Client → cryptographic operations
- Server → verification + business logic
- DB → persistence layer

---

### 🧾 Audit logging

- Tracks both successful and failed attempts
- Enables:
  - rate limiting
  - anomaly detection
  - debugging

---

### ⚡ Rate limiting

- Prevents brute-force attempts
- Automatically resets on successful authentication

---

### 🧵 Concurrency-safe design

- Uses async + lock-free structures where possible
- Avoids global blocking (Mutex-heavy design avoided)

---

### 🧾 Transactional integrity

- Session creation + logging are atomic
- Prevents inconsistent states

---

## 📊 Observability

- Structured logs using `tracing`
- Request-level instrumentation
- Latency measurement for critical operations

---

## 🚀 How to Run

### 1. Install dependencies

```bash
sudo apt install protobuf-compiler postgresql
```

---

### 2. Setup database

```bash
createdb zkp_db
psql -d zkp_db -f schema.sql
```

---

### 3. Set environment

```bash
export DATABASE_URL=postgres://postgres:password@localhost:5432/zkp_db
```

---

### 4. Run server

```bash
cargo run --bin server
```

---

### 5. Run client

```bash
cargo run --bin client -- register <username> <password>
cargo run --bin client -- authenticate <username> <password>
```

---

## 🐳 Docker (Optional)

```bash
docker-compose build
docker-compose up
```

---

## 🧪 Example

```
Register → OK
Authenticate → Session ID returned
Validate → Success
Logout → Session invalidated
```

---

## ⚠️ Limitations

- Uses CLI (no UI yet)
- In-memory rate limiting (can be moved to DB/Redis)
- No TLS (should be added for production)

---

## 🔮 Future Improvements

- [ ] Move rate limiting to Redis
- [ ] Add TLS (secure transport)
- [ ] Add refresh tokens / session rotation
- [ ] Add metrics (Prometheus)
- [ ] Horizontal scaling support

---

## 💡 What this project demonstrates

- Applied cryptography (ZKP)
- Distributed systems (client-server via gRPC)
- Backend system design
- Database design + consistency
- Observability and debugging
- Secure authentication patterns

---

## 👨‍💻 Author

Built as a **production-style system to explore secure authentication beyond passwords**.

---

## ⭐ If you liked this project

Star it, fork it, or break it 😄
