# Gurdia-Auth: Adaptive Security & RBAC System

This is a professional Authentication and Authorization system built with **NestJS**, **Prisma**, **PostgreSQL**, **Redis**, and **Kong API Gateway**. It features Adaptive Security (OTP based on IP) and Role-Based Access Control (RBAC).

---

## 1. Architecture
The system follows a microservices-ready architecture for scalability and security:



* **App Service:** NestJS application handling business logic and REST APIs.
* **API Gateway:** **Kong Gateway** acts as the entry point, managing request routing and security layers.
* **Database:** **PostgreSQL** for persistent storage of Users, Roles, Permissions, and Audit Logs.
* **Caching/OTP:** **Redis** for high-speed storage of temporary OTPs (5-minute expiry).
* **Containerization:** The entire stack is containerized using **Docker Compose** for easy deployment.

---

## 2. RBAC Logic (Role-Based Access Control)
The system implements a granular RBAC model where access is determined by specific permissions rather than just role names:

* **User-to-Role:** Each user is assigned one role (e.g., ADMIN, USER).
* **Role-to-Permission:** Each role is mapped to multiple permissions.
* **Flexibility:** This allows the administrator to change what a "USER" can do by simply adding or removing permissions from the role in the database without changing the code.

---

## 3. Permission Flow
The system ensures security through a custom interceptor/guard layer:

1.  **Request:** User sends a request with a JWT token in the Authorization header.
2.  **Guard:** The `PermissionsGuard` intercepts the request.
3.  **Extraction:** It extracts the `userId` from the JWT and fetches the user's role and associated permissions from the database.
4.  **Validation:** It checks if the required permission (defined via `@Permissions()` decorator in the controller) exists in the user's permission list.
5.  **Access:** If valid, the request proceeds. Otherwise, a `403 Forbidden` error is returned.



---

## 4. Policy Handling & Adaptive Security
* **Adaptive OTP:** The system monitors the user's `lastLoginIp`. If a login attempt is detected from a new IP address, the system generates a 6-digit OTP, saves it in Redis, and sends it to the user's email via **Nodemailer**.
* **Audit Logging:** Every security-related event (Login, OTP trigger, Registration, Permission Failure) is logged in the `AuditLog` table, providing a full security trail.
* **JWT Policy:** Access tokens are generated using a secure secret and include user identity and role information.

---

## 5. Sample Data Structure

### Roles & Permissions
| Role | Permissions | Description |
| :--- | :--- | :--- |
| **ADMIN** | `CREATE_USER`, `READ_USER`, `UPDATE_USER`, `DELETE_USER`, `VIEW_LOGS` | Full system access. |
| **USER** | `READ_USER`, `UPDATE_SELF` | Restricted access. |

### Sample Users
* **Admin User:** `admin@gurdia.com` | Role: `ADMIN`
* **Standard User:** `user@gurdia.com` | Role: `USER`

---

## How to Run
1.  **Clone the repository:**
    ```bash
    git clone https://github.com/Maksudur7/gurdia-auth-main.git
    ```
2.  **Configure Environment:** Create a `.env` file based on `.env`.
3.  ```bash
    DATABASE_URL="postgresql://user:password@db:5432/gurdia_auth?schema=public"
    BETTER_AUTH_SECRET=o2kEvkMLITIPDMKZKCdJYlD2q2dHYsSM
    PORT=3000
    APP_URL=http://localhost:3000
    JWT_SECRET = ' This is my secret key for jwt token generation '
    EMAIL_USER= add a appemail 
    EMAIL_PASS=  add a password
    ```
4.  **Start with Docker:**
    ```bash
    docker compose up -d --build
    ```
5.  **Database Setup:**
    ```bash
    docker compose exec app npx prisma generate
    docker compose exec gurdia_app npx prisma db push
    ```
6. ** If any provlem in app let giv a command in terminal and see the provlem : **
   ```bash
   docker compose logs app
   ```
