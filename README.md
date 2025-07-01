# 🛒 GadgetGear - Decoupled E-commerce Platform

GadgetGear is a full-stack decoupled e-commerce application featuring a **React.js frontend** and a **Drupal 10 backend**. It delivers a modern shopping experience with a custom-built Drupal REST API module to manage users, products, orders, and reviews.

---

## 🚀 Tech Stack

### Frontend (React)
- React.js (with hooks and functional components)
- React Router for navigation
- Axios for API communication
- Tailwind CSS or Material UI for UI styling
- Context API for global state

### Backend (Drupal)
- Drupal 10 CMS
- Custom RESTful API via `custom_api` module
- JWT (JSON Web Token) authentication using cookies
- Node entities for products and orders
- User entities with role-based access
- Protected admin-only routes

---

## 📁 Project Structure
```bash
GadgetGear/
├── config/
├── recipes/
├── upstream-configuration/
├── vendor/
├── web/
│   ├── core/
│   ├── modules/
│   │   └── custom/
│   │       └── custom_api/
│   │           ├── src/
│   │           │   └── Controller/
│   │           │       ├── ProductApiController.php
│   │           │       ├── OrderController.php
│   │           │       └── UserAuthController.php
│   │           ├── custom_api.info.yml
│   │           ├── custom_api.module
│   │           └── custom_api.routing.yml
│   ├── profiles/
│   ├── sites/
│   ├── themes/
│   ├── .htaccess
│   ├── index.php
│   ├── update.php
│   └── README.md
├── .lando.yml
├── composer.json
├── composer.lock
└── pantheon.yml

---
```
## 📦 API Endpoints

### 👤 Authentication Routes
| Method | Endpoint            | Description          |
|--------|---------------------|----------------------|
| POST   | `/api/users`        | Register new user    |
| POST   | `/api/users/auth`   | Login user           |
| POST   | `/api/users/logout` | Logout user          |
| GET    | `/api/users`        | Get all users (admin)|
| GET    | `/api/users/{id}`   | Get user by ID       |
| PUT    | `/api/users/{id}`   | Update user          |
| DELETE | `/api/users/{id}`   | Delete user          |

### 🛍 Product Routes
| Method | Endpoint                        | Description                |
|--------|----------------------------------|----------------------------|
| GET    | `/api/products`                 | List all products          |
| GET    | `/api/products/top`             | Top-rated products         |
| GET    | `/api/products/{id}`            | Product details            |
| POST   | `/api/products`                 | Create product (admin)     |
| PUT    | `/api/products/{id}`            | Update product (admin)     |
| DELETE | `/api/products/{id}`            | Delete product (admin)     |
| POST   | `/api/products/{id}/reviews`    | Submit product review      |

### 📦 Order Routes
| Method | Endpoint                     | Description                    |
|--------|------------------------------|--------------------------------|
| POST   | `/api/orders`               | Create a new order             |
| GET    | `/api/orders/mine`          | Get logged-in user's orders    |
| GET    | `/api/orders`               | Admin: Get all orders          |
| GET    | `/api/orders/{id}`          | Get order by ID                |
| PUT    | `/api/orders/{id}/deliver`  | Mark order as delivered (admin)|

---

## 🔐 Authentication

- **JWT-based Cookie Authentication** is used.
- On successful login, the backend sets a secure `jwt` cookie.
- Protected routes read and decode the token to authenticate users.

> You can also use **API Key Authentication** via the miniOrange module.

---

## 🧪 Testing API

Use Postman or a REST client to test API calls.

### Example Login

```http
POST /api/users/auth
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "password123"
}
```
### ⚙️ Setup Instructions

🖥 Backend (Drupal)
	1.	Clone the repository:
    git clone https://github.com/Gursimran07316/GadgetGear-Drupal.git

Set up using Lando (recommended):
```bash
    lando init --recipe drupal10 --webroot . --name gadgetgear
    lando start
    lando composer install
    lando drush site:install
    lando drush en custom_api
```

### Create content types:
-	Product
-	Order
-	Add fields: title, price, reviews, shipping, etc.
-	Set permissions and roles for authenticated/admin users.

### ✅ Features

-	🔐 Secure authentication via JWT cookies
		👤 User registration, login, logout
-	🛒 Product listing and reviews
-	📦 Order creation and history
-	🧑‍💼 Admin dashboard features
-	💡 Decoupled architecture




⸻

### 👨‍💻 Author

**Gursimran “Guri” Khela**  
📫 [gursimrankhela@gmail.com](mailto:gursimrankhela@gmail.com)  
🌐 [gursimrankhela.com](https://gursimrankhela.com)

⸻

📄 License

This project is licensed under the MIT License.
