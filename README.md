# 🔐 AuthBackendPackage

A flexible and plug-and-play authentication module for Node.js applications. Provides features such as OTP-based verification, JWT authentication, email verification, password reset, and user profile management.

---

## 🔧 Installation

```bash
npm i authbackendpackage
```

---

## 📦 Module Setup

```js
// index.js or app.js
import express from "express";
import { createAuthModule } from "authbackendpackage";
import userModel from "./models/user.model.js";
import cloudinary from "./lib/cloudinary.js";

const app = express();

const auth = createAuthModule({
  userModel,
  cloudinaryInstance: cloudinary,
  jwtSecret: process.env.JWT_SECRET,
  mailUser: process.env.MY_MAIL,
  mailPass: process.env.MY_PASSWORD,
  env: process.env.NODE_ENV,
});
```

---

## ☁️ Cloudinary Configuration

First, create an account on [Cloudinary](https://cloudinary.com/).
Then, create an API key and place the values in your `.env` file.

Cloudinary is used for storing profile or other images.

**Cloudinary Instance:**

```js
import { config } from "dotenv";
import { v2 as cloudinary } from "cloudinary";
config();

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

export default cloudinary;
```

---

## 🔐 JWT Secret

Choose any secure string as your `JWT_SECRET` and add it to your `.env` file.

## 📧 Mail Setup

Generate an **App Password** using your Gmail account. Refer to this [guide](https://itsupport.umd.edu/itsupport?id=kb_article_view&sysparm_article=KB0015112) for assistance.

---

## 👤 User Model Example

```js
import mongoose from 'mongoose';

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
  },
  name: {
    type: String,
    required: true,
  },
  password: {
    type: String,
    required: true,
  },
  profilePicture: {
    type: String,
    default: "",
  },
}, { timestamps: true });

const User = mongoose.model('User', userSchema);
export default User;
```

---

## 🔀 Routes Setup

```js
app.post("/api/send-otp", auth.sendOtp);
app.post("/api/verify-otp", auth.verifyOTP);
app.post("/api/signup", auth.signup);
app.post("/api/login", auth.login);
app.post("/api/logout", auth.logout);
app.put("/api/update-profile", auth.updateProfile);
app.get("/api/check-auth", auth.checkAuth);
app.post("/api/forgot-password", auth.forgotPassword);
```

---

## 🛡️ Middleware: Protect Route

```js
import jwt from "jsonwebtoken";
import user from "../models/user.model.js";
import dotenv from "dotenv";
dotenv.config();

export const protectRoute = async (req, res, next) => {
  try {
    const token = req.cookies.jwt;
    if (!token) {
      return res.status(401).json({ message: "Not authorized - No token provided" });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET || "shreyash5506");
    const foundUser = await user.findById(decoded.userId).select("-password");

    if (!foundUser) {
      return res.status(401).json({ message: "Not authorized - User not found" });
    }

    req.user = foundUser;
    next();
  } catch (error) {
    console.error("Auth middleware error:", error);
    res.status(401).json({ message: "Not authorized - Invalid token" });
  }
}
```

---

## 🧠 Features

* ✅ OTP verification via email (SMTP-based)
* ✅ Signup with verified OTP
* ✅ Secure login with JWT
* ✅ Profile update with optional image upload (Cloudinary)
* ✅ Forgot password with bcrypt hashing
* ✅ Logout via cookie expiration
* ✅ Middleware-ready endpoints

---

## 🧪 Example `.env`

```env
MY_MAIL=your-email@gmail.com
MY_PASSWORD=your-email-password-or-app-password
JWT_SECRET=your-secret-key
NODE_ENV=development
```

---

## 📥 Request Examples

### 1. Send OTP

```http
POST /api/send-otp
Content-Type: application/json
{
  "email": "user@example.com"
}
```

### 2. Verify OTP

```http
POST /api/verify-otp
Content-Type: application/json
{
  "email": "user@example.com",
  "otp": "123456"
}
```

### 3. Signup

```http
POST /api/signup
Content-Type: application/json
{
  "email": "user@example.com",
  "password": "your-password",
  "name": "User Name"
}
```

### 4. Login

```http
POST /api/login
Content-Type: application/json
{
  "email": "user@example.com",
  "password": "your-password"
}
```

### 5. Update Profile

```http
PUT /api/update-profile
Content-Type: application/json
{
  "name": "New Name",
  "profilePicture": "base64encodedImageOrUrl"
}
```

### 6. Forgot Password

```http
POST /api/forgot-password
Content-Type: application/json
{
  "email": "user@example.com",
  "newPassword": "new-secure-password"
}
```

---

## 🔐 Cookie-Based JWT Auth

The JWT token is automatically sent via `httpOnly` cookie and expires after 7 days.

---

## 📄 License

Apache-2.0

---

Built with ❤️ by the Shreyash Team
