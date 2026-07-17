
---

# 🔐 AuthBackendPackage

A flexible and plug-and-play authentication module for [Node.js](w) applications. Provides features such as [OTP](w)-based verification, [JWT](w) authentication, email verification, password reset, and user profile management.

✅ **Successfully tested and used in production at:**
🔗 [https://pulsetalk-6lrk.onrender.com](https://pulsetalk-6lrk.onrender.com)

---
Total downloads :- 1200+
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
  BREVO_API_KEY=your_brevo_api_key_here
BREVO_SENDER_EMAIL=noreply@pulsetalk.com
BREVO_SENDER_NAME=PulseTalk
  env: process.env.NODE_ENV,
});
```

---

## ☁️ Cloudinary Configuration

Create an account on [Cloudinary](https://cloudinary.com/), generate API credentials, and store them in your `.env` file.

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

Set a secure `JWT_SECRET` string in your `.env` file.

---

## 📧 Mail Setup

Generate an **App Password** from your Gmail settings and store it in `.env`.

👉 Follow this [Gmail App Password Guide](https://itsupport.umd.edu/itsupport?id=kb_article_view&sysparm_article=KB0015112)

---

## 👤 User Model Example

```js
import mongoose from 'mongoose';

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  password: { type: String, required: true },
  profilePicture: { type: String, default: "" },
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

* ✅ OTP verification via email (SMTP)
* ✅ Signup with verified OTP
* ✅ Secure login with JWT
* ✅ Profile update with image support (Cloudinary)
* ✅ Forgot password with [bcrypt](w)
* ✅ Cookie-based logout
* ✅ Middleware-ready routes

---

## 🧪 Example `.env`

```env
BREVO_API_KEY=your_brevo_api_key_here
BREVO_SENDER_EMAIL=noreply@pulsetalk.com
BREVO_SENDER_NAME=PulseTalk
JWT_SECRET=your-secret-key
NODE_ENV=development
CLOUDINARY_CLOUD_NAME=your-cloud-name
CLOUDINARY_API_KEY=your-api-key
CLOUDINARY_API_SECRET=your-api-secret
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

Authentication is done using `httpOnly` cookies which automatically expire after 7 days for enhanced security.

---

## 🚀 Live Usage Demo

✅ **Successfully running on:**
🌐 [https://pulsetalk-6lrk.onrender.com](https://pulsetalk-6lrk.onrender.com)

---

## 📄 License

Licensed under [Apache-2.0](w).

---

Built with ❤️ by the **Shreyash Team**

---
