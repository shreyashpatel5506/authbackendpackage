// File: index.js

import dotenv from "dotenv";
dotenv.config();

import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import dns from "dns/promises";

export const createAuthModule = ({
    userModel,
    cloudinaryInstance,
    jwtSecret,
    env = "development",
}) => {

    const otpStorage = new Map();

    // ================= TOKEN =================
    const generateToken = (userId, res) => {
        const token = jwt.sign({ userId }, jwtSecret, { expiresIn: "7d" });

        res.cookie("jwt", token, {
            httpOnly: true,
            secure: env !== "development",
            sameSite: "strict",
            maxAge: 30 * 24 * 60 * 60 * 1000,
        });

        return token;
    };

    // ================= BREVO SMTP =================
    const transporter = nodemailer.createTransport({
        host: process.env.BREVO_SMTP_HOST,
        port: process.env.BREVO_SMTP_PORT,
        secure: false,
        auth: {
            user: process.env.BREVO_SMTP_USER, // always "apikey"
            pass: process.env.BREVO_SMTP_PASS, // Brevo API key
        },
    });

    // ================= SEND OTP =================
    const sendOtp = async (req, res) => {
        const { email } = req.body;
        if (!email) return res.status(400).json({ message: "Email is required", success: false });

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email))
            return res.status(422).json({ message: "Invalid email format", success: false });

        try {
            const domain = email.split("@")[1];
            const mxRecords = await dns.resolveMx(domain);
            if (!mxRecords.length)
                return res.status(452).json({ message: "Email domain not valid", success: false });
        } catch {
            return res.status(452).json({ message: "Invalid email domain", success: false });
        }

        const otp = Math.floor(100000 + Math.random() * 900000).toString();

        const mailOptions = {
            from: "PulseTalk <noreply@pulsetalk.com>", // Brevo verified sender
            to: email,
            subject: "🔐 Your PulseTalk OTP",
            html: `
                <h3>Your OTP Code</h3>
                <p><b>${otp}</b></p>
                <p>Valid for 10 minutes</p>
            `,
        };

        try {
            await transporter.sendMail(mailOptions);
            otpStorage.set(email, { otp, verified: false, createdAt: Date.now() });

            return res.status(200).json({ message: "OTP sent successfully", success: true });
        } catch (error) {
            return res.status(502).json({ message: "Brevo email failed", success: false });
        }
    };

    // ================= VERIFY OTP =================
    const verifyOTP = (req, res) => {
        const { email, otp } = req.body;
        const record = otpStorage.get(email);

        if (record && record.otp === otp) {
            otpStorage.set(email, { ...record, verified: true });
            return res.status(200).json({ message: "OTP verified", success: true });
        }

        return res.status(400).json({ message: "Invalid OTP", success: false });
    };

    // ================= SIGNUP =================
    const signup = async (req, res) => {
        try {
            const { email, password, name } = req.body;
            const record = otpStorage.get(email);

            if (!record || !record.verified)
                return res.status(400).json({ message: "OTP not verified" });

            if (!email || !password || !name)
                return res.status(400).json({ message: "Missing fields" });

            if (password.length < 6)
                return res.status(400).json({ message: "Password too short" });

            const exists = await userModel.findOne({ email });
            if (exists)
                return res.status(400).json({ message: "User already exists" });

            const hash = await bcrypt.hash(password, 10);
            const user = await userModel.create({ email, password: hash, name });

            generateToken(user._id, res);
            otpStorage.delete(email);

            return res.status(201).json({ message: "User created", success: true, user });
        } catch (err) {
            return res.status(500).json({ message: err.message });
        }
    };

    // ================= LOGIN =================
    const login = async (req, res) => {
        try {
            const { email, password } = req.body;
            const user = await userModel.findOne({ email });
            if (!user) return res.status(400).json({ message: "User not found" });

            const valid = await bcrypt.compare(password, user.password);
            if (!valid) return res.status(400).json({ message: "Invalid password" });

            generateToken(user._id, res);
            return res.status(200).json({ message: "Login successful", success: true, user });
        } catch (err) {
            return res.status(500).json({ message: err.message });
        }
    };

    const logout = (req, res) => {
        res.cookie("jwt", "", { maxAge: 0 });
        res.status(200).json({ message: "Logout successful" });
    };

    const checkAuth = (req, res) => {
        res.status(200).json({ success: true, user: req.user });
    };

    const forgotPassword = async (req, res) => {
        try {
            const { email, newPassword } = req.body;
            if (!email || !newPassword)
                return res.status(400).json({ message: "Missing fields" });

            const user = await userModel.findOne({ email });
            if (!user) return res.status(400).json({ message: "User not found" });

            const hash = await bcrypt.hash(newPassword, 10);
            await userModel.findByIdAndUpdate(user._id, { password: hash });

            res.status(200).json({ message: "Password updated", success: true });
        } catch (err) {
            res.status(500).json({ message: err.message });
        }
    };

    return {
        sendOtp,
        verifyOTP,
        signup,
        login,
        logout,
        checkAuth,
        forgotPassword,
    };
};
