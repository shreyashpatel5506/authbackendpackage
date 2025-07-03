// File: index.js

import dotenv from "dotenv";
dotenv.config();

import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import dns from "dns/promises";

export const createAuthModule = ({ userModel, cloudinaryInstance, jwtSecret, mailUser, mailPass, env = "development" }) => {

    const otpStorage = new Map();

    const generateToken = (userId, res) => {
        const token = jwt.sign({ userId }, jwtSecret, {
            expiresIn: "7d",
        });

        res.cookie("jwt", token, {
            httpOnly: true,
            secure: env !== "development",
            sameSite: "strict",
            maxAge: 30 * 24 * 60 * 60 * 1000,
        });

        return token;
    };

    const transporter = nodemailer.createTransport({
        service: "gmail",
        auth: {
            user: mailUser,
            pass: mailPass,
        },
    });

    const sendOtp = async (req, res) => {
        const { email } = req.body;
        if (!email) return res.status(400).json({ message: "Email is required", success: false });

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) return res.status(422).json({ message: "Invalid email format", success: false });

        try {
            const domain = email.split("@")[1];
            const mxRecords = await dns.resolveMx(domain);
            if (!mxRecords || mxRecords.length === 0) {
                return res.status(452).json({ message: "Email domain does not accept mail", success: false });
            }
        } catch (dnsError) {
            return res.status(452).json({ message: "Invalid or unreachable email domain", success: false });
        }

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const mailOptions = {
            from: `PulseTalk <${mailUser}>`,
            to: email,
            subject: "🔐 Your PulseTalk OTP Code",
            html: `Your OTP code is: <strong>${otp}</strong> (valid for 10 minutes)`
        };

        try {
            const info = await transporter.sendMail(mailOptions);
            if (info.accepted.includes(email)) {
                otpStorage.set(email, { otp, verified: false });
                return res.status(200).json({ message: "OTP sent", success: true });
            } else {
                return res.status(452).json({ message: "SMTP did not accept the email", success: false });
            }
        } catch (err) {
            return res.status(502).json({ message: "Failed to send email", success: false });
        }
    };

    const verifyOTP = (req, res) => {
        const { email, otp } = req.body;
        const record = otpStorage.get(email);
        if (record && record.otp === otp) {
            otpStorage.set(email, { ...record, verified: true });
            return res.status(200).json({ message: "OTP verified", success: true });
        }
        return res.status(400).json({ message: "Invalid OTP", success: false });
    };

    const signup = async (req, res) => {
        try {
            const { email, password, name } = req.body;
            const { profilePicture } = req.files || {};
            const record = otpStorage.get(email);

            if (!record || !record.verified) return res.status(400).json({ message: "OTP not verified for this email" });
            if (!email || !password || !name) return res.status(400).json({ message: "Missing required fields" });
            if (password.length < 6) return res.status(401).json({ message: "Password too short" });

            const existingUser = await userModel.findOne({ email });
            if (existingUser) return res.status(400).json({ message: "User already exists" });

            const hashPassword = await bcrypt.hash(password, 10);
            const newUser = new userModel({ email, password: hashPassword, name });
            await newUser.save();
            generateToken(newUser._id, res);
            otpStorage.delete(email);

            return res.status(201).json({
                message: "User created",
                success: true,
                user: newUser,
            });
        } catch (err) {
            return res.status(500).json({ message: err.message });
        }
    };

    const login = async (req, res) => {
        try {
            const { email, password } = req.body;
            const user = await userModel.findOne({ email });
            if (!user) return res.status(400).json({ message: "User does not exist" });

            const validPassword = await bcrypt.compare(password, user.password);
            if (!validPassword) return res.status(400).json({ message: "Invalid password" });

            generateToken(user._id, res);
            return res.status(200).json({ message: "Login successful", success: true, user });
        } catch (error) {
            return res.status(500).json({ message: error.message });
        }
    };

    const logout = async (req, res) => {
        res.cookie("jwt", "", { maxAge: 0 });
        return res.status(200).json({ message: "Logout successful" });
    };

    const updateProfile = async (req, res) => {
        try {
            const userId = req.user._id;
            const { name, profilePicture } = req.body;

            const updatedFields = {};
            if (name) updatedFields.name = name;

            if (profilePicture && profilePicture.trim() !== '') {
                try {
                    const pic = await cloudinaryInstance.uploader.upload(profilePicture);
                    updatedFields.profilePicture = pic.secure_url;
                } catch {
                    return res.status(400).json({ message: "Invalid profile picture format" });
                }
            }

            const user = await userModel.findByIdAndUpdate(userId, updatedFields, { new: true });
            return res.status(200).json({ message: "Profile updated", success: true, user });
        } catch (error) {
            return res.status(500).json({ message: error.message });
        }
    };

    const checkAuth = async (req, res) => {
        try {
            const user = req.user;
            return res.status(200).json({ message: "User authenticated", success: true, user });
        } catch (error) {
            return res.status(500).json({ message: error.message });
        }
    };

    const forgotPassword = async (req, res) => {
        try {
            const { email, newPassword } = req.body;
            if (!email || !newPassword) return res.status(400).json({ message: "Email and new password are required" });

            const user = await userModel.findOne({ email });
            if (!user) return res.status(400).json({ message: "User does not exist" });

            const hashPassword = await bcrypt.hash(newPassword, 10);
            await userModel.findByIdAndUpdate(user._id, { password: hashPassword });

            return res.status(200).json({ message: "Password updated", success: true });
        } catch (error) {
            return res.status(500).json({ message: error.message });
        }
    };

    return {
        sendOtp,
        verifyOTP,
        signup,
        login,
        logout,
        updateProfile,
        checkAuth,
        forgotPassword,
    };
};
