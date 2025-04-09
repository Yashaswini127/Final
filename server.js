'use strict';

require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const bodyParser = require('body-parser');
const QRCode = require('qrcode');
const session = require('express-session'); 
const cookieParser = require('cookie-parser');
const { Parser } = require('json2csv');
const axios = require('axios');
const crypto = require('crypto');

const app = express();
const allowedOrigins = ["http://localhost:5001", "https://final-2-30iu.onrender.com"];

app.use(cors({
  origin: "https://final-2-30iu.onrender.com", // 
  credentials: true, //
}));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'frontend')));
app.use(cookieParser());

app.use(session({
  secret: process.env.JWT_SECRET || 'secretkey',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, httpOnly: true }
}));

const MONGO_URI = process.env.MONGO_URI || "mongodb+srv://Jet-Club:JETClub2025@cluster0.u7mfy.mongodb.net/";
mongoose.connect(MONGO_URI)
  .then(() => console.log("✅ MongoDB Connected"))
  .catch(err => console.error("❌ MongoDB Connection Failed:", err));

const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  role: { type: String, default: 'user' },
  contact: { type: String },
  register: { type: String, unique: true, required: true },
});
const User = mongoose.model('User', userSchema);

const attendanceSchema = new mongoose.Schema({
  name: { type: String, required: true },
  register: { type: String, required: true, ref: "User" },
  date: { type: Date, required: true },
  status: { type: String, enum: ["present", "absent"], required: true },
  hours: { type: Number, required: true, min: 0 }
});
const Attendance = mongoose.model("Attendance", attendanceSchema);

const authenticateUser = (req, res, next) => {
  const token = req.cookies.token || (req.headers.authorization && req.headers.authorization.split(" ")[1]);

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secretkey');
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(400).json({ error: "Invalid token." });
  }
};


app.post("/register", async (req, res) => {
  const { name, contact, email, register, role, password } = req.body;
  if (!email) return res.status(400).json({ error: "Email is required" });
  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\W).{8,}$/;
  if (!passwordRegex.test(password)) {
    return res.status(400).json({ error: "Password must meet complexity requirements." });
  }
  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ error: "User already exists" });
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ name, contact, email, register, role, password: hashedPassword });
    await newUser.save();
    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/login2", async (req, res) => {
  const { email, password, registerNumber } = req.body;

  try {
    const user = await User.findOne({ email, register: registerNumber });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = jwt.sign(
      { register: user.register, role: user.role, name: user.name },
      process.env.JWT_SECRET || 'secretkey',
      { expiresIn: '1h' }
    );
    res.cookie("token", token, {
  httpOnly: true,
  secure: true, // set to true if using HTTPS
  sameSite: "None" // or "Lax" if not cross-origin
  });

    const isAdmin = user.role.toLowerCase() === "admin";

    res.json({
      token,
      role: user.role.toLowerCase(),
      redirect: isAdmin ? "/admin.html" : "/dashboard.html"
    });

  } catch (error) {
    res.status(500).json({ error: "Server error" });
  }
});


  
app.post("/add-admin", authenticateUser, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).send("Access denied.");
    }
    const { name, register, password } = req.body;
    if (!name || !register || !password) return res.status(400).send("Missing fields");
    const existingUser = await User.findOne({ register });
    if (existingUser) return res.status(409).send("User already exists");
    const hashedPassword = await bcrypt.hash(password, 10);
    const newAdmin = new User({ name, register, password: hashedPassword, role: "admin" });
    await newAdmin.save();
    res.status(201).send("Admin created successfully");
  } catch (error) {
    res.status(500).send("Error creating admin");
  }
});

app.get("/api/generate-qr", authenticateUser, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: "Access denied. Admins only." });
  }
  const googleFormLink = "https://docs.google.com/forms/d/e/1FAIpQLSeE7rx-jCRTrUdbWeNoHi88zP3qawjv2ThImrHh_ql97RD0Lw/viewform?usp=header";
  try {
    const qrCodeDataURL = await QRCode.toDataURL(googleFormLink);
    res.json({ qrCode: qrCodeDataURL });
  } catch (error) {
    res.status(500).json({ error: "QR generation failed" });
  }
});

function convertToCSV(data) {
  if (!data.length) return "";
  const headers = Object.keys(data[0]);
  const csvRows = [
    headers.join(","),
    ...data.map(row => headers.map(field => JSON.stringify(row[field] || "")).join(","))
  ];
  return csvRows.join("\n");
}
app.get('/admin/download-attendance', authenticateUser, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: "Access denied. Admins only." });
    }

    const attendanceRecords = await Attendance.find();
    const csvData = attendanceRecords.map(record => ({
      Name: record.name,
      RegisterNumber: record.register,
      Date: record.date.toISOString().split('T')[0],
      Time: record.date.toISOString().split('T')[1].split('.')[0],
      Status: record.status,
      Hours: record.hours
    }));
    const parser = new Parser({ fields: ['Name', 'RegisterNumber', 'Date', 'Time', 'Status', 'Hours'] });
    const csv = parser.parse(csvData);

    res.setHeader('Content-Disposition', 'attachment; filename=attendance.csv');
    res.setHeader('Content-Type', 'text/csv');
    res.send(csv);
  } catch (error) {
    res.status(500).json({ error: "Failed to generate CSV." });
  }
});


app.post("/api/save-attendance", async (req, res) => {
  try {
    const { name, registerNumber, status, date } = req.body;
    const normalizedStatus = status.toLowerCase() === "present" ? "present" : "absent";
    const hours = normalizedStatus === "present" ? 1 : 0;
    let attendanceDate = date ? new Date(date) : new Date();
    attendanceDate.setHours(0, 0, 0, 0);
    if (isNaN(attendanceDate.getTime())) return res.status(400).json({ error: "Invalid date format" });
    const updatedAttendance = await Attendance.findOneAndUpdate(
      { register: registerNumber, date: attendanceDate },
      { $set: { name, register: registerNumber, status: normalizedStatus, date: attendanceDate, hours } },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    );
    res.json({ message: "Attendance recorded successfully!", data: updatedAttendance });
  } catch (error) {
    res.status(500).json({ error: "Failed to save attendance" });
  }
});

app.get("/api/get-attendance/:registerNumber", async (req, res) => {
  try {
    const registerNumber = req.params.registerNumber.trim();
    const attendanceRecords = await Attendance.find({ register: { $regex: new RegExp(`^${registerNumber}$`, "i") } });
    if (!attendanceRecords.length) return res.status(404).json({ success: false, message: "No attendance records found.", data: [] });
    const totalMeetings = 4;
    const attendedMeetings = attendanceRecords.filter(r => r.status === "present").length;
    const attendancePercentage = ((attendedMeetings / totalMeetings) * 100).toFixed(2);
    const totalHours = attendanceRecords.reduce((sum, r) => sum + r.hours, 0);
    res.json({
      success: true,
      name: attendanceRecords[0].name,
      registerNumber,
      totalMeetings,
      attendedMeetings,
      attendancePercentage,
      totalHours,
      records: attendanceRecords,
      belowMinimum: attendancePercentage < 75
    });
  } catch (error) {
    res.status(500).json({ success: false, error: "Failed to fetch attendance" });
  }
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'frontend', 'home.html'));
});

const PORT = process.env.PORT || 5001;
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
