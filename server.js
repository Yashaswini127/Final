require('dotenv').config(); // Load environment vriables
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const bodyParser = require('body-parser');
const QRCode = require('qrcode');
const { register } = require('module');
const session = require('express-session'); 
const cookieParser = require('cookie-parser');

const { Parser } = require('json2csv');


const app = express();

const allowedOrigins = [
  "http://localhost:5001", // for local dev
  "https://final-2-30iu.onrender.com" // your frontend live URL
];

app.use(cors({
  origin: function(origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS"));
    }
  },
  credentials: true
}));

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors({
    origin: "http://localhost:5001", // Change to your frontend URL if different
    credentials: true
}));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'frontend')));
app.use(cookieParser());


// Session Configuration
app.use(session({
    secret: process.env.JWT_SECRET || 'secretkey',
    resave: false,
    saveUninitialized: false, // Don't create session until something is stored
    cookie: { secure: false, httpOnly: true } // Set `secure: true` in production
}));

// MongoDB Connection
const MONGO_URI = process.env.MONGO_URI || "mongodb+srv://Jet-Club:JETClub2025@cluster0.u7mfy.mongodb.net/"; // Use environment variable
mongoose.connect(MONGO_URI)
    .then(() => console.log("✅ MongoDB Connected"))
    .catch(err => console.error("❌ MongoDB Connection Failed:", err));

// Define User Schema
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, unique: true, required: true },
    password: { type: String, required: true },
    role: { type: String, default: 'user' },
    contact: { type: String },
    register:{ type: String, unique: true, required: true },
   
});

const User = mongoose.model('User', userSchema);

const attendanceSchema = new mongoose.Schema({
    name: { type: String, required: true }, 
    register: { type: String, required: true, ref: "User" }, 
    date: { type: Date, required: true },
    status: { type: String, enum: ["present", "absent"], required: true },
    hours: { type: Number, required: true, min: 0 } // Hours attended in that session
  });
  
  const Attendance = mongoose.model("Attendance", attendanceSchema); // Attendance Collection
  module.exports = { Attendance};


  const usedSessions = new Set();

// ✅ Authentication Middleware
const authenticateUser = (req, res, next) => {
    const token = req.header('Authorization');
    if (!token) return res.status(401).json({ error: "Access denied. No token provided." });

    try {
        const decoded = jwt.verify(token.replace('Bearer ', ''), process.env.JWT_SECRET || 'secretkey');
        req.user = decoded;
        next();
    } catch (err) {
        res.status(400).json({ error: "Invalid token." });
    }
};

// ✅ Register Route
app.post("/register", async (req, res) => {
    console.log("📩 Received registration request with data:", req.body);

    const { name, contact, email, register,role, password } = req.body;

    if (!email) {
        console.log("❌ Error: Email is missing");
        return res.status(400).json({ error: "Email is required" });
    }

    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\W).{8,}$/;
    
    if (!passwordRegex.test(password)) {
        return res.status(400).json({ 
            error: "Password must have at least 1 uppercase letter, 1 lowercase letter, 1 special character, and be at least 8 characters long." 
        });
    }

    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: "User already exists" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        // ✅ Save user using Mongoose
        const newUser = new User({
            name,
            contact,
            email,
            register,
            role,
            password: hashedPassword
        });

        await newUser.save();
        console.log("✅ User registered successfully!");
        res.status(201).json({ message: "User registered successfully" });

    } catch (error) {
        console.error("❌ Registration error:", error);
        res.status(500).json({ error: "Server error" });
    }
});

// ✅ Login Route
app.post("/login2", async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email });

        if (!user) {
            console.log("❌ Login Failed: User not found");
            return res.status(401).json({ error: "User not found" });
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            console.log("❌ Login Failed: Invalid password for", email);
            return res.status(401).json({ error: "Invalid password" });
        }

        // Store user session securely
        req.session.user = { register: user.register, role: user.role, name: user.name };
        console.log("✅ Session Data After Login:", req.session.user);

        // Prepare response data
        const responseData = {
            message: "Login successful",
            registerNumber: user.register, // Added register number
            role: user.role,
            redirect: user.role.toLowerCase() === "admin" ? "/admin.html" : "/attendance.html"
        };

        return res.json(responseData);
    } catch (error) {
        console.error("❌ Login Error:", error);
        res.status(500).json({ error: "Server error" });
    }
});

const requireAdmin = (req, res, next) => {
    if (!req.session.user || req.session.user.role !== "admin") {
        return res.status(403).json({ error: "Access denied. Admins only." });
    }
    next();
};

app.post("/add-admin", async (req, res) => {
    try {
      if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).send("successfull!.");
      }
  
      const { name, register, password } = req.body;
  
      if (!name || !register || !password) {
        return res.status(400).send("Missing required fields");
      }
  
      const existingUser = await User.findOne({ register });
      if (existingUser) {
        return res.status(409).send("User already exists");
      }
  
      const hashedPassword = await bcrypt.hash(password, 10);
  
      const newAdmin = new User({
        name,
        register,
        password: hashedPassword,
        role: "admin"
      });
  
      await newAdmin.save();
      res.status(201).send("Admin created successfully");
    } catch (error) {
      console.error("🔥 ERROR creating admin:", error); // <-- check this in your terminal
      res.status(500).send("Admin created successfully");
    }
  });
  
  
app.get("/admin", async (req, res) => {
    console.log("📌 Session Data in /admin Route:", req.session);

    if (!req.session.user) {
        console.log("❌ No session found!");
        return res.status(403).json({ message: "Unauthorized" });
    }

    const user = await User.findOne({ register: req.session.user.register });

    if (!user) {
        console.log("❌ User not found in database");
        return res.status(403).json({ message: "User not found" });
    }

    if (user.role.toLowerCase() === "admin") {
        console.log("✅ Admin access granted:", user.name);
        return res.json({ isAdmin: true, name: user.name });
    } else {
        console.log("❌ Access denied: Not an admin");
        return res.status(403).json({ message: "You must be an admin to view this page" });
    }
});

// ✅ Generate Secure QR Code for Attendance
const crypto = require("crypto");

const router = express.Router();

app.get("/api/generate-qr", async (req, res) => {
    try {
        const googleFormLink = "https://docs.google.com/forms/d/e/1FAIpQLSeE7rx-jCRTrUdbWeNoHi88zP3qawjv2ThImrHh_ql97RD0Lw/viewform?usp=header"; // Replace with your actual form link
        const qrCodeDataURL = await QRCode.toDataURL(googleFormLink);
        res.json({ qrCode: qrCodeDataURL });
    } catch (error) {
        console.error("QR Code generation failed:", error);
        res.status(500).json({ error: "QR generation failed" });
    }
});

app.get('/admin/download-attendance', async (req, res) => {
    try {
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
      console.error("Error generating CSV:", error);
      res.status(500).json({ error: "Failed to generate CSV." });
    }
  });
 
// ✅ Prevent Multiple Scans

    const axios = require('axios');

app.post("/api/save-attendance", async (req, res) => {
        try {
            console.log("📥 Received data:", req.body);
    
            const { name, registerNumber, status, date } = req.body;
    
            // ✅ Normalize status (case insensitive)
            const normalizedStatus = status.toLowerCase() === "present" ? "present" : "absent";
    
            // ✅ Automatically assign hours
            const hours = normalizedStatus === "present" ? 1 : 0;
    
            // ✅ Validate and normalize date
            let attendanceDate = date ? new Date(date) : new Date();
            attendanceDate.setHours(0, 0, 0, 0); // Ensure consistent date storage
    
            if (isNaN(attendanceDate.getTime())) {
                return res.status(400).json({ error: "Invalid date format" });
            }
            // ✅ Use $set to properly update existing records
            const updatedAttendance = await Attendance.findOneAndUpdate(
                { register: registerNumber, date: attendanceDate }, // Find by register and date
                { $set: { name, register: registerNumber, status: normalizedStatus, date: attendanceDate, hours } }, // ✅ Ensure fields are properly updated
                { upsert: true, new: true, setDefaultsOnInsert: true } // ✅ Upsert & set defaults
            );
    
            console.log("✅ Attendance recorded successfully:", updatedAttendance);
            res.json({ message: "Attendance recorded successfully!", data: updatedAttendance });
        } catch (error) {
            console.error("❌ Error saving attendance:", error.message);
            res.status(500).json({ error: "Failed to save attendance", details: error.message });
        }
});
    
            
            

app.get("/api/get-attendance/:registerNumber", async (req, res) => {
    try {
        const registerNumber = req.params.registerNumber.trim();
        console.log(`🔍 Fetching attendance for: ${registerNumber}`);

        // Fetch attendance records for the user
        const attendanceRecords = await Attendance.find({ 
            register: { $regex: new RegExp(`^${registerNumber}$`, "i") } // Case-insensitive match
        });
        

        if (!attendanceRecords || attendanceRecords.length === 0) {
            console.log("❌ No attendance records found.");
            return res.status(404).json({ 
                success: false, 
                message: "No attendance records found.", 
                data: [] 
            });
        }

        // Count total meetings dynamically (or keep 4 if fixed)
        const totalMeetings = 4; // Fixed to 4 meetings per month


        // Count attended meetings
        const attendedMeetings = attendanceRecords.filter(record => record.status === "present").length;

        // Calculate attendance percentage
        const attendancePercentage = ((attendedMeetings / totalMeetings) * 100).toFixed(2);

        // Calculate total hours attended
        const totalHours = attendanceRecords.reduce((sum, record) => sum + record.hours, 0);

        // Determine if attendance is below 75%
        const belowMinimum = attendancePercentage < 75;

        // ✅ Explicitly set JSON response type
        res.setHeader("Content-Type", "application/json");

        // ✅ Send response
        res.json({
            success: true,
            name: attendanceRecords[0].name,
            registerNumber,
            totalMeetings,
            attendedMeetings,
            attendancePercentage,
            totalHours,
            records: attendanceRecords,
            belowMinimum
        });

        console.log(`✅ Attendance data sent successfully for ${registerNumber}`);
    } catch (error) {
        console.error("❌ Error fetching attendance:", error.message);
        res.status(500).json({ 
            success: false, 
            error: "Failed to fetch attendance", 
            details: error.message 
        });
    }
});

// ✅ Serve Frontend
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'frontend', 'home.html'));
});

// ✅ Start the Server
const PORT = process.env.PORT || 5001;
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
