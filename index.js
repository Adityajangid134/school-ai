require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { createClient } = require("@supabase/supabase-js");
const twilio = require("twilio");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 5000;

// ✅ Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());

// ✅ Ensure environment variables are set
if (!process.env.SUPABASE_URL || !process.env.SUPABASE_KEY) {
    console.error("❌ ERROR: Supabase credentials are missing!");
    process.exit(1);
}
if (!process.env.TWILIO_SID || !process.env.TWILIO_AUTH_TOKEN || !process.env.TWILIO_PHONE_NUMBER) {
    console.error("❌ ERROR: Twilio credentials are missing!");
    process.exit(1);
}
if (!process.env.JWT_SECRET) {
    console.error("❌ ERROR: JWT secret is missing!");
    process.exit(1);
}

// ✅ Initialize Supabase
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY, {
    auth: { persistSession: false }
});

// ✅ Initialize Twilio
const twilioClient = twilio(process.env.TWILIO_SID, process.env.TWILIO_AUTH_TOKEN);

// ✅ Secret key for JWT
const JWT_SECRET = process.env.JWT_SECRET || "supersecretkey";

// ✅ Store OTPs in-memory (for testing purposes)
const otpStore = {};

// ✅ Authenticate JWT Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers["authorization"];
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({ success: false, error: "Unauthorized: Token required" });
    }
    const token = authHeader.split(" ")[1];
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ success: false, error: "Invalid or expired token" });
        req.user = decoded;
        next();
    });
};

// ✅ Health Check Route
app.get("/", (req, res) => res.json({ message: "✅ Backend is running!" }));

// ✅ Send OTP Route
app.post("/send-otp", async (req, res) => {
    const { phone } = req.body;
    if (!phone) return res.status(400).json({ success: false, error: "Phone number is required" });

    try {
        const otp = Math.floor(100000 + Math.random() * 900000);
        otpStore[phone] = otp;
        await twilioClient.messages.create({
            body: `Your verification code is: ${otp}`,
            from: process.env.TWILIO_PHONE_NUMBER,
            to: phone
        });
        res.json({ success: true, message: "OTP sent successfully" });
    } catch (error) {
        console.error("❌ Error sending OTP:", error);
        res.status(500).json({ success: false, error: "Failed to send OTP" });
    }
});

// ✅ Verify OTP Route
app.post("/verify-otp", async (req, res) => {
    const { phone, otp } = req.body;
    if (!phone || !otp) return res.status(400).json({ success: false, error: "Phone and OTP are required" });

    if (otpStore[phone] && otpStore[phone] == otp) {
        delete otpStore[phone];
        const token = jwt.sign({ phone }, JWT_SECRET, { expiresIn: "24h" });
        res.json({ success: true, message: "OTP verified successfully", token });
    } else {
        res.status(401).json({ success: false, error: "Invalid OTP" });
    }
});

// ✅ Add Student Route
app.post("/add-student", authenticateToken, async (req, res) => {
    console.log("📩 Received request:", req.body);

    const { name, phone, email, class_name, section } = req.body;

    if (!name || !phone || !class_name || !section) {
        return res.status(400).json({ success: false, error: "All required fields must be provided." });
    }

    try {
        // Check if student already exists
        const { data: existingStudent, error: checkError } = await supabase
            .from("students")
            .select("*")
            .or(`phone.eq.${phone},email.eq.${email}`)
            .single();

        if (existingStudent) {
            return res.status(409).json({ success: false, error: "Student with this phone or email already exists" });
        }

        if (checkError && checkError.code !== "PGRST116") {
            console.error("❌ Error checking existing student:", checkError);
            return res.status(500).json({ success: false, error: "Database error" });
        }

        // Insert new student (id is auto-generated)
        const { data, error } = await supabase
            .from("students")
            .insert([{ name, phone, email, class_name, section }]);

        if (error) {
            console.error("❌ Error adding student:", error);
            return res.status(500).json({ success: false, error: "Database error", details: error.message });
        }

        res.json({ success: true, message: "✅ Student added successfully", data });
    } catch (error) {
        console.error("❌ Server error:", error);
        res.status(500).json({ success: false, error: "Internal server error" });
    }
});

// ✅ Start Server
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
