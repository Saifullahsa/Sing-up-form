import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import pkg from "pg";
const { Pool } = pkg;
import bcrypt from "bcrypt";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
});

// API to register user
app.post("/register", async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: "Email and password required" });
    }

    try {
        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        const result = await pool.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
            [email, hashedPassword]
        );

        res.json({ message: "User registered successfully", user: result.rows[0] });
    } catch (err) {
        console.error(err);
        if (err.code === "23505") {
            res.status(400).json({ error: "Email already exists" });
        } else {
            res.status(500).json({ error: "Server error" });
        }
    }
});

// API to login user
app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: "Email and password required" });
    }

    try {
        const result = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
        const user = result.rows[0];

        if (!user) return res.status(400).json({ error: "User not found" });

        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.status(400).json({ error: "Invalid password" });

        res.json({ message: "Login successful", user: { id: user.id, email: user.email } });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Server error" });
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
