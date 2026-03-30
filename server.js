const express = require("express");
const fs = require("fs/promises");
const path = require("path");
const bcrypt = require("bcrypt");

const app = express();
const PORT = 3000;

const ROOT_DIR = __dirname;
const SAVES_DIR = path.join(ROOT_DIR, "saves");
const USERS_FILE = path.join(SAVES_DIR, "users.json");

app.use(express.json());
app.use(express.static(ROOT_DIR));

function isValidUsername(username) {
    return /^[a-zA-Z0-9_-]+$/.test(username);
}

async function ensureStorage() {
    await fs.mkdir(SAVES_DIR, { recursive: true });

    try {
        await fs.access(USERS_FILE);
    } catch {
        await fs.writeFile(USERS_FILE, "[]", "utf8");
    }
}

async function readUsers() {
    await ensureStorage();
    const raw = await fs.readFile(USERS_FILE, "utf8");
    return JSON.parse(raw);
}

async function writeUsers(users) {
    await fs.writeFile(USERS_FILE, JSON.stringify(users, null, 2), "utf8");
}

app.get("/api/check-username", async (req, res) => {
    try {
        const username = String(req.query.username || "").trim();

        if (!username) {
            return res.status(400).json({ error: "Username is required." });
        }

        if (!isValidUsername(username)) {
            return res.status(400).json({ error: "Invalid username format." });
        }

        const users = await readUsers();
        const exists = users.some(user => user.username === username);

        return res.json({ exists });
    } catch (error) {
        console.error("check-username error:", error);
        return res.status(500).json({ error: "Server error while checking username." });
    }
});

app.post("/api/create-account", async (req, res) => {
    try {
        const username = String(req.body.username || "").trim();
        const password = String(req.body.password || "");

        if (!username) {
            return res.status(400).json({ error: "Username is required." });
        }

        if (!isValidUsername(username)) {
            return res.status(400).json({
                error: "Username must only consist of letters, numbers, _ and -."
            });
        }

        if (password.length < 6) {
            return res.status(400).json({ error: "Password must contain 6+ characters." });
        }

        const users = await readUsers();

        if (users.some(user => user.username === username)) {
            return res.status(409).json({ error: "Username is already taken." });
        }

        const passwordHash = await bcrypt.hash(password, 10);

        users.push({
            username,
            passwordHash,
            createdAt: new Date().toISOString()
        });

        await writeUsers(users);

        const userDir = path.join(SAVES_DIR, username);
        await fs.mkdir(userDir, { recursive: true });

        await fs.writeFile(
            path.join(userDir, "profile.json"),
            JSON.stringify(
                {
                    username,
                    createdAt: new Date().toISOString()
                },
                null,
                2
            ),
            "utf8"
        );

        return res.status(201).json({ ok: true });
    } catch (error) {
        console.error("create-account error:", error);
        return res.status(500).json({ error: "Server error while creating account." });
    }
});

app.post("/api/login", async (req, res) => {
    try {
        const username = String(req.body.username || "").trim();
        const password = String(req.body.password || "");

        if (!username || !password) {
            return res.status(400).json({ error: "Username and password are required." });
        }

        const users = await readUsers();
        const user = users.find(u => u.username === username);

        if (!user) {
            return res.status(401).json({ error: "Invalid username or password." });
        }

        const ok = await bcrypt.compare(password, user.passwordHash);

        if (!ok) {
            return res.status(401).json({ error: "Invalid username or password." });
        }

        return res.json({ ok: true });
    } catch (error) {
        console.error("login error:", error);
        return res.status(500).json({ error: "Server error while logging in." });
    }
});

app.listen(PORT, async () => {
    await ensureStorage();
    console.log(`Server running on http://localhost:${PORT}`);
});