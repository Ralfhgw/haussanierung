import express from "express";
import jwt from "jsonwebtoken";
import { readFile, writeFile } from "fs/promises";
import bcrypt from "bcrypt";
import cookieParser from "cookie-parser";
import path from "path";
import { fileURLToPath } from "url";
import "bun:dotenv";

declare global {
  namespace Express {
    interface Request {
      user?: any;
    }
  }
}

const PORT = process.env.PORT;
const JWT_SECRET = process.env.JWT_SECRET;

const app = express();

const saltRounds = 10;

if (!PORT || !JWT_SECRET) {
  console.log("You have to set PORT and JWT_SECRET");
  process.exit(1);
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const usersFile = path.join(__dirname, "/src/data", "users.json");

app.use(express.static(path.join(__dirname, "public")));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

function authMiddleware(req: express.Request, res: express.Response, next: express.NextFunction) {
  const header = req.headers.authorization;
  const tokenFromHeader = header && header.startsWith("Bearer ") ? header.slice(7) : undefined;
  const token = ((req as any).cookies?.token as string | undefined) ?? tokenFromHeader;

  console.log("authMiddleware token:", token);

  if (!token) return res.redirect("/login");

  try {
    const payload = jwt.verify(token as string, JWT_SECRET as string);
    (req as any).user = payload;
    next();
  } catch (err: any) {
    console.error("Token validation error:", err);

    res.clearCookie("token");
    return res.redirect("/login");
  }
}

app.get("/", authMiddleware, (req, res) => {
  res.render("index");
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ ok: false, message: "username and password required" });
  }

  try {
    const file = await readFile(usersFile, "utf-8");
    const users = file.trim() ? JSON.parse(file) : [];
    const user = (users as any[]).find((person) =>
      person.username === username
    );

    if (!user) {
      return res.status(401).json({ ok: false, message: "Invalid credentials" });
    }

    if (!user.password || typeof user.password !== "string") {
      console.error("user has no password hash:", user);
      return res.status(500).json({ ok: false, message: "Server error: user has no password hash" });
    }

    let ok = false;
    try {
      ok = await bcrypt.compare(password, user.password);
    } catch (err) {
      console.error("bcrypt.compare error:", err);
      return res.status(500).json({ ok: false, message: "Server error during password check" });
    }

    if (ok) {
         const token = jwt.sign({ sub: user.id, name: user.username }, JWT_SECRET, {
           expiresIn: "10m",
         });
         res.cookie("token", token, { httpOnly: true, sameSite: "lax" });
         return res.redirect("/");
       } else {
         return res.status(401).json({ ok: false, message: "Invalid credentials" });
       }
   } catch (error) {
     console.error("Fehler beim Laden der json Datei", error);
     return res.sendStatus(500);
   }
   return res.json({ received: req.body });
});

app.get("/gallery/:imageId", (req, res) => {
  const { imageId } = req.params;
  console.log("id:", imageId);
  res.render("image-details");
});

app.listen(PORT, () => {
  console.log(`server listening on port ${PORT}`);
});
