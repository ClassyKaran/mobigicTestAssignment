const express = require("express");
const mongoose = require("mongoose");
const multer = require("multer");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const fs = require("fs");
const path = require("path");
const cors = require("cors");
const dotenv = require("dotenv");

dotenv.config();
const app = express();
const PORT = process.env.PORT || 5000;

// ✅ Enable CORS for frontend
const corsOptions = {
  origin: "http://localhost:3000", // Update if frontend runs elsewhere
  methods: "GET,HEAD,PUT,PATCH,POST,DELETE",
  credentials: true,
  optionsSuccessStatus: 204,
};
app.use(cors(corsOptions));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// ✅ MongoDB connection
mongoose.connect("mongodb://localhost:27017/mobigic_test", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => {
  console.log("Connected to MongoDB");
}).catch(err => {
  console.error("MongoDB connection failed:", err);
});

// ✅ User Schema
const userSchema = new mongoose.Schema({
  username: String,
  password: String,
});
const User = mongoose.model("User", userSchema);

// ✅ File Schema
const fileSchema = new mongoose.Schema({
  filename: String,
  filepath: String,
  uploadedBy: mongoose.Schema.Types.ObjectId,
  code: String,
  uploadedAt: { type: Date, default: Date.now },
});
const File = mongoose.model("File", fileSchema);

// ✅ JWT Authentication Middleware
const authMiddleware = async (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Unauthorized" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: "Invalid token" });
  }
};

// ✅ Multer storage setup
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "uploads/");
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + "-" + file.originalname);
  },
});
const upload = multer({ storage });

// ✅ Register Route
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  const user = new User({ username, password: hashed });
  await user.save();
  res.json({ message: "User registered" });
});

// ✅ Login Route
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user) return res.status(401).json({ error: "User not found" });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(401).json({ error: "Invalid password" });

  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
  res.json({ token });
});

// ✅ File Upload Route
app.post("/upload", authMiddleware, upload.single("file"), async (req, res) => {
  const code = Math.floor(100000 + Math.random() * 900000).toString();
  const file = new File({
    filename: req.file.filename,
    filepath: req.file.path,
    uploadedBy: req.user.id,
    code,
  });
  await file.save();
  res.json({ message: "File uploaded", code });
});

// ✅ Get User Files Route
app.get("/files", authMiddleware, async (req, res) => {
  const files = await File.find({ uploadedBy: req.user.id });
  res.json(files);
});

// ✅ Delete File Route
app.delete("/delete/:id", authMiddleware, async (req, res) => {
  const file = await File.findOne({
    _id: req.params.id,
    uploadedBy: req.user.id,
  });
  if (!file) return res.status(404).json({ error: "File not found" });

  try {
    fs.unlinkSync(file.filepath);
  } catch (err) {
    console.error("Failed to delete file:", err);
  }

  await file.deleteOne();
  res.json({ message: "File deleted" });
});

// ✅ Download File Route
app.post("/download/:id", async (req, res) => {
  const { code } = req.body;
  const file = await File.findById(req.params.id);
  if (!file || file.code !== code)
    return res.status(403).json({ error: "Invalid code" });

  res.download(file.filepath);
});

// ✅ Health Check
app.get("/", (req, res) => {
  res.send(`Server is running on port:${PORT} ...!`);
  console.log("Home Endpoint Hit successfully...!");
});

// ✅ Start server
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
