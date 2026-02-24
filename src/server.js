import "dotenv/config";
import express from "express";
import authRoutes from "./routes/auth.routes.js";

const app = express();
app.use(express.json());

app.get("/", (req, res) => res.json({ status: "ok" }));

app.use("/auth", authRoutes);

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server running on port ${port}`));