
import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import mongoose from "mongoose";

const router = express.Router();

// =====================
// 🧠 Esquema del Usuario
// =====================
const userSchema = new mongoose.Schema({
  nombre: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  telefono: { type: String },
  idUniversitario: { type: String },
  role: { type: String, enum: ["pasajero", "conductor"], default: "pasajero" },
});

const User = mongoose.model("User", userSchema);

// =====================
// 🧍‍♀️ Registro de usuario - CORREGIDO
// =====================
router.post("/register", async (req, res) => {
  try {
    const { nombre, email, password, telefono, idUniversitario, role } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser)
      return res.status(400).json({ error: "El correo ya está registrado" });

    const hashedPassword = await bcrypt.hash(password, 10);
    
    // ✅ CORRECCIÓN: Usar todos los campos
    const newUser = new User({ 
      nombre, 
      email, 
      password: hashedPassword, 
      telefono,        // ✅ Ahora se guarda
      idUniversitario, // ✅ Ahora se guarda
      role 
    });
    
    await newUser.save();

    res.status(201).json({ message: "Usuario registrado correctamente" });
  } catch (error) {
    console.error("Error al registrar usuario:", error);
    res.status(500).json({ error: "Error al registrar el usuario" });
  }
});

// =====================
// 🔐 Inicio de sesión
// =====================
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user)
      return res.status(404).json({ error: "Usuario no encontrado" });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword)
      return res.status(401).json({ error: "Contraseña incorrecta" });

    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "2h" }
    );

    res.json({
      message: "Inicio de sesión exitoso",
      token,
      role: user.role,
      nombre: user.nombre,
    });
  } catch (error) {
    console.error("Error en login:", error);
    res.status(500).json({ error: "Error al iniciar sesión" });
  }
});

export default router;