// server.js - VERSIÓN COMPLETA CON DEBUG
import express from "express";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

dotenv.config();

const app = express();

// ✅ CORS CORREGIDO - Soporta desarrollo y producción
const allowedOrigins = [
  "http://localhost:5173",
  "http://localhost:3000",
  // Dominios de despliegue conocidos
  "https://wheells-fronted-3e3b.vercel.app",
  process.env.FRONTEND_URL
].filter(Boolean); // Elimina valores undefined

app.use((req, res, next) => {
  const origin = req.headers.origin;

  // Log básico del origen
  if (origin) {
    console.log("Solicitud desde origen:", origin);
  }

  // Permitir origen si está en la lista o si estamos en desarrollo
  // También permite previews de Vercel del proyecto 'wheells-fronted-3e3b'
  const isVercelPreview = !!(origin && /^https:\/\/wheells-fronted-3e3b[\w-]*\.vercel\.app$/.test(origin));
  if (origin && (allowedOrigins.includes(origin) || isVercelPreview || process.env.NODE_ENV !== "production")) {
    res.header("Access-Control-Allow-Origin", origin);
  }

  res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  res.header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With");
  res.header("Access-Control-Allow-Credentials", "true");

  // Manejar preflight requests
  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  next();
});

app.use(express.json());

// =====================
// 🗃️ BASE DE DATOS EN MEMORIA
// =====================
let users = [];
let nextId = 1;

// Utilidades JWT
const JWT_SECRET = process.env.JWT_SECRET || "claveultrasegura";
function signAppToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "2h" });
}

// Middleware auth simple
function authRequired(req, res, next) {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Token requerido" });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (e) {
    return res.status(401).json({ error: "Token inválido" });
  }
}

// =====================
// 🧪 RUTA DE PRUEBA
// =====================
app.get("/api/test", (req, res) => {
  res.json({ 
    message: "✅ Backend funcionando correctamente",
    timestamp: new Date().toISOString(),
    usersCount: users.length
  });
});

// =====================
// 🧍‍♀️ Registro de usuario - CON DEBUG COMPLETO
// =====================
app.post("/api/auth/register", async (req, res) => {
  try {
    // ✅ DEBUG COMPLETO - DETALLE DE CAMPOS
    console.log("=== 🐛 DEBUG REGISTRO ===");
    console.log("Body completo:", JSON.stringify(req.body, null, 2));
    console.log("--- Campos individuales ---");
    console.log("name:", req.body.name, "- Tipo:", typeof req.body.name, "- Vacío?", !req.body.name);
    console.log("email:", req.body.email, "- Tipo:", typeof req.body.email, "- Vacío?", !req.body.email);
    console.log("password:", req.body.password, "- Tipo:", typeof req.body.password, "- Vacío?", !req.body.password);
    console.log("telefono:", req.body.telefono, "- Tipo:", typeof req.body.telefono, "- Vacío?", !req.body.telefono);
    console.log("idUniversitario:", req.body.idUniversitario, "- Tipo:", typeof req.body.idUniversitario, "- Vacío?", !req.body.idUniversitario);
    console.log("role:", req.body.role, "- Tipo:", typeof req.body.role, "- Vacío?", !req.body.role);
    
    // Verificar campos obligatorios
    const camposRequeridos = ['name', 'email', 'password'];
    const camposVacios = camposRequeridos.filter(campo => !req.body[campo] || req.body[campo].toString().trim() === '');
    
    if (camposVacios.length > 0) {
      console.log("❌ CAMPOS VACÍOS DETECTADOS:", camposVacios);
      return res.status(400).json({ error: "Todos los campos obligatorios deben estar completos" });
    }

    // ✅ CONVERTIR 'name' A 'nombre'
    const { name, email, password, telefono, idUniversitario, role } = req.body;
    const nombre = name;

    console.log("✅ Todos los campos OK, procediendo con registro...");

    // Verificar si el usuario ya existe
    const existingUser = users.find(user => user.email === email);
    if (existingUser) {
      console.log("❌ Usuario ya existe:", email);
      return res.status(400).json({ error: "El correo ya está registrado" });
    }

    // Hashear contraseña
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Crear nuevo usuario en estado de onboarding pendiente
    const initialRole = role === "conductor" ? "conductor" : "pasajero";
    const newUser = {
      id: nextId++,
      nombre,
      email,
      password: hashedPassword,
      telefono: telefono || "",
      idUniversitario: idUniversitario || "",
      rolesCompleted: { pasajero: false, conductor: false },
      currentRole: null,
      status: "pending", // pending hasta completar al menos un rol
      preferredRole: initialRole
    };
    
    users.push(newUser);
    console.log("✅ Usuario registrado exitosamente:", newUser.email);
    console.log("📊 Total de usuarios registrados:", users.length);

    const onboardingToken = signAppToken({ id: newUser.id, onboarding: true });
    const nextRoute = initialRole === "conductor" ? "/register-driver-vehicle" : "/register-photo";

    res.status(201).json({ 
      message: "Registro iniciado. Completa el onboarding ✅",
      onboardingToken,
      nextRoute,
      preferredRole: initialRole
    });
  } catch (error) {
    console.error("❌ Error al registrar usuario:", error);
    res.status(500).json({ error: "Error al registrar el usuario" });
  }
});

// =====================
// 🔐 Inicio de sesión
// =====================
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    console.log("🔐 Intento de login:", email);

    const user = users.find(u => u.email === email);
    if (!user) {
      console.log("❌ Usuario no encontrado:", email);
      return res.status(404).json({ error: "Usuario no encontrado" });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      console.log("❌ Contraseña incorrecta para:", email);
      return res.status(401).json({ error: "Contraseña incorrecta" });
    }

    // Si no tiene ningún rol completado, bloquear y enviar señal de onboarding
    const hasAnyRole = user.rolesCompleted?.pasajero || user.rolesCompleted?.conductor;
    if (!hasAnyRole) {
      return res.status(403).json({
        error: "Onboarding incompleto",
        needOnboarding: true,
        preferredRole: user.preferredRole || "pasajero",
        nextRoute: (user.preferredRole === "conductor") ? "/register-driver-vehicle" : "/register-photo"
      });
    }

    const effectiveRole = user.currentRole || (user.rolesCompleted.conductor ? "conductor" : "pasajero");
    user.currentRole = effectiveRole;

    const token = signAppToken({ id: user.id, role: effectiveRole });

    console.log("✅ Login exitoso:", email);

    res.json({
      message: "Inicio de sesión exitoso ✅",
      token,
      role: effectiveRole,
      nombre: user.nombre,
      userId: user.id
    });
  } catch (error) {
    console.error("❌ Error en login:", error);
    res.status(500).json({ error: "Error al iniciar sesión" });
  }
});

// =====================
// 🚀 Onboarding Pasajero
// =====================
app.post("/api/onboarding/pasajero", authRequired, async (req, res) => {
  try {
    const user = users.find(u => u.id === req.user.id);
    if (!user) return res.status(404).json({ error: "Usuario no encontrado" });

    user.rolesCompleted.pasajero = true;
    user.status = "active";
    if (!user.currentRole) user.currentRole = "pasajero";

    return res.json({
      message: "Onboarding de pasajero completado ✅",
      rolesCompleted: user.rolesCompleted,
      currentRole: user.currentRole
    });
  } catch (e) {
    console.error("❌ Error en onboarding pasajero:", e);
    return res.status(500).json({ error: "Error en onboarding" });
  }
});

// =====================
// 🚀 Onboarding Conductor
// =====================
app.post("/api/onboarding/conductor", authRequired, async (req, res) => {
  try {
    const user = users.find(u => u.id === req.user.id);
    if (!user) return res.status(404).json({ error: "Usuario no encontrado" });

    user.rolesCompleted.conductor = true;
    user.status = "active";
    if (!user.currentRole) user.currentRole = "conductor";

    return res.json({
      message: "Onboarding de conductor completado ✅",
      rolesCompleted: user.rolesCompleted,
      currentRole: user.currentRole
    });
  } catch (e) {
    console.error("❌ Error en onboarding conductor:", e);
    return res.status(500).json({ error: "Error en onboarding" });
  }
});

// =====================
// 👤 Datos del usuario actual
// =====================
app.get("/api/user/me", authRequired, (req, res) => {
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: "Usuario no encontrado" });
  return res.json({
    id: user.id,
    nombre: user.nombre,
    email: user.email,
    rolesCompleted: user.rolesCompleted,
    currentRole: user.currentRole,
    status: user.status
  });
});

// =====================
// 🔄 Cambiar rol actual (si está completado)
// =====================
app.put("/api/user/role", authRequired, (req, res) => {
  const { role } = req.body;
  if (role !== "pasajero" && role !== "conductor") {
    return res.status(400).json({ error: "Rol inválido" });
  }
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: "Usuario no encontrado" });
  if (!user.rolesCompleted[role]) {
    return res.status(400).json({ error: "Debes completar el onboarding de este rol" });
  }
  user.currentRole = role;
  const token = signAppToken({ id: user.id, role: user.currentRole });
  return res.json({ message: "Rol cambiado ✅", role: user.currentRole, token });
});

// =====================
// 🧭 Ruta inicial
// =====================
app.get("/", (req, res) => {
  res.send("🚗 Servidor Wheels funcionando correctamente 🚀");
});

// =====================
// 🧨 Iniciar servidor
// =====================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🔥 Servidor escuchando en puerto ${PORT}`);
  console.log(`🗃️ Usando base de datos en memoria`);
  console.log(`🌐 CORS permitido para: ${allowedOrigins.join(', ')}`);
  console.log(`📡 Endpoint de prueba: http://localhost:${PORT}/api/test`);
});