// server.js - VERSIÓN COMPLETA CON DEBUG
import express from "express";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import mongoose from "mongoose";
import User from "./models/User.js";
import Trip from "./models/Trip.js";
import Message from "./models/Message.js";

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

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// =====================
// 🛡️ Seguridad básica (headers tipo Helmet)
// =====================
app.use((req, res, next) => {
  // Protecciones comunes
  res.setHeader("X-DNS-Prefetch-Control", "off");
  res.setHeader("X-Frame-Options", "SAMEORIGIN");
  res.setHeader("Strict-Transport-Security", "max-age=15552000; includeSubDomains");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Download-Options", "noopen");
  res.setHeader("X-Permitted-Cross-Domain-Policies", "none");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("X-XSS-Protection", "0");
  next();
});

// =====================
// 🚦 Rate limiting por IP (sin dependencias)
// =====================
const RATE_WINDOW_MS = 60_000; // 1 minuto
const RATE_MAX = 100; // 100 req/min por IP (global simple)
const RATE_MAX_AUTH = 30; // 30 req/min para /api/auth/* (más permisivo para login)
const ipHits = new Map();
const authHits = new Map(); // Rate limiter separado para auth

function rateLimiter(maxPerWindow) {
  return (req, res, next) => {
    const ip = req.headers["x-forwarded-for"]?.toString().split(",")[0].trim() || req.socket.remoteAddress || "unknown";
    const now = Date.now();
    const entry = ipHits.get(ip) || { count: 0, resetAt: now + RATE_WINDOW_MS };
    if (now > entry.resetAt) {
      entry.count = 0;
      entry.resetAt = now + RATE_WINDOW_MS;
    }
    entry.count += 1;
    ipHits.set(ip, entry);
    if (entry.count > maxPerWindow) {
      res.setHeader("Retry-After", Math.ceil((entry.resetAt - now) / 1000).toString());
      return res.status(429).json({ 
        error: "Demasiadas solicitudes, intenta más tarde",
        retryAfter: Math.ceil((entry.resetAt - now) / 1000)
      });
    }
    next();
  };
}

// Rate limiter específico para auth (más permisivo)
function authRateLimiter(maxPerWindow) {
  return (req, res, next) => {
    const ip = req.headers["x-forwarded-for"]?.toString().split(",")[0].trim() || req.socket.remoteAddress || "unknown";
    const now = Date.now();
    const entry = authHits.get(ip) || { count: 0, resetAt: now + RATE_WINDOW_MS };
    if (now > entry.resetAt) {
      entry.count = 0;
      entry.resetAt = now + RATE_WINDOW_MS;
    }
    entry.count += 1;
    authHits.set(ip, entry);
    if (entry.count > maxPerWindow) {
      const retryAfter = Math.ceil((entry.resetAt - now) / 1000);
      res.setHeader("Retry-After", retryAfter.toString());
      return res.status(429).json({ 
        error: "Demasiados intentos de inicio de sesión. Por favor espera un momento.",
        message: `Intenta de nuevo en ${retryAfter} segundos`,
        retryAfter: retryAfter
      });
    }
    next();
  };
}

// Global suave
app.use(rateLimiter(RATE_MAX));

// =====================
// 🗃️ CONEXIÓN A MONGODB
// =====================
const MONGODB_URI = process.env.MONGODB_URI;
if (!MONGODB_URI) {
  console.warn("⚠️  MONGODB_URI no está definido. Configúralo en variables de entorno.");
}

// Función para conectar a MongoDB
async function connectToMongoDB() {
  try {
    const uri = MONGODB_URI || "mongodb://127.0.0.1:27017/wheells";
    console.log("🔌 Intentando conectar a MongoDB...");
    console.log("🔌 URI:", uri.replace(/\/\/.*@/, '//***:***@')); // Ocultar credenciales en logs
    
    await mongoose.connect(uri, { 
      dbName: "wheells",
      serverSelectionTimeoutMS: 10000, // Aumentado a 10 segundos
      socketTimeoutMS: 45000,
    });
    
    console.log("✅ Conectado a MongoDB exitosamente");
    console.log("✅ Base de datos:", mongoose.connection.db.databaseName);
    console.log("✅ Estado de conexión:", mongoose.connection.readyState);
    return true;
  } catch (err) {
    console.error("❌ Error conectando a MongoDB:", err.message);
    console.error("❌ Error completo:", err);
    return false;
  }
}

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
app.get("/api/test", async (req, res) => {
  try {
    const usersCount = await User.countDocuments();
    res.json({ 
      message: "✅ Backend funcionando correctamente",
      timestamp: new Date().toISOString(),
      usersCount
    });
  } catch (e) {
    res.json({ message: "✅ Backend funcionando, sin DB count", timestamp: new Date().toISOString() });
  }
});

// =====================
// 🧍‍♀️ Registro de usuario - CON DEBUG COMPLETO
// =====================
app.post("/api/auth/register", authRateLimiter(RATE_MAX_AUTH), async (req, res) => {
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
    
    // ✅ CONVERTIR 'name' A 'nombre' - Primero desestructurar
    const { name, email, password, telefono, idUniversitario, role } = req.body;
    const nombre = name;
    
    // Verificar campos obligatorios
    const camposRequeridos = ['name', 'email', 'password'];
    const camposVacios = camposRequeridos.filter(campo => !req.body[campo] || req.body[campo].toString().trim() === '');
    
    if (camposVacios.length > 0) {
      console.log("❌ CAMPOS VACÍOS DETECTADOS:", camposVacios);
      return res.status(400).json({ error: "Todos los campos obligatorios deben estar completos" });
    }

    // ✅ Validaciones básicas
    const isValidEmail = (v) => /.+@.+\..+/.test(v);
    const isValidPassword = (v) => typeof v === 'string' && v.length >= 6;

    if (!isValidEmail(email)) return res.status(400).json({ error: "Email inválido" });
    if (!isValidPassword(password)) return res.status(400).json({ error: "La contraseña debe tener al menos 6 caracteres" });

    console.log("✅ Todos los campos OK, procediendo con registro...");

    // Verificar conexión a MongoDB (el servidor solo inicia si MongoDB está conectado, pero verificamos por seguridad)
    if (mongoose.connection.readyState !== 1) {
      console.error("❌ MongoDB no está conectado. Estado:", mongoose.connection.readyState);
      console.error("❌ Estados posibles: 0=desconectado, 1=conectado, 2=conectando, 3=desconectando");
      return res.status(503).json({ 
        error: "Servicio de base de datos no disponible",
        message: "Por favor, intenta de nuevo en unos momentos"
      });
    }

    // Verificar si el usuario ya existe
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      console.log("❌ Usuario ya existe:", email);
      return res.status(400).json({ error: "El correo ya está registrado" });
    }

    // Hashear contraseña
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Crear nuevo usuario en estado de onboarding pendiente
    const initialRole = role === "conductor" ? "conductor" : "pasajero";
    
    const newUser = await User.create({
      nombre,
      email,
      password: hashedPassword,
      telefono: telefono || "",
      idUniversitario: idUniversitario || "",
      rolesCompleted: { pasajero: false, conductor: false },
      currentRole: null,
      status: "pending",
      preferredRole: initialRole
    });

    console.log("✅ Usuario registrado exitosamente:", newUser.email);

    const onboardingToken = signAppToken({ id: newUser._id.toString(), onboarding: true });
    const nextRoute = initialRole === "conductor" ? "/register-driver-vehicle" : "/register-photo";

    res.status(201).json({ 
      message: "Registro iniciado. Completa el onboarding ✅",
      onboardingToken,
      nextRoute,
      preferredRole: initialRole
    });
  } catch (error) {
    console.error("❌ Error al registrar usuario:", error);
    console.error("❌ Error name:", error.name);
    console.error("❌ Error message:", error.message);
    console.error("❌ Stack trace:", error.stack);
    
    // Manejar errores específicos de MongoDB
    if (error.name === 'MongoServerError' && error.code === 11000) {
      return res.status(400).json({ error: "El correo ya está registrado" });
    }
    if (error.name === 'ValidationError') {
      return res.status(400).json({ 
        error: "Error de validación",
        message: error.message 
      });
    }
    
    res.status(500).json({ 
      error: "Error al registrar el usuario",
      message: error.message || "Error desconocido",
      errorType: error.name || "Unknown",
      details: process.env.NODE_ENV === "development" ? error.stack : undefined
    });
  }
});

// =====================
// 🔐 Inicio de sesión
// =====================
app.post("/api/auth/login", authRateLimiter(RATE_MAX_AUTH), async (req, res) => {
  const startTime = Date.now();
  try {
    const { email, password } = req.body;
    
    // Validaciones básicas
    if (!email || !password) {
      return res.status(400).json({ error: "Email y contraseña son requeridos" });
    }
    
    const isValidEmail = (v) => /.+@.+\..+/.test(v);
    if (!isValidEmail(email)) {
      return res.status(400).json({ error: "Email inválido" });
    }

    console.log("🔐 Intento de login:", email);

    // Verificar conexión a MongoDB
    if (mongoose.connection.readyState !== 1) {
      console.error("❌ MongoDB no está conectado. Estado:", mongoose.connection.readyState);
      return res.status(503).json({ 
        error: "Servicio de base de datos no disponible",
        message: "Por favor, intenta de nuevo en unos momentos"
      });
    }

    // Optimización: Solo seleccionar campos necesarios para mejorar rendimiento
    const normalizedEmail = email.trim().toLowerCase();
    const queryStart = Date.now();
    const user = await User.findOne({ email: normalizedEmail })
      .select('password nombre rolesCompleted currentRole preferredRole _id')
      .lean(); // Usar lean() para obtener objeto plano más rápido
    
    if (!user) {
      console.log("❌ Usuario no encontrado:", email);
      return res.status(404).json({ error: "Usuario no encontrado" });
    }
    console.log(`⏱️ Query DB: ${Date.now() - queryStart}ms`);

    // Verificar contraseña
    const bcryptStart = Date.now();
    const validPassword = await bcrypt.compare(password, user.password);
    console.log(`⏱️ Bcrypt compare: ${Date.now() - bcryptStart}ms`);
    
    if (!validPassword) {
      console.log("❌ Contraseña incorrecta para:", email);
      return res.status(401).json({ error: "Contraseña incorrecta" });
    }

    // Si no tiene ningún rol completado, NO permitir login
    const hasPasajero = user.rolesCompleted?.pasajero || false;
    const hasConductor = user.rolesCompleted?.conductor || false;
    
    if (!hasPasajero && !hasConductor) {
      return res.status(403).json({
        error: "Debes completar el registro primero. Completa el onboarding de al menos un rol antes de iniciar sesión.",
        needOnboarding: true,
        mustCompleteRegistration: true
      });
    }

    // Determinar el rol efectivo basado en el rol actual o el primer rol completado
    let effectiveRole;
    if (user.currentRole && ((user.currentRole === "pasajero" && hasPasajero) || (user.currentRole === "conductor" && hasConductor))) {
      // Si tiene un currentRole válido y completado, usarlo
      effectiveRole = user.currentRole;
    } else if (hasPasajero && hasConductor) {
      // Si tiene ambos, usar el preferredRole o el primero disponible
      effectiveRole = user.preferredRole || (hasPasajero ? "pasajero" : "conductor");
    } else if (hasPasajero) {
      effectiveRole = "pasajero";
    } else if (hasConductor) {
      effectiveRole = "conductor";
    } else {
      // Esto no debería pasar por el check anterior, pero por seguridad
      return res.status(403).json({
        error: "No tienes ningún rol completado. Completa el onboarding primero.",
        needOnboarding: true,
        mustCompleteRegistration: true
      });
    }

    // Optimización: Solo actualizar si es necesario y usar updateOne en lugar de save
    if (user.currentRole !== effectiveRole) {
      const updateStart = Date.now();
      // Usar updateOne en lugar de save para mejor rendimiento
      await User.updateOne(
        { _id: user._id },
        { $set: { currentRole: effectiveRole } }
      );
      console.log(`⏱️ Update currentRole: ${Date.now() - updateStart}ms`);
    }

    const token = signAppToken({ id: user._id.toString(), role: effectiveRole });

    const totalTime = Date.now() - startTime;
    console.log(`✅ Login exitoso: ${email} - Rol: ${effectiveRole} - Tiempo total: ${totalTime}ms`);

    res.json({
      message: "Inicio de sesión exitoso ✅",
      token,
      role: effectiveRole,
      nombre: user.nombre,
      userId: user._id,
      rolesCompleted: {
        pasajero: hasPasajero,
        conductor: hasConductor
      }
    });
  } catch (error) {
    const totalTime = Date.now() - startTime;
    console.error(`❌ Error en login después de ${totalTime}ms:`, error);
    res.status(500).json({ error: "Error al iniciar sesión" });
  }
});

// =====================
// ✅ Verificar si email está disponible
// =====================
app.post("/api/auth/check-email", async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email || !/.+@.+\..+/.test(email)) {
      return res.status(400).json({ error: "Email inválido" });
    }

    // Verificar conexión a MongoDB
    if (mongoose.connection.readyState !== 1) {
      console.error("❌ MongoDB no está conectado. Estado:", mongoose.connection.readyState);
      return res.status(503).json({ 
        error: "Servicio de base de datos no disponible",
        message: "Por favor, intenta de nuevo en unos momentos"
      });
    }

    const existingUser = await User.findOne({ email: email.trim().toLowerCase() });
    if (existingUser) {
      return res.status(400).json({ error: "El correo ya está registrado" });
    }

    return res.json({ available: true });
  } catch (e) {
    console.error("❌ Error al verificar email:", e);
    return res.status(500).json({ error: "Error al verificar email" });
  }
});

// =====================
// 🎯 Registro completo de pasajero (registro + onboarding)
// =====================
app.post("/api/auth/register-complete", async (req, res) => {
  try {
    const { nombre, email, password, telefono, idUniversitario, photoUrl } = req.body;

    // Validaciones
    if (!nombre || !email || !password) {
      return res.status(400).json({ error: "Campos obligatorios faltantes" });
    }

    const isValidEmail = (v) => /.+@.+\..+/.test(v);
    const isValidPassword = (v) => typeof v === 'string' && v.length >= 6;

    if (!isValidEmail(email)) {
      return res.status(400).json({ error: "Email inválido" });
    }
    if (!isValidPassword(password)) {
      return res.status(400).json({ error: "La contraseña debe tener al menos 6 caracteres" });
    }

    // Verificar conexión a MongoDB
    if (mongoose.connection.readyState !== 1) {
      console.error("❌ MongoDB no está conectado. Estado:", mongoose.connection.readyState);
      return res.status(503).json({ 
        error: "Servicio de base de datos no disponible",
        message: "Por favor, intenta de nuevo en unos momentos"
      });
    }

    // Normalizar email
    const normalizedEmail = email.trim().toLowerCase();

    // Verificar si el usuario ya existe
    const existingUser = await User.findOne({ email: normalizedEmail });
    
    let user;
    let isNewUser = false;

    if (existingUser) {
      // Usuario existente: verificar contraseña y agregar rol pasajero
      console.log("📝 Usuario existente encontrado, verificando contraseña:", normalizedEmail);
      
      const validPassword = await bcrypt.compare(password, existingUser.password);
      if (!validPassword) {
        console.log("❌ Contraseña incorrecta para usuario existente:", normalizedEmail);
        return res.status(401).json({ error: "Contraseña incorrecta. Si ya tienes una cuenta, usa la contraseña correcta." });
      }

      // Si ya tiene el rol pasajero completado, informar
      if (existingUser.rolesCompleted?.pasajero) {
        console.log("ℹ️ Usuario ya tiene rol pasajero completado:", normalizedEmail);
        // Actualizar datos si es necesario
        if (photoUrl && (!existingUser.photoUrl || photoUrl !== existingUser.photoUrl)) {
          existingUser.photoUrl = photoUrl;
        }
        if (nombre && nombre.trim() !== existingUser.nombre) {
          existingUser.nombre = nombre.trim();
        }
        if (telefono !== undefined) {
          existingUser.telefono = telefono?.trim() || "";
        }
        if (idUniversitario !== undefined) {
          existingUser.idUniversitario = idUniversitario?.trim() || "";
        }
        await existingUser.save();
        
        const token = signAppToken({ id: existingUser._id.toString(), role: "pasajero" });
        return res.json({
          message: "Rol pasajero ya estaba completado. Datos actualizados ✅",
          token,
          role: "pasajero",
          nombre: existingUser.nombre,
          userId: existingUser._id
        });
      }

      // Agregar rol pasajero al usuario existente
      console.log("➕ Agregando rol pasajero a usuario existente:", normalizedEmail);
      existingUser.rolesCompleted = {
        pasajero: true,
        conductor: existingUser.rolesCompleted?.conductor || false
      };
      
      // Actualizar datos
      if (photoUrl) existingUser.photoUrl = photoUrl;
      if (nombre && nombre.trim()) existingUser.nombre = nombre.trim();
      if (telefono !== undefined) existingUser.telefono = telefono?.trim() || "";
      if (idUniversitario !== undefined) existingUser.idUniversitario = idUniversitario?.trim() || "";
      
      // Si no tiene currentRole o es conductor, cambiar a pasajero
      if (!existingUser.currentRole || existingUser.currentRole === "conductor") {
        existingUser.currentRole = "pasajero";
      }
      
      existingUser.status = "active";
      await existingUser.save();
      user = existingUser;
      console.log("✅ Rol pasajero agregado exitosamente a usuario existente:", user.email);
    } else {
      // Usuario nuevo: crear con rol pasajero
      console.log("📝 Creando nuevo usuario pasajero:", { email: normalizedEmail, nombre });
      
      const hashedPassword = await bcrypt.hash(password, 10);
      
      try {
        user = await User.create({
          nombre: nombre.trim(),
          email: normalizedEmail,
          password: hashedPassword,
          telefono: telefono?.trim() || "",
          idUniversitario: idUniversitario?.trim() || "",
          photoUrl: photoUrl || "",
          rolesCompleted: { pasajero: true, conductor: false },
          currentRole: "pasajero",
          status: "active",
          preferredRole: "pasajero"
        });
        isNewUser = true;
        console.log("✅ Usuario pasajero creado exitosamente:", user._id, user.email);
      } catch (createError) {
        console.error("❌ Error al crear usuario:", createError);
        if (createError.name === 'MongoServerError' && createError.code === 11000) {
          return res.status(400).json({ error: "El correo ya está registrado" });
        }
        throw createError;
      }
    }

    // Verificar que realmente se guardó
    const savedUser = await User.findById(user._id);
    if (!savedUser) {
      console.error("❌ ERROR: El usuario no se guardó en la base de datos");
      return res.status(500).json({ error: "Error al guardar usuario en la base de datos" });
    }
    console.log("✅ Usuario verificado en BD:", savedUser.email);

    // Generar token
    const token = signAppToken({ id: user._id.toString(), role: "pasajero" });

    return res.status(isNewUser ? 201 : 200).json({
      message: isNewUser ? "Registro completado exitosamente ✅" : "Rol pasajero agregado exitosamente ✅",
      token,
      role: "pasajero",
      nombre: user.nombre,
      userId: user._id
    });
  } catch (error) {
    console.error("❌ Error al registrar usuario completo:", error);
    console.error("❌ Error name:", error.name);
    console.error("❌ Error message:", error.message);
    console.error("❌ Error stack:", error.stack);
    console.error("❌ MongoDB connection state:", mongoose.connection.readyState);
    
    if (error.name === 'MongoServerError' && error.code === 11000) {
      return res.status(400).json({ error: "El correo ya está registrado" });
    }
    if (error.name === 'ValidationError') {
      return res.status(400).json({ 
        error: "Error de validación",
        message: error.message 
      });
    }

    return res.status(500).json({ 
      error: "Error al completar registro",
      message: error.message,
      details: process.env.NODE_ENV === "development" ? error.stack : undefined
    });
  }
});

// =====================
// 🎯 Registro completo de conductor (registro + onboarding completo)
// =====================
app.post("/api/auth/register-complete-conductor", async (req, res) => {
  try {
    const { nombre, email, password, telefono, idUniversitario, photoUrl, marca, modelo, anio, placa, vehiclePhotoUrl } = req.body;

    // Validaciones
    if (!nombre || !email || !password) {
      return res.status(400).json({ error: "Campos obligatorios faltantes" });
    }

    if (!marca || !modelo || !anio || !placa) {
      return res.status(400).json({ error: "Todos los campos del vehículo son obligatorios" });
    }

    const isValidEmail = (v) => /.+@.+\..+/.test(v);
    const isValidPassword = (v) => typeof v === 'string' && v.length >= 6;

    if (!isValidEmail(email)) {
      return res.status(400).json({ error: "Email inválido" });
    }
    if (!isValidPassword(password)) {
      return res.status(400).json({ error: "La contraseña debe tener al menos 6 caracteres" });
    }

    // Verificar conexión a MongoDB
    if (mongoose.connection.readyState !== 1) {
      console.error("❌ MongoDB no está conectado. Estado:", mongoose.connection.readyState);
      return res.status(503).json({ 
        error: "Servicio de base de datos no disponible",
        message: "Por favor, intenta de nuevo en unos momentos"
      });
    }

    // Normalizar email
    const normalizedEmail = email.trim().toLowerCase();

    // Verificar si el usuario ya existe
    const existingUser = await User.findOne({ email: normalizedEmail });
    
    let user;
    let isNewUser = false;

    if (existingUser) {
      // Usuario existente: verificar contraseña y agregar rol conductor
      console.log("📝 Usuario existente encontrado, verificando contraseña:", normalizedEmail);
      
      const validPassword = await bcrypt.compare(password, existingUser.password);
      if (!validPassword) {
        console.log("❌ Contraseña incorrecta para usuario existente:", normalizedEmail);
        return res.status(401).json({ error: "Contraseña incorrecta. Si ya tienes una cuenta, usa la contraseña correcta." });
      }

      // Si ya tiene el rol conductor completado, informar y actualizar datos del vehículo
      if (existingUser.rolesCompleted?.conductor) {
        console.log("ℹ️ Usuario ya tiene rol conductor completado:", normalizedEmail);
        // Actualizar datos si es necesario
        if (photoUrl && (!existingUser.photoUrl || photoUrl !== existingUser.photoUrl)) {
          existingUser.photoUrl = photoUrl;
        }
        if (nombre && nombre.trim() !== existingUser.nombre) {
          existingUser.nombre = nombre.trim();
        }
        if (telefono !== undefined) {
          existingUser.telefono = telefono?.trim() || "";
        }
        if (idUniversitario !== undefined) {
          existingUser.idUniversitario = idUniversitario?.trim() || "";
        }
        // Actualizar información del vehículo
        if (marca || modelo || anio || placa || vehiclePhotoUrl) {
          existingUser.vehicle = {
            marca: marca?.trim() || existingUser.vehicle?.marca || "",
            modelo: modelo?.trim() || existingUser.vehicle?.modelo || "",
            anio: anio?.trim() || existingUser.vehicle?.anio || "",
            placa: placa?.trim() || existingUser.vehicle?.placa || "",
            photoUrl: vehiclePhotoUrl || existingUser.vehicle?.photoUrl || ""
          };
        }
        await existingUser.save();
        
        const token = signAppToken({ id: existingUser._id.toString(), role: "conductor" });
        return res.json({
          message: "Rol conductor ya estaba completado. Datos actualizados ✅",
          token,
          role: "conductor",
          nombre: existingUser.nombre,
          userId: existingUser._id
        });
      }

      // Agregar rol conductor al usuario existente
      console.log("➕ Agregando rol conductor a usuario existente:", normalizedEmail);
      existingUser.rolesCompleted = {
        pasajero: existingUser.rolesCompleted?.pasajero || false,
        conductor: true
      };
      
      // Actualizar datos
      if (photoUrl) existingUser.photoUrl = photoUrl;
      if (nombre && nombre.trim()) existingUser.nombre = nombre.trim();
      if (telefono !== undefined) existingUser.telefono = telefono?.trim() || "";
      if (idUniversitario !== undefined) existingUser.idUniversitario = idUniversitario?.trim() || "";
      
      // Agregar/actualizar información del vehículo
      existingUser.vehicle = {
        marca: marca?.trim() || "",
        modelo: modelo?.trim() || "",
        anio: anio?.trim() || "",
        placa: placa?.trim() || "",
        photoUrl: vehiclePhotoUrl || ""
      };
      
      // Si no tiene currentRole o es pasajero, cambiar a conductor
      if (!existingUser.currentRole || existingUser.currentRole === "pasajero") {
        existingUser.currentRole = "conductor";
      }
      
      existingUser.status = "active";
      await existingUser.save();
      user = existingUser;
      console.log("✅ Rol conductor agregado exitosamente a usuario existente:", user.email);
    } else {
      // Usuario nuevo: crear con rol conductor
      console.log("📝 Creando nuevo usuario conductor:", { email: normalizedEmail, nombre });
      
      const hashedPassword = await bcrypt.hash(password, 10);
      
      try {
        user = await User.create({
          nombre: nombre.trim(),
          email: normalizedEmail,
          password: hashedPassword,
          telefono: telefono?.trim() || "",
          idUniversitario: idUniversitario?.trim() || "",
          photoUrl: photoUrl || "",
          rolesCompleted: { pasajero: false, conductor: true },
          currentRole: "conductor",
          status: "active",
          preferredRole: "conductor",
          vehicle: {
            marca: marca?.trim() || "",
            modelo: modelo?.trim() || "",
            anio: anio?.trim() || "",
            placa: placa?.trim() || "",
            photoUrl: vehiclePhotoUrl || ""
          }
        });
        isNewUser = true;
        console.log("✅ Usuario conductor creado exitosamente:", user._id, user.email);
      } catch (createError) {
        console.error("❌ Error al crear usuario:", createError);
        if (createError.name === 'MongoServerError' && createError.code === 11000) {
          return res.status(400).json({ error: "El correo ya está registrado" });
        }
        throw createError;
      }
    }

    // Verificar que realmente se guardó
    const savedUser = await User.findById(user._id);
    if (!savedUser) {
      console.error("❌ ERROR: El usuario no se guardó en la base de datos");
      return res.status(500).json({ error: "Error al guardar usuario en la base de datos" });
    }
    console.log("✅ Usuario verificado en BD:", savedUser.email);

    // Generar token
    const token = signAppToken({ id: user._id.toString(), role: "conductor" });

    return res.status(isNewUser ? 201 : 200).json({
      message: isNewUser ? "Registro completado exitosamente ✅" : "Rol conductor agregado exitosamente ✅",
      token,
      role: "conductor",
      nombre: user.nombre,
      userId: user._id
    });
  } catch (error) {
    console.error("❌ Error al registrar usuario completo (conductor):", error);
    console.error("❌ Error name:", error.name);
    console.error("❌ Error message:", error.message);
    console.error("❌ Error stack:", error.stack);
    console.error("❌ MongoDB connection state:", mongoose.connection.readyState);
    
    if (error.name === 'MongoServerError' && error.code === 11000) {
      return res.status(400).json({ error: "El correo ya está registrado" });
    }
    if (error.name === 'ValidationError') {
      return res.status(400).json({ 
        error: "Error de validación",
        message: error.message 
      });
    }

    return res.status(500).json({ 
      error: "Error al completar registro",
      message: error.message,
      details: process.env.NODE_ENV === "development" ? error.stack : undefined
    });
  }
});

// =====================
// 🚀 Onboarding Pasajero (para usuarios que ya existen)
// =====================
app.post("/api/onboarding/pasajero", authRequired, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: "Usuario no encontrado" });

    // Guardar foto si viene en el body
    if (req.body.photoUrl) {
      user.photoUrl = req.body.photoUrl;
    }

    user.rolesCompleted.pasajero = true;
    user.status = "active";
    // Actualizar currentRole a pasajero si no tiene rol o si está cambiando de rol
    user.currentRole = "pasajero";
    await user.save();

    // Generar nuevo token con el rol actualizado
    const token = signAppToken({ id: user._id.toString(), role: user.currentRole });

    return res.json({
      message: "Onboarding de pasajero completado ✅",
      rolesCompleted: user.rolesCompleted,
      currentRole: user.currentRole,
      token: token
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
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: "Usuario no encontrado" });

    user.rolesCompleted.conductor = true;
    user.status = "active";
    // Actualizar currentRole a conductor si no tiene rol o si está cambiando de rol
    user.currentRole = "conductor";
    if (req.body) {
      // Guardar foto del usuario si viene
      if (req.body.photoUrl) {
        user.photoUrl = req.body.photoUrl;
      }
      // Guardar datos del vehículo
      user.vehicle.marca = req.body.marca || user.vehicle.marca;
      user.vehicle.modelo = req.body.modelo || user.vehicle.modelo;
      user.vehicle.anio = req.body.anio || user.vehicle.anio;
      user.vehicle.placa = req.body.placa || user.vehicle.placa;
      // Guardar foto del vehículo si viene
      if (req.body.vehiclePhotoUrl) {
        user.vehicle.photoUrl = req.body.vehiclePhotoUrl;
      }
    }
    await user.save();

    // Generar nuevo token con el rol actualizado
    const token = signAppToken({ id: user._id.toString(), role: user.currentRole });

    return res.json({
      message: "Onboarding de conductor completado ✅",
      rolesCompleted: user.rolesCompleted,
      currentRole: user.currentRole,
      token: token
    });
  } catch (e) {
    console.error("❌ Error en onboarding conductor:", e);
    return res.status(500).json({ error: "Error en onboarding" });
  }
});

// =====================
// 👤 Datos del usuario actual
// =====================
app.get("/api/user/me", authRequired, async (req, res) => {
  try {
  const user = await User.findById(req.user.id).lean();
  if (!user) return res.status(404).json({ error: "Usuario no encontrado" });
  return res.json({
    id: user._id,
    nombre: user.nombre,
    email: user.email,
      telefono: user.telefono || "",
      idUniversitario: user.idUniversitario || "",
      photoUrl: user.photoUrl || "",
    rolesCompleted: user.rolesCompleted,
    currentRole: user.currentRole,
      preferredRole: user.preferredRole,
      status: user.status,
      vehicle: user.vehicle || {}
    });
  } catch (e) {
    console.error("❌ Error al obtener perfil:", e);
    return res.status(500).json({ error: "Error al obtener perfil" });
  }
});

// =====================
// ✏️ Actualizar perfil del usuario
// =====================
app.put("/api/user/me", authRequired, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: "Usuario no encontrado" });

    const { nombre, telefono, idUniversitario, preferredRole } = req.body;

    // Validaciones
    if (nombre !== undefined) {
      if (!nombre || nombre.trim() === "") {
        return res.status(400).json({ error: "El nombre no puede estar vacío" });
      }
      user.nombre = nombre.trim();
    }

    if (telefono !== undefined) {
      user.telefono = telefono ? telefono.trim() : "";
    }

    if (idUniversitario !== undefined) {
      user.idUniversitario = idUniversitario ? idUniversitario.trim() : "";
    }

    if (preferredRole !== undefined) {
      if (preferredRole !== "pasajero" && preferredRole !== "conductor") {
        return res.status(400).json({ error: "Rol preferido inválido" });
      }
      user.preferredRole = preferredRole;
    }

    await user.save();

    return res.json({
      message: "Perfil actualizado exitosamente ✅",
      user: {
        id: user._id,
        nombre: user.nombre,
        email: user.email,
        telefono: user.telefono,
        idUniversitario: user.idUniversitario,
        rolesCompleted: user.rolesCompleted,
        currentRole: user.currentRole,
        preferredRole: user.preferredRole,
    status: user.status,
    vehicle: user.vehicle
      }
  });
  } catch (e) {
    console.error("❌ Error al actualizar perfil:", e);
    return res.status(500).json({ error: "Error al actualizar perfil" });
  }
});

// =====================
// 🗑️ Eliminar cuenta de usuario
// =====================
app.delete("/api/user/me", authRequired, async (req, res) => {
  try {
    const userId = req.user.id;
    
    // Buscar el usuario
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: "Usuario no encontrado" });
    }

    // Eliminar todos los viajes creados por el usuario
    await Trip.deleteMany({ driverId: userId });

    // Eliminar todas las reservas del usuario (como pasajero)
    await Trip.updateMany(
      { "bookings.passengerId": userId },
      { $pull: { bookings: { passengerId: userId } } }
    );

    // Eliminar mensajes del usuario
    await Message.deleteMany({ $or: [{ senderId: userId }, { receiverId: userId }] });

    // Eliminar el usuario
    await User.findByIdAndDelete(userId);

    return res.json({ 
      message: "Cuenta eliminada exitosamente ✅",
      deleted: true
    });
  } catch (e) {
    console.error("❌ Error al eliminar cuenta:", e);
    return res.status(500).json({ error: "Error al eliminar cuenta" });
  }
});

// =====================
// 🔄 Cambiar rol actual - Redirige a onboarding si no está completado
// =====================
app.put("/api/user/role", authRequired, async (req, res) => {
  const { role } = req.body;
  if (role !== "pasajero" && role !== "conductor") {
    return res.status(400).json({ error: "Rol inválido" });
  }
  const user = await User.findById(req.user.id);
  if (!user) return res.status(404).json({ error: "Usuario no encontrado" });
  
  // Si el rol no está completado, generar token de onboarding y redirigir
  // Incluir datos del usuario para prellenar formularios
  if (!user.rolesCompleted[role]) {
    const onboardingToken = signAppToken({ id: user._id.toString(), onboarding: true });
    const nextRoute = role === "conductor" ? "/register-driver-vehicle" : "/register-photo";
    
    // Preparar datos del usuario para prellenar formularios
    const userData = {
      nombre: user.nombre || "",
      email: user.email || "",
      telefono: user.telefono || "",
      idUniversitario: user.idUniversitario || "",
      photoUrl: user.photoUrl || "",
      // Si es conductor, incluir datos del vehículo si existen
      ...(role === "conductor" && user.vehicle ? {
        marca: user.vehicle.marca || "",
        modelo: user.vehicle.modelo || "",
        anio: user.vehicle.anio || "",
        placa: user.vehicle.placa || "",
        vehiclePhotoUrl: user.vehicle.photoUrl || ""
      } : {})
    };
    
    return res.status(200).json({ 
      needOnboarding: true,
      message: `Necesitas completar el onboarding de ${role}`,
      onboardingToken,
      nextRoute,
      role: role,
      userData: userData // Datos del usuario para prellenar formularios
    });
  }
  
  // Si el rol está completado, cambiar directamente
  user.currentRole = role;
  await user.save();
  const token = signAppToken({ id: user._id.toString(), role: user.currentRole });
  return res.json({ 
    message: "Rol cambiado ✅", 
    role: user.currentRole, 
    token,
    needOnboarding: false
  });
});

// =====================
// 🧭 Ruta inicial
// =====================
app.get("/", (req, res) => {
  res.send("🚗 Servidor Wheels funcionando correctamente 🚀");
});

// =====================
// 🧨 Iniciar servidor - Esperar conexión a MongoDB
// =====================
const PORT = process.env.PORT || 5000;

async function startServer() {
  // Intentar conectar a MongoDB antes de iniciar el servidor
  const connected = await connectToMongoDB();
  
  if (!connected) {
    console.error("❌ No se pudo conectar a MongoDB. El servidor no se iniciará.");
    console.error("⚠️  Verifica que MONGODB_URI esté configurado correctamente.");
    process.exit(1);
  }

app.listen(PORT, () => {
  console.log(`🔥 Servidor escuchando en puerto ${PORT}`);
    console.log(`🗃️ Base de datos: MongoDB conectado`);
  console.log(`🌐 CORS permitido para: ${allowedOrigins.join(', ')}`);
  console.log(`📡 Endpoint de prueba: http://localhost:${PORT}/api/test`);
});
}

// Manejar eventos de conexión de MongoDB
mongoose.connection.on('error', (err) => {
  console.error('❌ Error de MongoDB:', err);
});

mongoose.connection.on('disconnected', () => {
  console.warn('⚠️  MongoDB desconectado');
});

mongoose.connection.on('reconnected', () => {
  console.log('✅ MongoDB reconectado');
});

// Iniciar el servidor
startServer();

// =====================
// 🚌 VIAJES Y RESERVAS
// =====================

// Crear viaje (rol: conductor)
app.post("/api/trips", authRequired, async (req, res) => {
  try {
    const me = await User.findById(req.user.id);
    if (!me) return res.status(401).json({ error: "No autorizado" });
    if (!me.rolesCompleted?.conductor) return res.status(403).json({ error: "Debes completar onboarding de conductor" });

    const { from, to, departureTime, price, seatsTotal } = req.body;
    if (!from || !to || !departureTime || price == null || !seatsTotal) {
      return res.status(400).json({ error: "Campos requeridos: from, to, departureTime, price, seatsTotal" });
    }

    const trip = await Trip.create({
      driverId: me._id,
      from,
      to,
      departureTime: new Date(departureTime),
      price: Number(price),
      seatsTotal: Number(seatsTotal),
      seatsAvailable: Number(seatsTotal),
    });

    return res.status(201).json({ message: "Viaje creado", trip });
  } catch (e) {
    console.error("❌ Error al crear viaje:", e);
    return res.status(500).json({ error: "Error al crear viaje" });
  }
});

// Buscar viajes (query: from, to, date opcional)
app.get("/api/trips/search", async (req, res) => {
  try {
    const { from, to, date } = req.query;
    const criteria = {};
    
    if (from) criteria.from = new RegExp(from, "i");
    if (to) criteria.to = new RegExp(to, "i");
    
    // Filtrar solo viajes futuros
    const now = new Date();
    if (date) {
      const start = new Date(date);
      start.setHours(0, 0, 0, 0);
      const end = new Date(date);
      end.setHours(23, 59, 59, 999);
      // Asegurar que la fecha seleccionada sea futura
      const minDate = start > now ? start : now;
      criteria.departureTime = { $gte: minDate, $lte: end };
    } else {
      // Si no hay fecha específica, solo mostrar futuros
      criteria.departureTime = { $gte: now };
    }
    
    const trips = await Trip.find(criteria)
      .populate('driverId', 'nombre email photoUrl vehicle')
      .populate('bookings.passengerId', 'nombre email')
      .sort({ departureTime: 1 })
      .limit(100)
      .lean();
    
    // Filtrar y formatear viajes con asientos disponibles (solo aceptados cuentan)
    const formattedTrips = trips
      .map(trip => {
        const acceptedBookings = trip.bookings.filter(b => b.status === "accepted");
        const totalAcceptedSeats = acceptedBookings.reduce((sum, b) => sum + (b.seats || 1), 0);
        const availableSeats = trip.seatsTotal - totalAcceptedSeats;
        return {
          ...trip,
          seatsAvailable: availableSeats,
          driver: trip.driverId ? {
            nombre: trip.driverId.nombre,
            photoUrl: trip.driverId.photoUrl || "",
            vehicle: trip.driverId.vehicle || {}
          } : null
        };
      })
      .filter(trip => trip.seatsAvailable > 0); // Solo mostrar viajes con asientos disponibles
    
    return res.json({ trips: formattedTrips });
  } catch (e) {
    console.error("❌ Error al buscar viajes:", e);
    return res.status(500).json({ error: "Error al buscar viajes" });
  }
});

// Mis viajes (si soy conductor: que publiqué; si soy pasajero: que reservé)
app.get("/api/trips/my", authRequired, async (req, res) => {
  try {
    const meId = req.user.id;
    const asDriver = await Trip.find({ driverId: meId })
      .populate('bookings.passengerId', 'nombre email telefono idUniversitario photoUrl')
      .populate('driverId', 'nombre email photoUrl vehicle')
      .sort({ createdAt: -1 })
      .lean();
    
    // Para pasajero, filtrar solo sus solicitudes
    const asPassenger = await Trip.find({ "bookings.passengerId": meId })
      .populate('driverId', 'nombre email photoUrl vehicle')
      .sort({ createdAt: -1 })
      .lean();
    
    // Formatear para incluir el estado de la solicitud del pasajero
    const formattedAsPassenger = asPassenger.map(trip => {
      const myBooking = trip.bookings.find(b => {
        const passengerId = b.passengerId._id || b.passengerId;
        return passengerId.toString() === meId;
      });
      return {
        ...trip,
        myBookingStatus: myBooking?.status || null,
        driver: trip.driverId ? {
          nombre: trip.driverId.nombre,
          photoUrl: trip.driverId.photoUrl || "",
          vehicle: trip.driverId.vehicle || {}
        } : null
      };
    });
    
    return res.json({ asDriver, asPassenger: formattedAsPassenger });
  } catch (e) {
    console.error("❌ Error al listar viajes del usuario:", e);
    return res.status(500).json({ error: "Error al listar viajes" });
  }
});

// Obtener solicitudes pendientes de un viaje (rol: conductor)
app.get("/api/trips/:tripId/requests", authRequired, async (req, res) => {
  try {
    const me = await User.findById(req.user.id);
    if (!me) return res.status(401).json({ error: "No autorizado" });
    if (!me.rolesCompleted?.conductor) return res.status(403).json({ error: "Debes completar onboarding de conductor" });

    const trip = await Trip.findById(req.params.tripId)
      .populate('bookings.passengerId', 'nombre email telefono idUniversitario')
      .lean();
    
    if (!trip) return res.status(404).json({ error: "Viaje no encontrado" });
    
    // Verificar que el viaje pertenezca al conductor
    if (trip.driverId.toString() !== me._id.toString()) {
      return res.status(403).json({ error: "No tienes permiso para ver solicitudes de este viaje" });
    }

    // Separar solicitudes por estado
    const pending = trip.bookings.filter(b => b.status === "pending");
    const accepted = trip.bookings.filter(b => b.status === "accepted");
    const rejected = trip.bookings.filter(b => b.status === "rejected");

    // Calcular asientos disponibles (solo aceptados cuentan)
    const totalAcceptedSeats = accepted.reduce((sum, b) => sum + (b.seats || 1), 0);
    
    return res.json({
      trip: {
        _id: trip._id,
        from: trip.from,
        to: trip.to,
        departureTime: trip.departureTime,
        price: trip.price,
        seatsTotal: trip.seatsTotal,
        seatsAvailable: trip.seatsTotal - totalAcceptedSeats
      },
      requests: {
        pending: pending,
        accepted: accepted,
        rejected: rejected
      }
    });
  } catch (e) {
    console.error("❌ Error al obtener solicitudes:", e);
    return res.status(500).json({ error: "Error al obtener solicitudes" });
  }
});

// Solicitar reserva de un viaje (rol: pasajero) - Ahora crea solicitud pendiente
app.post("/api/trips/:id/book", authRequired, async (req, res) => {
  try {
    const me = await User.findById(req.user.id);
    if (!me) return res.status(401).json({ error: "No autorizado" });
    if (!me.rolesCompleted?.pasajero) return res.status(403).json({ error: "Debes completar onboarding de pasajero" });

    const trip = await Trip.findById(req.params.id);
    if (!trip) return res.status(404).json({ error: "Viaje no encontrado" });
    
    // Obtener cantidad de asientos solicitados (default: 1)
    const seatsRequested = Number(req.body.seats) || 1;
    if (seatsRequested < 1) {
      return res.status(400).json({ error: "Debes solicitar al menos 1 asiento" });
    }
    
    // Verificar que el viaje tenga asientos disponibles (contando solo aceptados)
    const acceptedBookings = trip.bookings.filter(b => b.status === "accepted");
    const totalAcceptedSeats = acceptedBookings.reduce((sum, b) => sum + (b.seats || 1), 0);
    const availableSeats = trip.seatsTotal - totalAcceptedSeats;
    
    if (availableSeats < seatsRequested) {
      return res.status(400).json({ 
        error: `Solo hay ${availableSeats} asiento${availableSeats !== 1 ? 's' : ''} disponible${availableSeats !== 1 ? 's' : ''}` 
      });
    }
    
    if (trip.driverId.toString() === me._id.toString()) {
      return res.status(400).json({ error: "No puedes solicitar reserva en tu propio viaje" });
    }
    
    // Verificar si ya tiene una solicitud (pendiente o aceptada)
    const existingRequestIndex = trip.bookings.findIndex(b => b.passengerId.toString() === me._id.toString());
    const existingRequest = existingRequestIndex !== -1 ? trip.bookings[existingRequestIndex] : null;
    
    if (existingRequest) {
      if (existingRequest.status === "pending") {
        // Si ya tiene una solicitud pendiente, actualizar la cantidad de asientos
        const oldSeats = existingRequest.seats || 1;
        const seatsDifference = seatsRequested - oldSeats;
        
        // Verificar que haya suficientes asientos para la nueva cantidad
        if (availableSeats < seatsDifference) {
          return res.status(400).json({ 
            error: `Solo hay ${availableSeats + oldSeats} asiento${availableSeats + oldSeats !== 1 ? 's' : ''} disponible${availableSeats + oldSeats !== 1 ? 's' : ''} en total. Ya tienes ${oldSeats} reservado${oldSeats > 1 ? 's' : ''}` 
          });
        }
        
        // Actualizar la cantidad de asientos
        trip.bookings[existingRequestIndex].seats = seatsRequested;
    await trip.save();
        
        return res.json({ 
          message: `Solicitud actualizada. Ahora solicitas ${seatsRequested} asiento${seatsRequested > 1 ? 's' : ''}.`, 
          tripId: trip._id,
          status: "pending",
          seats: seatsRequested
        });
      }
      if (existingRequest.status === "accepted") {
        // Si ya está aceptado, permitir actualizar la cantidad de asientos
        const oldSeats = existingRequest.seats || 1;
        const seatsDifference = seatsRequested - oldSeats;
        
        // Verificar que haya suficientes asientos disponibles para aumentar
        if (seatsDifference > 0 && availableSeats < seatsDifference) {
          return res.status(400).json({ 
            error: `Solo hay ${availableSeats} asiento${availableSeats !== 1 ? 's' : ''} disponible${availableSeats !== 1 ? 's' : ''}. Ya tienes ${oldSeats} reservado${oldSeats > 1 ? 's' : ''}` 
          });
        }
        
        // Actualizar la cantidad de asientos
        trip.bookings[existingRequestIndex].seats = seatsRequested;
        
        // Recalcular asientos disponibles
        const acceptedBookings = trip.bookings.filter(b => b.status === "accepted");
        const totalAcceptedSeats = acceptedBookings.reduce((sum, b) => sum + (b.seats || 1), 0);
        trip.seatsAvailable = trip.seatsTotal - totalAcceptedSeats;
        
        await trip.save();
        
        return res.json({ 
          message: `Reserva actualizada. Ahora tienes ${seatsRequested} asiento${seatsRequested > 1 ? 's' : ''} reservado${seatsRequested > 1 ? 's' : ''}.`, 
          tripId: trip._id,
          status: "accepted",
          seats: seatsRequested,
          seatsAvailable: trip.seatsAvailable
        });
      }
      // Si fue rechazada, puede volver a solicitar
    }

    // Crear solicitud pendiente
    trip.bookings.push({ 
      passengerId: me._id, 
      seats: seatsRequested,
      status: "pending",
      requestedAt: new Date()
    });
    await trip.save();
    
    return res.json({ 
      message: `Solicitud de reserva por ${seatsRequested} asiento${seatsRequested > 1 ? 's' : ''} enviada. Espera la respuesta del conductor.`, 
      tripId: trip._id,
      status: "pending",
      seats: seatsRequested
    });
  } catch (e) {
    console.error("❌ Error al solicitar reserva:", e);
    return res.status(500).json({ error: "Error al solicitar reserva" });
  }
});

// Aceptar solicitud de reserva (rol: conductor)
app.post("/api/trips/:tripId/requests/:requestId/accept", authRequired, async (req, res) => {
  try {
    const me = await User.findById(req.user.id);
    if (!me) return res.status(401).json({ error: "No autorizado" });
    if (!me.rolesCompleted?.conductor) return res.status(403).json({ error: "Debes completar onboarding de conductor" });

    const trip = await Trip.findById(req.params.tripId);
    if (!trip) return res.status(404).json({ error: "Viaje no encontrado" });
    
    // Verificar que el viaje pertenezca al conductor
    if (trip.driverId.toString() !== me._id.toString()) {
      return res.status(403).json({ error: "No tienes permiso para aceptar solicitudes de este viaje" });
    }

    // Buscar la solicitud
    const requestIndex = trip.bookings.findIndex(
      b => b.passengerId.toString() === req.params.requestId && b.status === "pending"
    );
    
    if (requestIndex === -1) {
      return res.status(404).json({ error: "Solicitud no encontrada o ya procesada" });
    }

    const request = trip.bookings[requestIndex];
    const seatsRequested = request.seats || 1;

    // Verificar asientos disponibles
    const acceptedBookings = trip.bookings.filter(b => b.status === "accepted");
    const totalAcceptedSeats = acceptedBookings.reduce((sum, b) => sum + (b.seats || 1), 0);
    const availableSeats = trip.seatsTotal - totalAcceptedSeats;
    
    if (availableSeats < seatsRequested) {
      return res.status(400).json({ 
        error: `No hay suficientes asientos disponibles. Solo quedan ${availableSeats} asiento${availableSeats !== 1 ? 's' : ''}` 
      });
    }

    // Aceptar la solicitud
    trip.bookings[requestIndex].status = "accepted";
    trip.bookings[requestIndex].respondedAt = new Date();
    const newTotalAcceptedSeats = totalAcceptedSeats + seatsRequested;
    trip.seatsAvailable = trip.seatsTotal - newTotalAcceptedSeats;
    await trip.save();

    return res.json({ 
      message: "Solicitud aceptada ✅", 
      tripId: trip._id,
      seatsAvailable: trip.seatsAvailable
    });
  } catch (e) {
    console.error("❌ Error al aceptar solicitud:", e);
    return res.status(500).json({ error: "Error al aceptar solicitud" });
  }
});

// Rechazar solicitud de reserva (rol: conductor)
app.post("/api/trips/:tripId/requests/:requestId/reject", authRequired, async (req, res) => {
  try {
    const me = await User.findById(req.user.id);
    if (!me) return res.status(401).json({ error: "No autorizado" });
    if (!me.rolesCompleted?.conductor) return res.status(403).json({ error: "Debes completar onboarding de conductor" });

    const trip = await Trip.findById(req.params.tripId);
    if (!trip) return res.status(404).json({ error: "Viaje no encontrado" });
    
    // Verificar que el viaje pertenezca al conductor
    if (trip.driverId.toString() !== me._id.toString()) {
      return res.status(403).json({ error: "No tienes permiso para rechazar solicitudes de este viaje" });
    }

    // Buscar la solicitud
    const requestIndex = trip.bookings.findIndex(
      b => b.passengerId.toString() === req.params.requestId && b.status === "pending"
    );
    
    if (requestIndex === -1) {
      return res.status(404).json({ error: "Solicitud no encontrada o ya procesada" });
    }

    // Rechazar la solicitud
    trip.bookings[requestIndex].status = "rejected";
    trip.bookings[requestIndex].respondedAt = new Date();
    await trip.save();

    return res.json({ 
      message: "Solicitud rechazada", 
      tripId: trip._id
    });
  } catch (e) {
    console.error("❌ Error al rechazar solicitud:", e);
    return res.status(500).json({ error: "Error al rechazar solicitud" });
  }
});

// Editar viaje (rol: conductor)
app.put("/api/trips/:tripId", authRequired, async (req, res) => {
  try {
    const me = await User.findById(req.user.id);
    if (!me) return res.status(401).json({ error: "No autorizado" });
    if (!me.rolesCompleted?.conductor) return res.status(403).json({ error: "Debes completar onboarding de conductor" });

    const trip = await Trip.findById(req.params.tripId);
    if (!trip) return res.status(404).json({ error: "Viaje no encontrado" });
    
    // Verificar que el viaje pertenezca al conductor
    if (trip.driverId.toString() !== me._id.toString()) {
      return res.status(403).json({ error: "No tienes permiso para editar este viaje" });
    }

    const { from, to, departureTime, price, seatsTotal } = req.body;

    // Validar que si se reduce seatsTotal, no sea menor a los asientos ya ocupados
    if (seatsTotal !== undefined) {
      const acceptedBookings = trip.bookings.filter(b => b.status === "accepted");
      const totalAcceptedSeats = acceptedBookings.reduce((sum, b) => sum + (b.seats || 1), 0);
      
      if (Number(seatsTotal) < totalAcceptedSeats) {
        return res.status(400).json({ 
          error: `No puedes reducir los asientos a menos de ${totalAcceptedSeats} porque ya hay ${totalAcceptedSeats} asiento${totalAcceptedSeats > 1 ? 's' : ''} reservado${totalAcceptedSeats > 1 ? 's' : ''}` 
        });
      }
    }

    // Actualizar campos si están presentes
    if (from !== undefined) trip.from = from.trim();
    if (to !== undefined) trip.to = to.trim();
    if (departureTime !== undefined) trip.departureTime = new Date(departureTime);
    if (price !== undefined) trip.price = Number(price);
    if (seatsTotal !== undefined) {
      trip.seatsTotal = Number(seatsTotal);
      // Recalcular asientos disponibles
      const acceptedBookings = trip.bookings.filter(b => b.status === "accepted");
      const totalAcceptedSeats = acceptedBookings.reduce((sum, b) => sum + (b.seats || 1), 0);
      trip.seatsAvailable = trip.seatsTotal - totalAcceptedSeats;
    }

    await trip.save();

    return res.json({ 
      message: "Viaje actualizado exitosamente ✅", 
      trip: trip
    });
  } catch (e) {
    console.error("❌ Error al editar viaje:", e);
    return res.status(500).json({ error: "Error al editar viaje" });
  }
});

// Eliminar viaje (rol: conductor)
app.delete("/api/trips/:tripId", authRequired, async (req, res) => {
  try {
    const me = await User.findById(req.user.id);
    if (!me) return res.status(401).json({ error: "No autorizado" });
    if (!me.rolesCompleted?.conductor) return res.status(403).json({ error: "Debes completar onboarding de conductor" });

    const trip = await Trip.findById(req.params.tripId);
    if (!trip) return res.status(404).json({ error: "Viaje no encontrado" });
    
    // Verificar que el viaje pertenezca al conductor
    if (trip.driverId.toString() !== me._id.toString()) {
      return res.status(403).json({ error: "No tienes permiso para eliminar este viaje" });
    }

    // Eliminar el viaje
    await Trip.findByIdAndDelete(req.params.tripId);

    return res.json({ 
      message: "Viaje eliminado exitosamente ✅", 
      tripId: trip._id
    });
  } catch (e) {
    console.error("❌ Error al eliminar viaje:", e);
    return res.status(500).json({ error: "Error al eliminar viaje" });
  }
});

// =====================
// 💬 CHAT Y MENSAJERÍA
// =====================

// Obtener conversaciones del usuario (viajes donde tiene reservas aceptadas)
app.get("/api/chat/conversations", authRequired, async (req, res) => {
  try {
    const meId = req.user.id;
    
    // Obtener viajes donde el usuario es conductor o pasajero aceptado
    const tripsAsDriver = await Trip.find({ driverId: meId })
      .populate('bookings.passengerId', 'nombre email')
      .lean();
    
    const tripsAsPassenger = await Trip.find({ 
      "bookings.passengerId": meId,
      "bookings.status": "accepted"
    })
      .populate('driverId', 'nombre email')
      .lean();
    
    // Formatear conversaciones
    const conversations = [];
    
    // Conversaciones como conductor
    tripsAsDriver.forEach(trip => {
      const acceptedBookings = trip.bookings.filter(b => b.status === "accepted");
      acceptedBookings.forEach(booking => {
        const passenger = booking.passengerId;
        if (passenger) {
          conversations.push({
            tripId: trip._id,
            otherUserId: passenger._id,
            otherUserName: passenger.nombre,
            otherUserEmail: passenger.email,
            trip: {
              from: trip.from,
              to: trip.to,
              departureTime: trip.departureTime
            },
            role: "conductor"
          });
        }
      });
    });
    
    // Conversaciones como pasajero
    tripsAsPassenger.forEach(trip => {
      const myBooking = trip.bookings.find(b => 
        b.passengerId && (b.passengerId._id?.toString() === meId || b.passengerId.toString() === meId)
      );
      if (myBooking && myBooking.status === "accepted" && trip.driverId) {
        conversations.push({
          tripId: trip._id,
          otherUserId: trip.driverId._id,
          otherUserName: trip.driverId.nombre,
          otherUserEmail: trip.driverId.email,
          trip: {
            from: trip.from,
            to: trip.to,
            departureTime: trip.departureTime
          },
          role: "pasajero"
        });
      }
    });
    
    return res.json({ conversations });
  } catch (e) {
    console.error("❌ Error al obtener conversaciones:", e);
    return res.status(500).json({ error: "Error al obtener conversaciones" });
  }
});

// Obtener mensajes de una conversación
app.get("/api/chat/trips/:tripId/messages", authRequired, async (req, res) => {
  try {
    const meId = req.user.id;
    const tripId = req.params.tripId;
    
    // Verificar que el usuario tenga acceso a esta conversación
    const trip = await Trip.findById(tripId)
      .populate('driverId', '_id')
      .populate('bookings.passengerId', '_id')
      .lean();
    
    if (!trip) {
      return res.status(404).json({ error: "Viaje no encontrado" });
    }
    
    const isDriver = trip.driverId && (trip.driverId._id?.toString() === meId || trip.driverId.toString() === meId);
    const isPassenger = trip.bookings && trip.bookings.some(b => {
      if (!b.passengerId || b.status !== "accepted") return false;
      const passengerId = b.passengerId._id || b.passengerId;
      return passengerId.toString() === meId;
    });
    
    if (!isDriver && !isPassenger) {
      return res.status(403).json({ error: "No tienes acceso a esta conversación" });
    }
    
    // Obtener mensajes de esta conversación
    const messages = await Message.find({ tripId })
      .populate('senderId', 'nombre')
      .populate('receiverId', 'nombre')
      .sort({ createdAt: 1 })
      .lean();
    
    return res.json({ messages });
  } catch (e) {
    console.error("❌ Error al obtener mensajes:", e);
    return res.status(500).json({ error: "Error al obtener mensajes" });
  }
});

// Enviar mensaje
app.post("/api/chat/trips/:tripId/messages", authRequired, async (req, res) => {
  try {
    const meId = req.user.id;
    const tripId = req.params.tripId;
    const { message, receiverId } = req.body;
    
    if (!message || !message.trim()) {
      return res.status(400).json({ error: "El mensaje no puede estar vacío" });
    }
    
    // Verificar que el usuario tenga acceso a esta conversación
    const trip = await Trip.findById(tripId)
      .populate('driverId', '_id')
      .populate('bookings.passengerId', '_id')
      .lean();
    
    if (!trip) {
      return res.status(404).json({ error: "Viaje no encontrado" });
    }
    
    const isDriver = trip.driverId && (trip.driverId._id?.toString() === meId || trip.driverId.toString() === meId);
    const isPassenger = trip.bookings && trip.bookings.some(b => {
      if (!b.passengerId || b.status !== "accepted") return false;
      const passengerId = b.passengerId._id || b.passengerId;
      return passengerId.toString() === meId;
    });
    
    if (!isDriver && !isPassenger) {
      return res.status(403).json({ error: "No tienes acceso a esta conversación" });
    }
    
    // Determinar el receptor
    let actualReceiverId;
    if (isDriver) {
      // Si soy conductor, el receptor es el pasajero
      // Si se especificó receiverId, usarlo; si no, usar el primer pasajero aceptado
      if (receiverId) {
        const booking = trip.bookings.find(b => {
          if (b.status !== "accepted" || !b.passengerId) return false;
          const passengerId = b.passengerId._id || b.passengerId;
          return passengerId.toString() === receiverId.toString();
        });
        if (!booking) {
          return res.status(400).json({ error: "Pasajero no encontrado o no aceptado en este viaje" });
        }
        actualReceiverId = booking.passengerId._id || booking.passengerId;
      } else {
        // Si no se especifica, usar el primer pasajero aceptado
        const acceptedBooking = trip.bookings.find(b => b.status === "accepted" && b.passengerId);
        if (!acceptedBooking || !acceptedBooking.passengerId) {
          return res.status(400).json({ error: "No hay pasajeros aceptados en este viaje" });
        }
        actualReceiverId = acceptedBooking.passengerId._id || acceptedBooking.passengerId;
      }
    } else {
      // Si soy pasajero, el receptor es el conductor
      actualReceiverId = trip.driverId._id || trip.driverId;
    }
    
    // Crear mensaje
    const newMessage = await Message.create({
      tripId,
      senderId: meId,
      receiverId: actualReceiverId,
      message: message.trim()
    });
    
    const populatedMessage = await Message.findById(newMessage._id)
      .populate('senderId', 'nombre')
      .populate('receiverId', 'nombre')
      .lean();
    
    return res.status(201).json({ 
      message: "Mensaje enviado ✅",
      data: populatedMessage
    });
  } catch (e) {
    console.error("❌ Error al enviar mensaje:", e);
    return res.status(500).json({ error: "Error al enviar mensaje" });
  }
});

// Marcar mensajes como leídos
app.put("/api/chat/trips/:tripId/messages/read", authRequired, async (req, res) => {
  try {
    const meId = req.user.id;
    const tripId = req.params.tripId;
    
    // Marcar como leídos todos los mensajes donde el usuario es el receptor
    await Message.updateMany(
      { tripId, receiverId: meId, read: false },
      { read: true }
    );
    
    return res.json({ message: "Mensajes marcados como leídos" });
  } catch (e) {
    console.error("❌ Error al marcar mensajes como leídos:", e);
    return res.status(500).json({ error: "Error al marcar mensajes como leídos" });
  }
});

// Cancelar reserva (rol: pasajero)
app.delete("/api/trips/:tripId/bookings", authRequired, async (req, res) => {
  try {
    const me = await User.findById(req.user.id);
    if (!me) return res.status(401).json({ error: "No autorizado" });
    if (!me.rolesCompleted?.pasajero) return res.status(403).json({ error: "Debes completar onboarding de pasajero" });

    const trip = await Trip.findById(req.params.tripId);
    if (!trip) return res.status(404).json({ error: "Viaje no encontrado" });

    // Buscar la reserva del pasajero
    const bookingIndex = trip.bookings.findIndex(
      b => b.passengerId.toString() === me._id.toString()
    );
    
    if (bookingIndex === -1) {
      return res.status(404).json({ error: "No tienes una reserva en este viaje" });
    }

    const booking = trip.bookings[bookingIndex];
    const seatsToFree = booking.seats || 1;

    // Si la reserva estaba aceptada, liberar los asientos
    if (booking.status === "accepted") {
      const acceptedBookings = trip.bookings.filter(b => b.status === "accepted");
      const totalAcceptedSeats = acceptedBookings.reduce((sum, b) => sum + (b.seats || 1), 0);
      // Restar los asientos de esta reserva que vamos a eliminar
      const newTotalAcceptedSeats = totalAcceptedSeats - seatsToFree;
      trip.seatsAvailable = trip.seatsTotal - newTotalAcceptedSeats;
    }

    // Eliminar la reserva del array
    trip.bookings.splice(bookingIndex, 1);
    await trip.save();

    return res.json({ 
      message: `Reserva cancelada exitosamente. Se liberaron ${seatsToFree} asiento${seatsToFree > 1 ? 's' : ''} ✅`, 
      tripId: trip._id,
      seatsAvailable: trip.seatsAvailable
    });
  } catch (e) {
    console.error("❌ Error al cancelar reserva:", e);
    return res.status(500).json({ error: "Error al cancelar reserva" });
  }
});