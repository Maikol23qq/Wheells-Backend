// server.js - VERSIÓN COMPLETA CON DEBUG
import express from "express";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import mongoose from "mongoose";
import User from "./models/User.js";
import Trip from "./models/Trip.js";

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
const RATE_MAX = 60; // 60 req/min por IP (global simple)
const RATE_MAX_AUTH = 10; // 10 req/min para /api/auth/*
const ipHits = new Map();

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
      return res.status(429).json({ error: "Demasiadas solicitudes, intenta más tarde" });
    }
    next();
  };
}

// Global suave y específico para auth
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
    await mongoose.connect(MONGODB_URI || "mongodb://127.0.0.1:27017/wheells", { 
      dbName: "wheells",
      serverSelectionTimeoutMS: 5000, // Timeout de 5 segundos
      socketTimeoutMS: 45000,
    });
    console.log("✅ Conectado a MongoDB");
    return true;
  } catch (err) {
    console.error("❌ Error conectando a MongoDB:", err.message);
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
app.post("/api/auth/register", rateLimiter(RATE_MAX_AUTH), async (req, res) => {
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
app.post("/api/auth/login", rateLimiter(RATE_MAX_AUTH), async (req, res) => {
  try {
    const { email, password } = req.body;
    const isValidEmail = (v) => /.+@.+\..+/.test(v);
    if (!isValidEmail(email)) return res.status(400).json({ error: "Email inválido" });

    console.log("🔐 Intento de login:", email);

    const user = await User.findOne({ email });
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
    await user.save();

    const token = signAppToken({ id: user._id.toString(), role: effectiveRole });

    console.log("✅ Login exitoso:", email);

    res.json({
      message: "Inicio de sesión exitoso ✅",
      token,
      role: effectiveRole,
      nombre: user.nombre,
      userId: user._id
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
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: "Usuario no encontrado" });

    user.rolesCompleted.pasajero = true;
    user.status = "active";
    if (!user.currentRole) user.currentRole = "pasajero";
    await user.save();

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
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: "Usuario no encontrado" });

    user.rolesCompleted.conductor = true;
    user.status = "active";
    if (!user.currentRole) user.currentRole = "conductor";
    if (req.body) {
      user.vehicle.marca = req.body.marca || user.vehicle.marca;
      user.vehicle.modelo = req.body.modelo || user.vehicle.modelo;
      user.vehicle.anio = req.body.anio || user.vehicle.anio;
      user.vehicle.placa = req.body.placa || user.vehicle.placa;
    }
    await user.save();

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
app.get("/api/user/me", authRequired, async (req, res) => {
  const user = await User.findById(req.user.id).lean();
  if (!user) return res.status(404).json({ error: "Usuario no encontrado" });
  return res.json({
    id: user._id,
    nombre: user.nombre,
    email: user.email,
    rolesCompleted: user.rolesCompleted,
    currentRole: user.currentRole,
    status: user.status,
    vehicle: user.vehicle
  });
});

// =====================
// 🔄 Cambiar rol actual (si está completado)
// =====================
app.put("/api/user/role", authRequired, async (req, res) => {
  const { role } = req.body;
  if (role !== "pasajero" && role !== "conductor") {
    return res.status(400).json({ error: "Rol inválido" });
  }
  const user = await User.findById(req.user.id);
  if (!user) return res.status(404).json({ error: "Usuario no encontrado" });
  if (!user.rolesCompleted[role]) {
    return res.status(400).json({ error: "Debes completar el onboarding de este rol" });
  }
  user.currentRole = role;
  await user.save();
  const token = signAppToken({ id: user._id.toString(), role: user.currentRole });
  return res.json({ message: "Rol cambiado ✅", role: user.currentRole, token });
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
    const criteria = { seatsAvailable: { $gt: 0 } };
    
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
      .populate('driverId', 'nombre email vehicle')
      .sort({ departureTime: 1 })
      .limit(100)
      .lean();
    
    // Formatear respuesta para incluir información del conductor
    const formattedTrips = trips.map(trip => ({
      ...trip,
      driver: trip.driverId ? {
        nombre: trip.driverId.nombre,
        vehicle: trip.driverId.vehicle
      } : null
    }));
    
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
    const asDriver = await Trip.find({ driverId: meId }).sort({ createdAt: -1 }).lean();
    const asPassenger = await Trip.find({ "bookings.passengerId": meId }).sort({ createdAt: -1 }).lean();
    return res.json({ asDriver, asPassenger });
  } catch (e) {
    console.error("❌ Error al listar viajes del usuario:", e);
    return res.status(500).json({ error: "Error al listar viajes" });
  }
});

// Reservar un viaje (rol: pasajero)
app.post("/api/trips/:id/book", authRequired, async (req, res) => {
  try {
    const me = await User.findById(req.user.id);
    if (!me) return res.status(401).json({ error: "No autorizado" });
    if (!me.rolesCompleted?.pasajero) return res.status(403).json({ error: "Debes completar onboarding de pasajero" });

    const trip = await Trip.findById(req.params.id);
    if (!trip) return res.status(404).json({ error: "Viaje no encontrado" });
    if (trip.seatsAvailable <= 0) return res.status(400).json({ error: "No hay asientos disponibles" });
    if (trip.driverId.toString() === me._id.toString()) return res.status(400).json({ error: "No puedes reservar tu propio viaje" });
    const already = trip.bookings.some(b => b.passengerId.toString() === me._id.toString());
    if (already) return res.status(400).json({ error: "Ya estás reservado en este viaje" });

    trip.bookings.push({ passengerId: me._id });
    trip.seatsAvailable -= 1;
    await trip.save();
    return res.json({ message: "Reserva confirmada", tripId: trip._id, seatsAvailable: trip.seatsAvailable });
  } catch (e) {
    console.error("❌ Error al reservar viaje:", e);
    return res.status(500).json({ error: "Error al reservar" });
  }
});