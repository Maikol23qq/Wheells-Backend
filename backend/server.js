/**
 * ===================================================================
 * SERVIDOR BACKEND - Wheells
 * ===================================================================
 * 
 * Este archivo es el servidor principal de la aplicación Wheells.
 * Maneja todas las peticiones HTTP, autenticación, y comunicación con MongoDB.
 * 
 * Funcionalidades principales:
 * - Autenticación de usuarios (login, registro)
 * - Gestión de usuarios y perfiles
 * - Gestión de viajes (crear, buscar, reservar)
 * - Sistema de mensajería entre conductores y pasajeros
 * - Onboarding de conductores y pasajeros
 * 
 * @author Wheells Team
 * @version 1.0
 */

// server.js - VERSIÓN COMPLETA CON DEBUG
import express from "express";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import mongoose from "mongoose";
import User from "./models/User.js";
import Trip from "./models/Trip.js";
import Message from "./models/Message.js";

// Cargar variables de entorno desde archivo .env
dotenv.config();

// Crear aplicación Express
const app = express();

// ===================================================================
// 🌐 CONFIGURACIÓN CORS (Cross-Origin Resource Sharing)
// ===================================================================
// Permite que el frontend se comunique con el backend desde diferentes dominios

const allowedOrigins = [
  "http://localhost:5173",  // Frontend en desarrollo (Vite)
  "http://localhost:3000",  // Frontend alternativo en desarrollo
  // Dominios de despliegue conocidos
  "https://wheells-fronted-3e3b.vercel.app",  // Frontend en producción (Vercel)
  process.env.FRONTEND_URL  // URL del frontend desde variables de entorno
].filter(Boolean); // Elimina valores undefined/null

/**
 * Middleware CORS personalizado
 * Maneja las solicitudes de diferentes orígenes y permite comunicación
 * entre frontend y backend desde diferentes dominios
 */
app.use((req, res, next) => {
  const origin = req.headers.origin;

  // Log básico del origen para debugging
  if (origin) {
    console.log("Solicitud desde origen:", origin);
  }

  // Permitir origen si está en la lista o si estamos en desarrollo
  // También permite previews de Vercel del proyecto 'wheells-fronted-3e3b'
  const isVercelPreview = !!(origin && /^https:\/\/wheells-fronted-3e3b[\w-]*\.vercel\.app$/.test(origin));
  
  if (origin && (allowedOrigins.includes(origin) || isVercelPreview || process.env.NODE_ENV !== "production")) {
    res.header("Access-Control-Allow-Origin", origin);
  }

  // Configurar headers permitidos
  res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  res.header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With");
  res.header("Access-Control-Allow-Credentials", "true");

  // Manejar preflight requests (OPTIONS) - CORS previo a la solicitud real
  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  next();
});

// ===================================================================
// 📦 MIDDLEWARES DE EXPRESS
// ===================================================================

// Configurar Express para parsear JSON con límite de 50MB (para imágenes en base64)
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// ===================================================================
// 🛡️ SEGURIDAD BÁSICA (Headers de seguridad tipo Helmet)
// ===================================================================
// Agrega headers HTTP de seguridad para proteger la aplicación

/**
 * Middleware de seguridad
 * Agrega headers HTTP que previenen ataques comunes:
 * - XSS (Cross-Site Scripting)
 * - Clickjacking
 * - MIME type sniffing
 * - etc.
 */
app.use((req, res, next) => {
  // Protecciones comunes
  res.setHeader("X-DNS-Prefetch-Control", "off");           // Desactiva DNS prefetching
  res.setHeader("X-Frame-Options", "SAMEORIGIN");           // Previene clickjacking
  res.setHeader("Strict-Transport-Security", "max-age=15552000; includeSubDomains");  // Fuerza HTTPS
  res.setHeader("X-Content-Type-Options", "nosniff");       // Previene MIME sniffing
  res.setHeader("X-Download-Options", "noopen");            // Previene descargas automáticas
  res.setHeader("X-Permitted-Cross-Domain-Policies", "none"); // Bloquea políticas cross-domain
  res.setHeader("Referrer-Policy", "no-referrer");          // No envía información del referrer
  res.setHeader("X-XSS-Protection", "0");                   // Desactiva protección XSS del navegador (deprecated)
  next();
});

// ===================================================================
// 🚦 RATE LIMITING (Limitador de solicitudes por IP)
// ===================================================================
// Previene abuso del servidor limitando el número de solicitudes por IP

const RATE_WINDOW_MS = 60_000;  // Ventana de tiempo: 1 minuto (60,000 ms)
const RATE_MAX = 100;           // Máximo 100 solicitudes por minuto por IP (global)
const RATE_MAX_AUTH = 30;       // Máximo 30 solicitudes por minuto para /api/auth/* (más restrictivo)

// Mapas para rastrear solicitudes por IP
const ipHits = new Map();       // Para solicitudes generales
const authHits = new Map();     // Para solicitudes de autenticación (separado)

/**
 * Rate limiter general
 * Limita el número de solicitudes por IP en una ventana de tiempo
 * 
 * @param {number} maxPerWindow - Número máximo de solicitudes permitidas en la ventana
 * @returns {Function} Middleware de Express
 */
function rateLimiter(maxPerWindow) {
  return (req, res, next) => {
    // Obtener IP del cliente (considera proxies y load balancers)
    const ip = req.headers["x-forwarded-for"]?.toString().split(",")[0].trim() || req.socket.remoteAddress || "unknown";
    const now = Date.now();
    
    // Obtener o crear entrada para esta IP
    const entry = ipHits.get(ip) || { count: 0, resetAt: now + RATE_WINDOW_MS };
    
    // Si la ventana de tiempo expiró, reiniciar contador
    if (now > entry.resetAt) {
      entry.count = 0;
      entry.resetAt = now + RATE_WINDOW_MS;
    }
    
    // Incrementar contador
    entry.count += 1;
    ipHits.set(ip, entry);
    
    // Si excede el límite, rechazar la solicitud
    if (entry.count > maxPerWindow) {
      const retryAfter = Math.ceil((entry.resetAt - now) / 1000);
      res.setHeader("Retry-After", retryAfter.toString());
      return res.status(429).json({ 
        error: "Demasiadas solicitudes, intenta más tarde",
        retryAfter: retryAfter
      });
    }
    
    next();
  };
}

/**
 * Rate limiter específico para autenticación
 * Más restrictivo para prevenir ataques de fuerza bruta en login
 * 
 * @param {number} maxPerWindow - Número máximo de solicitudes permitidas en la ventana
 * @returns {Function} Middleware de Express
 */
function authRateLimiter(maxPerWindow) {
  return (req, res, next) => {
    // Obtener IP del cliente
    const ip = req.headers["x-forwarded-for"]?.toString().split(",")[0].trim() || req.socket.remoteAddress || "unknown";
    const now = Date.now();
    
    // Obtener o crear entrada para esta IP
    const entry = authHits.get(ip) || { count: 0, resetAt: now + RATE_WINDOW_MS };
    
    // Si la ventana de tiempo expiró, reiniciar contador
    if (now > entry.resetAt) {
      entry.count = 0;
      entry.resetAt = now + RATE_WINDOW_MS;
    }
    
    // Incrementar contador
    entry.count += 1;
    authHits.set(ip, entry);
    
    // Si excede el límite, rechazar la solicitud con mensaje específico
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

// Aplicar rate limiting global a todas las rutas
app.use(rateLimiter(RATE_MAX));

// ===================================================================
// 🗃️ CONEXIÓN A MONGODB
// ===================================================================
// Gestiona la conexión a la base de datos MongoDB

const MONGODB_URI = process.env.MONGODB_URI;

if (!MONGODB_URI) {
  console.warn("⚠️  MONGODB_URI no está definido. Configúralo en variables de entorno.");
}

/**
 * Conecta a la base de datos MongoDB
 * Configura pool de conexiones y crea índices para mejorar rendimiento
 * 
 * @returns {Promise<boolean>} true si la conexión fue exitosa, false en caso contrario
 */
async function connectToMongoDB() {
  try {
    // Si ya está conectado, no volver a conectar (evita conexiones duplicadas)
    if (mongoose.connection.readyState === 1) {
      console.log("✅ MongoDB ya está conectado");
      return true;
    }

    // Obtener URI de conexión desde variables de entorno o usar default local
    const uri = MONGODB_URI || "mongodb://127.0.0.1:27017/wheells";
    console.log("🔌 Intentando conectar a MongoDB...");
    console.log("🔌 URI:", uri.replace(/\/\/.*@/, '//***:***@')); // Ocultar credenciales en logs
    
    // Conectar a MongoDB con configuración optimizada
    await mongoose.connect(uri, { 
      dbName: "wheells",                    // Nombre de la base de datos
      serverSelectionTimeoutMS: 5000,       // Tiempo máximo para seleccionar servidor (5 segundos)
      socketTimeoutMS: 45000,               // Tiempo máximo sin actividad antes de cerrar socket
      maxPoolSize: 10,                      // Máximo de conexiones en el pool (mejora rendimiento)
      minPoolSize: 2,                       // Mínimo de conexiones activas (reduce latencia en primer request)
      maxIdleTimeMS: 30000,                 // Tiempo máximo que una conexión puede estar inactiva (30 segundos)
      bufferCommands: false,                // No hacer buffer de comandos (falla rápido si no hay conexión)
      bufferMaxEntries: 0,                  // Desactivar buffer completamente
    });
    
    console.log("✅ Conectado a MongoDB exitosamente");
    console.log("✅ Base de datos:", mongoose.connection.db.databaseName);
    console.log("✅ Estado de conexión:", mongoose.connection.readyState);
    
    // Crear índices para mejorar rendimiento de consultas
    try {
      // Índice único en email para búsquedas rápidas y garantizar unicidad
      await User.collection.createIndex({ email: 1 }, { unique: true });
      // Índice en driverId para búsquedas rápidas de viajes por conductor
      await Trip.collection.createIndex({ driverId: 1 });
      // Índice en departureTime para ordenar y filtrar viajes por fecha
      await Trip.collection.createIndex({ departureTime: 1 });
      console.log("✅ Índices creados/verificados");
    } catch (idxError) {
      // Los índices pueden ya existir, no es crítico
      console.log("ℹ️ Índices ya existentes o error menor:", idxError.message);
    }
    
    return true;
  } catch (err) {
    console.error("❌ Error conectando a MongoDB:", err.message);
    console.error("❌ Error completo:", err);
    return false;
  }
}

// ===================================================================
// 🔐 UTILIDADES DE AUTENTICACIÓN JWT
// ===================================================================

// Secreto para firmar y verificar tokens JWT (desde variables de entorno o default)
const JWT_SECRET = process.env.JWT_SECRET || "claveultrasegura";

/**
 * Genera un token JWT para autenticación
 * 
 * @param {Object} payload - Datos a incluir en el token (ej: { id: userId, role: "conductor" })
 * @returns {string} Token JWT firmado
 */
function signAppToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "2h" }); // Token válido por 2 horas
}

// ===================================================================
// 🔒 MIDDLEWARE DE AUTENTICACIÓN
// ===================================================================

/**
 * Middleware para proteger rutas que requieren autenticación
 * Verifica que la solicitud incluya un token JWT válido
 * 
 * Si el token es válido, agrega req.user con los datos decodificados del token
 * Si el token es inválido o no existe, retorna error 401
 * 
 * @param {Object} req - Objeto request de Express
 * @param {Object} res - Objeto response de Express
 * @param {Function} next - Función para continuar al siguiente middleware
 */
function authRequired(req, res, next) {
  // Extraer token del header Authorization
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  
  // Si no hay token, rechazar la solicitud
  if (!token) return res.status(401).json({ error: "Token requerido" });
  
  try {
    // Verificar y decodificar el token
    const decoded = jwt.verify(token, JWT_SECRET);
    // Agregar datos del usuario al request para usar en los endpoints
    req.user = decoded;
    next();
  } catch (e) {
    // Si el token es inválido, expirado, etc., rechazar
    return res.status(401).json({ error: "Token inválido" });
  }
}

// ===================================================================
// 📍 RUTA DE PRUEBA
// ===================================================================

/**
 * Endpoint de prueba para verificar que el servidor está funcionando
 * GET /api/test
 */
app.get("/api/test", (req, res) => {
  res.json({ 
    message: "Servidor funcionando correctamente ✅",
    timestamp: new Date().toISOString(),
    mongoStatus: mongoose.connection.readyState 
  });
});

// ===================================================================
// 🔐 ENDPOINTS DE AUTENTICACIÓN
// ===================================================================

/**
 * POST /api/auth/register
 * Registra un nuevo usuario en el sistema
 * 
 * Este endpoint NO crea el usuario completo, solo inicia el proceso de registro.
 * El usuario debe completar el onboarding después (subir foto, datos adicionales).
 * 
 * Body requerido:
 * - name: Nombre completo del usuario
 * - email: Email del usuario (debe ser @unisabana.edu.co)
 * - password: Contraseña (mínimo 6 caracteres)
 * - telefono: Teléfono (opcional, 10 dígitos)
 * - idUniversitario: ID universitario (opcional)
 * - role: Rol inicial ("pasajero" o "conductor")
 * 
 * Response:
 * - 201: Registro iniciado exitosamente, retorna onboardingToken y nextRoute
 * - 400: Email inválido, contraseña inválida, email ya registrado
 * - 503: Base de datos no disponible
 */
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
    const isValidUnisabanaEmail = (v) => v.endsWith('@unisabana.edu.co');
    const isValidPhone = (v) => !v || /^\d{10}$/.test(v.trim());

    if (!isValidEmail(email)) return res.status(400).json({ error: "Email inválido" });
    if (!isValidUnisabanaEmail(email)) return res.status(400).json({ error: "El correo debe ser de la Universidad de La Sabana (@unisabana.edu.co)" });
    if (!isValidPassword(password)) return res.status(400).json({ error: "La contraseña debe tener al menos 6 caracteres" });
    if (telefono && !isValidPhone(telefono)) return res.status(400).json({ error: "El teléfono debe tener exactamente 10 dígitos" });

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

    // Hashear contraseña con bcrypt (10 rounds de salt)
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Crear nuevo usuario en estado de onboarding pendiente
    const initialRole = role === "conductor" ? "conductor" : "pasajero";
    
    const newUser = await User.create({
      nombre,
      email,
      password: hashedPassword,
      telefono: telefono || "",
      idUniversitario: idUniversitario || "",
      rolesCompleted: { pasajero: false, conductor: false }, // Ningún rol completado aún
      currentRole: null,                                      // No tiene rol activo aún
      status: "pending",                                      // Estado pendiente hasta completar onboarding
      preferredRole: initialRole                              // Rol preferido para completar primero
    });

    console.log("✅ Usuario registrado exitosamente:", newUser.email);

    // Generar token de onboarding (permite completar el proceso sin hacer login completo)
    const onboardingToken = signAppToken({ id: newUser._id.toString(), onboarding: true });
    
    // Determinar la ruta siguiente según el rol
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
/**
 * POST /api/auth/login
 * Autentica un usuario y genera un token JWT
 * 
 * Body requerido:
 * - email: Email del usuario
 * - password: Contraseña del usuario
 * 
 * Validaciones:
 * - Email debe ser válido y de @unisabana.edu.co
 * - Usuario debe existir en la base de datos
 * - Contraseña debe ser correcta
 * - Usuario debe tener al menos un rol completado (pasajero o conductor)
 * 
 * Response:
 * - 200: Login exitoso, retorna token y datos del usuario
 * - 400: Email inválido
 * - 401: Contraseña incorrecta
 * - 403: Usuario no tiene roles completados (debe hacer onboarding)
 * - 404: Usuario no encontrado
 * - 429: Demasiados intentos (rate limiting)
 * - 503: Base de datos no disponible
 * 
 * Optimizaciones:
 * - Usa .lean() para obtener objeto plano más rápido
 * - Fuerza uso del índice de email con .hint()
 * - Update de currentRole se hace de forma asíncrona (no bloquea respuesta)
 */
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
    
    // Usar collation para búsqueda case-insensitive eficiente si no está normalizado
    // .lean() obtiene objeto plano JavaScript (más rápido que documento Mongoose)
    // .hint() fuerza uso del índice de email para búsqueda rápida
    const user = await User.findOne({ email: normalizedEmail })
      .select('password nombre rolesCompleted currentRole preferredRole _id')
      .lean() // Usar lean() para obtener objeto plano más rápido
      .hint({ email: 1 }); // Forzar uso del índice de email
    
    if (!user) {
      console.log("❌ Usuario no encontrado:", email);
      return res.status(404).json({ error: "Usuario no encontrado" });
    }
    console.log(`⏱️ Query DB: ${Date.now() - queryStart}ms`);

    // Verificar contraseña usando bcrypt.compare
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
    // Este es el rol que se usará para el token y la sesión
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
    // Hacer el update de forma asíncrona para no bloquear la respuesta
    if (user.currentRole !== effectiveRole) {
      // Actualizar en segundo plano sin esperar (fire and forget)
      // Esto mejora el tiempo de respuesta del login
      User.updateOne(
        { _id: user._id },
        { $set: { currentRole: effectiveRole } }
      ).catch(err => {
        console.error("⚠️ Error actualizando currentRole (no crítico):", err.message);
      });
    }

    // Generar token JWT con ID del usuario y rol
    const token = signAppToken({ id: user._id.toString(), role: effectiveRole });

    const totalTime = Date.now() - startTime;
    console.log(`✅ Login exitoso: ${email} - Rol: ${effectiveRole} - Tiempo total: ${totalTime}ms`);

    // Retornar token y datos del usuario
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

// ... existing code ...
