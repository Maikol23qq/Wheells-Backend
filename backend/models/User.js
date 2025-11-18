import mongoose from "mongoose";

const RolesCompletedSchema = new mongoose.Schema(
  {
    pasajero: { type: Boolean, default: false },
    conductor: { type: Boolean, default: false }
  },
  { _id: false }
);

const VehicleSchema = new mongoose.Schema(
  {
    marca: { type: String, required: true },
    modelo: { type: String, required: true },
    anio: { type: String, required: true },
    placa: { type: String, required: true },
    photoUrl: { type: String },
    soatPhotoUrl: { type: String } // Foto del SOAT
  },
  { _id: true, timestamps: true }
);

const UserSchema = new mongoose.Schema(
  {
    nombre: { type: String, required: true },
    email: { type: String, required: true, unique: true, index: true },
    password: { type: String, required: true },
    telefono: { type: String },
    idUniversitario: { type: String },
    photoUrl: { type: String },
    rolesCompleted: { type: RolesCompletedSchema, default: () => ({}) },
    currentRole: { type: String, enum: ["pasajero", "conductor", null], default: null },
    preferredRole: { type: String, enum: ["pasajero", "conductor"], default: "pasajero" },
    status: { type: String, enum: ["pending", "active"], default: "pending" },
    vehicles: { type: [VehicleSchema], default: [] } // Array de vehículos
  },
  { timestamps: true }
);

export default mongoose.models.User || mongoose.model("User", UserSchema);