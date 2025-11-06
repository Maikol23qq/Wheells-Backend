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
    marca: { type: String },
    modelo: { type: String },
    anio: { type: String },
    placa: { type: String },
    photoUrl: { type: String }
  },
  { _id: false }
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
    vehicle: { type: VehicleSchema, default: () => ({}) }
  },
  { timestamps: true }
);

export default mongoose.models.User || mongoose.model("User", UserSchema);