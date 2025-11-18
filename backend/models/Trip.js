import mongoose from "mongoose";

const BookingSchema = new mongoose.Schema(
  {
    passengerId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    seats: { type: Number, required: true, min: 1, default: 1 },
    status: { type: String, enum: ["pending", "accepted", "rejected"], default: "pending" },
    requestedAt: { type: Date, default: Date.now },
    respondedAt: { type: Date }
  },
  { _id: false }
);

const TripSchema = new mongoose.Schema(
  {
    driverId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },
    vehicleId: { type: mongoose.Schema.Types.ObjectId, ref: "User.vehicles", required: false }, // ID del vehículo usado
    from: { type: String, required: true },
    to: { type: String, required: true },
    route: { type: String, default: "" }, // Ruta/paradas del viaje
    departureTime: { type: Date, required: true },
    price: { type: Number, required: true, min: 0 },
    seatsTotal: { type: Number, required: true, min: 1 },
    seatsAvailable: { type: Number, required: true, min: 0 },
    bookings: { type: [BookingSchema], default: () => [] }
  },
  { timestamps: true }
);

export default mongoose.models.Trip || mongoose.model("Trip", TripSchema);
