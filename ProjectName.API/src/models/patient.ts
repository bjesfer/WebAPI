// Import mongoose and Schema class from mongoose package
import mongoose, { Schema } from "mongoose";
import { IPatient } from "../interfaces/patientInterface";

// Define a schema for Patient documents in MongoDB
export const patientSchema = new Schema(
  {
    // Basic patient information
    firstName: { type: String, length: 50, required: true }, // Required field, max 50 chars
    lastName: { type: String, length: 50, required: true }, // Required field, max 50 chars

    // Patient's address details (all optional)
    street1: { type: String, length: 50 }, // Primary street address
    street2: { type: String, length: 50 }, // Secondary street address (apt, unit, etc.)
    city: { type: String, length: 50 }, // City name
    state: { type: String, length: 50 }, // State/Province
    postalCode: { type: String, length: 50 }, // ZIP/Postal code fdsfs

    // Additional patient details
    dateOfBirth: { type: Date }, // Patient's birth date
    contactNumber: { type: String, length: 50 }, // Phone number
  },
  // Add automatic timestamp fields (createdAt, updatedAt)
  { timestamps: true }
);

// Create and export the Patient model
// This will create a 'patients' collection in MongoDB
export const Patient = mongoose.model<IPatient>("Patients", patientSchema);
