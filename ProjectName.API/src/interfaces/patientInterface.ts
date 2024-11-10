import { Document } from "mongoose";

export interface IPatient extends Document {
  firstName: string;
  lastName: string;
  street1?: string;
  street2?: string;
  city?: string;
  state?: string;
  postalCode?: string;
  dateOfBirth?: Date;
  contactNumber?: string;
}
