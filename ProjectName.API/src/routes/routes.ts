import { Router } from "express";
import userRoutes from "./userRoutes";
import authRoutes from "./authRoutes";
// Import other route files here
// import productRoutes from './productRoutes';

// Create main router instance
const router = Router();

// Health check endpoint to verify API is running
router.get("/main/healthcheck", (req, res) => {
  res.status(200).json({
    message: "API is healthy",
  });
});

// Mount user routes under /api/users prefix
router.use("/api/users", userRoutes);
router.use("/api/auth", authRoutes);
// Add other routes with their prefixes
// router.use('/api/products', productRoutes);

export default router;
