import express from 'express';
import { registerUser, loginUser } from '../controllers/auth.controller.js';
// import loginLimiter from '../middlewares/loginLimited.middleware.js';
// import captchaValidator from '../middlewares/captchaValidator.middleware.js';
// import csrfProtection from '../middlewares/csrf.middleware.js';

const router = express.Router();

router.post('/register', registerUser)
router.post('/login', loginUser)

export default router;