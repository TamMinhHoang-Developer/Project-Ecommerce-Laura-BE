import express from 'express';

import { login } from '../controllers/auth.controller.js';
import loginLimiter from '../middlewares/loginLimited.middleware.js';
import csrfProtection from '../middlewares/csrf.middleware.js';

const router = express.Router();

router.post('/login', login);

export default router;