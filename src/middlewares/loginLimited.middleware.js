import rateLimit from 'express-rate-limit';

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Too many failed login attempts. Please try again in 15 minutes.',
  standardHeaders: true,
  legacyHeaders: false,
});

export default loginLimiter;