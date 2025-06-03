import { body } from 'express-validator';

export const validateRegister = [
    body('email').isEmail().withMessage('Invalid email'),
    body('username').isAlphanumeric().withMessage('Username must be alphanumeric'),
    body('password').isStrongPassword().withMessage('Weak password'),
    body('confirmPassword').notEmpty(),
    body('agreeToTerms').equals('true').withMessage('Must accept terms')
];