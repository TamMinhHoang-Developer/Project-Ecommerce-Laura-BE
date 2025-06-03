import axios from 'axios';
import dotenv from 'dotenv';

dotenv.config();

const captchaValidator = async (req, res, next) => {
    const token = req.body['g-recaptcha-response'];

    if (!token) {
        return res.status(400).json({ message: 'Invalid or missing CAPTCHA.' });
    }

    try {
        const response = await axios.post(
            `https://www.google.com/recaptcha/api/siteverify?secret=${process.env.RECAPTCHA_SECRET_KEY}&response=${token}&remoteip=${req.ip}`
        );

        const { success, score, action } = response.data;

        if (!success) {
            return res.status(400).json({ message: 'CAPTCHA verification failed.' });
        }

        next();
    } catch (err) {
        console.error('CAPTCHA verification failed:', err);
        return res.status(500).json({ message: 'Unable to verify CAPTCHA.' });
    }
};

export default captchaValidator;