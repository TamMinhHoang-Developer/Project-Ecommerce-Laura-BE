import express from 'express';
import cookieParser from 'cookie-parser';
import authRoutes from './routes/auth.routes.js';
import cors from 'cors';

const app = express();

app.use(express.json());
app.use(cookieParser());

const allowedOrigins = [
    'http://localhost:3000',
    'http://127.0.0.1:3000',
];

app.use(cors({
    origin: (origin, callback) => {
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true
}));

app.use('/api/auth', authRoutes);

export default app;