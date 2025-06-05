import dotenv from 'dotenv';
import { Resend } from 'resend';

dotenv.config();

// Function to send verification email
export const sendVerificationEmail = async (to, token) => {
  const resend = new Resend(process.env.RESEND_API_KEY);
  await resend.emails.send({
    from: 'onboarding@resend.dev',
    to: process.env.RESEND_EMAIL_FROM_TEST,
    subject: 'Hello World',
    html: '<p>Congrats on sending your <strong>first email</strong>!</p>'
  })
};

// Function to send welcome email
export const sendWelcomeEmail = async (to) => {
  const resend = new Resend(process.env.RESEND_API_KEY);
  await resend.emails.send({
    from: 'onboarding@resend.dev',
    to: process.env.RESEND_EMAIL_FROM_TEST,
    subject: 'Hello World Welcome',
    html: '<p>Congrats on sending your <strong>first email</strong>!</p>'
  })
};
