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

// Function to send Suspicious login email
export const sendSuspiciousLoginEmail = async (email, ip, device, geo) => {
  const resend = new Resend(process.env.RESEND_API_KEY);
  await resend.emails.send({
    from: 'onboarding@resend.dev',
    to: process.env.RESEND_EMAIL_FROM_TEST,
    subject: 'Hello World Welcome',
    html: `
      <p>Suspicious login detected for your account.</p>
        <ul>
          <li>Email: ${email}</li>
          <li>IP: ${ip}</li>
          <li>Device: ${device}</li>
          <li>Location: ${geo}</li>
        </ul>
      <p>If this is you, you can ignore it. If not, change your password now!</p>
    `
  })
};

// Function to send password reset email
export const sendPasswordResetEmail = async (to, code) => {
  const resend = new Resend(process.env.RESEND_API_KEY);

  await resend.emails.send({
    from: 'onboarding@resend.dev',
    to: process.env.RESEND_EMAIL_FROM_TEST,
    subject: 'Reset your password',
    html: `<p>Your reset code is: <strong>${code}</strong>. It expires in 15 minutes.</p>`
  });
}