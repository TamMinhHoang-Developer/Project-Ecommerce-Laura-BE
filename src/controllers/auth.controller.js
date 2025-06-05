import bcrypt from 'bcrypt';
import validator from 'validator';
import supabase from '../config/supabaseClient.js';

import { v4 as uuidv4 } from 'uuid';
import { getDeviceFingerprint } from '../utils/device.util.js';
import { getGeoIP } from '../utils/geoip.util.js';

import { sendVerificationEmail, sendWelcomeEmail } from '../services/email.service.js';

//* [POST] /api/auth/register - Register a new user 
export const registerUser = async (req, res) => {
  const { email, username, password, confirmPassword, agreeToTerms } = req.body;

  //* Validation Input
  if (!email || !username || !password) {
    return res.status(400).json({ message: 'Please fill in all information.' });
  }

  if (!agreeToTerms) {
    return res.status(400).json({ message: 'Please agree to the terms.' });
  }

  const emailNormalized = email.trim().toLowerCase();
  const usernameNormalized = username.trim().toLowerCase();

  if (!validator.isEmail(emailNormalized)) {
    return res.status(400).json({ message: 'Invalid email.' });
  }

  if (!validator.isAlphanumeric(usernameNormalized)) {
    return res.status(400).json({ message: 'Username must be alphanumeric.' });
  }


  if (password !== confirmPassword) {
    return res.status(400).json({ message: 'Confirm passwords do not match.' });
  }

  if (!validator.isLength(password, { min: 8 })) {
    return res.status(400).json({ message: 'Password must be at least 8 characters long.' });
  }

  if (!validator.isStrongPassword(password)) {
    return res.status(400).json({ message: 'Weak password.' });
  }

  //* Check Email Exist
  const { data: existingUser, error: userCheckErr } = await supabase
    .from('users')
    .select('id')
    .or(`email.eq.${emailNormalized},username.eq.${usernameNormalized}`)
    .maybeSingle();

  if (existingUser) {
    return res.status(400).json({ message: 'Email or username already exists.', error: userCheckErr });
  }

  //* Hash Password
  const passwordHash = await bcrypt.hash(password, 12);
  const verification_token = uuidv4();
  const token_expiry = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours from now

  //* Device Fingerprint
  const fingerprint = getDeviceFingerprint(req);
  const geo_ip = getGeoIP(req);

  //* Create User In DB
  const { data: newUser, error: insertErr } = await supabase.from('users').insert({
    email: emailNormalized,
    username: usernameNormalized,
    password_hash: passwordHash,
    email_verification_token: verification_token,
    email_verification_token_expiry: token_expiry.toISOString(),
    role: 'user',
    geo_ip: geo_ip,
    device_fingerprint: fingerprint,
    created_at: new Date().toISOString(),
    is_agree_to_terms: agreeToTerms,
  }).select().single();

  if (insertErr) {
    return res.status(500).json({ message: 'User registration failed.', error: insertErr.message });
  }

  //* Add User To Supabase Auth
  const { data: authUser, error: authErr } = await supabase.auth.admin.createUser({
    email: emailNormalized,
    password,
    email_confirm: false,
  });

  if (authErr) {
    await supabase.from('users').delete().eq('id', newUser.id);
    return res.status(500).json({ message: 'Supabase Auth failed.', error: authErr.message });
  }

  //* Send Email Verification - Pending
  await sendVerificationEmail(emailNormalized, verification_token);
  await sendWelcomeEmail(emailNormalized);

  //* Response Success
  return res.status(201).json({ message: 'User registered successfully.' });
}
