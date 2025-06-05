import bcrypt from 'bcrypt';
import validator from 'validator';
import supabase from '../config/supabaseClient.js';

import { v4 as uuidv4 } from 'uuid';
import { getDeviceFingerprint } from '../utils/device.util.js';
import { getGeoIP } from '../utils/geoip.util.js';

import { sendVerificationEmail, sendWelcomeEmail } from '../services/email.service.js';
import { logActivity } from '../services/log.service.js';

//* [POST] /api/auth/register - Register a new user 
export const registerUser = async (req, res) => {
  try {
    const { email, username, password, confirmPassword, agreeToTerms } = req.body;

    // Validate required fields
    if (!email || !username || !password || !confirmPassword) {
      return res.status(400).json({ success: false, message: 'Please fill in all required information.' });
    }

    if (!agreeToTerms) {
      return res.status(400).json({ success: false, message: 'Please agree to the terms and conditions.' });
    }

    // Normalize inputs
    const emailNormalized = email.trim().toLowerCase();
    const usernameNormalized = username.trim().toLowerCase();

    // Validate email format
    if (!validator.isEmail(emailNormalized)) {
      return res.status(400).json({ success: false, message: 'Please provide a valid email address.' });
    }

    // Validate username format
    if (!validator.isAlphanumeric(usernameNormalized)) {
      return res.status(400).json({ success: false, message: 'Username must contain only letters and numbers.' });
    }

    if (usernameNormalized.length < 3 || usernameNormalized.length > 20) {
      return res.status(400).json({ success: false, message: 'Username must be between 3 and 20 characters.' });
    }

    // Validate password
    if (password !== confirmPassword) {
      return res.status(400).json({ success: false, message: 'Passwords do not match.' });
    }

    if (!validator.isLength(password, { min: 8 })) {
      return res.status(400).json({ success: false, message: 'Password must be at least 8 characters long.' });
    }

    if (!validator.isStrongPassword(password)) {
      return res.status(400).json({
        success: false,
        message: 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character.'
      });
    }

    // Check if email or username already exists
    const { data: existingUser, error: userCheckErr } = await supabase
      .from('users')
      .select('id, email, username')
      .or(`email.eq.${emailNormalized},username.eq.${usernameNormalized}`)
      .maybeSingle();

    if (userCheckErr) {
      console.error('Database error during user check:', userCheckErr);
      return res.status(500).json({ success: false, message: 'Server error during registration process.' });
    }

    if (existingUser) {
      // Provide more specific feedback about which field is duplicated
      if (existingUser.email === emailNormalized) {
        return res.status(400).json({ success: false, message: 'This email address is already registered.' });
      } else {
        return res.status(400).json({ success: false, message: 'This username is already taken.' });
      }
    }

    // Hash password with appropriate cost factor
    const saltRounds = 12;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // Generate verification token
    const verification_token = uuidv4();
    const token_expiry = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours from now

    // Get device and location information
    const fingerprint = getDeviceFingerprint(req);
    const geo_ip = getGeoIP(req);

    // Create user in database
    const { data: newUser, error: insertErr } = await supabase.from('users').insert({
      email: emailNormalized,
      username: usernameNormalized,
      password_hash: passwordHash,
      is_email_verified: false,
      email_verification_token: verification_token,
      email_verification_token_expiry: token_expiry.toISOString(),
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      is_locked: false,
      failed_login_attempts: 0,
      role: 'user',
      device_fingerprint: fingerprint,
      geo_ip: geo_ip
    }).select().single();

    if (insertErr) {
      console.error('Database error during user creation:', insertErr);
      return res.status(500).json({ success: false, message: 'Failed to create user account.', error: insertErr.message });
    }

    // Add user to Supabase Auth
    const { data: authUser, error: authErr } = await supabase.auth.admin.createUser({
      email: emailNormalized,
      password,
      email_confirm: false,
    });

    if (authErr) {
      // Rollback user creation if auth fails
      console.error('Supabase Auth error:', authErr);
      await supabase.from('users').delete().eq('id', newUser.id);
      return res.status(500).json({ success: false, message: 'Authentication setup failed.', error: authErr.message });
    }

    // Log the successful login
    try {
      await supabase.from('login_logs').insert({
        user_id: newUser.id,
        email: emailNormalized,
        success: true,
        ip_address: req.ip || req.connection.remoteAddress,
        user_agent: req.headers['user-agent'],
        device: fingerprint,
        geo_location: geo_ip,
        reason: 'new_registration'
      });
    } catch (logErr) {
      console.error('Error logging registration:', logErr);
      // Continue despite logging errors
    }

    // Send verification and welcome emails
    try {
      await Promise.all([
        sendVerificationEmail(emailNormalized, verification_token),
        sendWelcomeEmail(emailNormalized)
      ]);
    } catch (emailErr) {
      console.error('Email sending error:', emailErr);
      // Continue despite email errors - don't fail registration
    }

    // Return success response
    return res.status(201).json({
      success: true,
      message: 'Registration successful! Please check your email to verify your account.',
      userId: newUser.id
    });
  } catch (error) {
    console.error('Unexpected error during registration:', error);
    return res.status(500).json({
      success: false,
      message: 'An unexpected error occurred during registration.',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};
