import bcrypt from 'bcrypt';
import validator from 'validator';
import supabase from '../config/supabaseClient.js';
import jwt from 'jsonwebtoken';

import { v4 as uuidv4 } from 'uuid';
import { getDeviceFingerprint } from '../utils/device.util.js';
import { getGeoIP } from '../utils/geoip.util.js';

import { sendVerificationEmail, sendWelcomeEmail, sendSuspiciousLoginEmail } from '../services/email.service.js';
import { loggerInfoAuthentication } from '../utils/logger.util.js';
import { generateRandomCode } from '../utils/generate_token.util.js';
import { sendPasswordResetEmail } from '../services/email.service.js';

//* [POST] /api/auth/login - Login a user
export const loginUser = async (req, res) => {
  const MAX_FAILED_ATTEMPTS = 5;
  const LOCK_DURATION_MINUTES = 15;

  try {
    const { email, password, rememberMe } = req.body;
    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Email/Password is required' });
    }

    const ipAddress = req.ip;
    const userAgent = req.headers['user-agent'];
    const fingerprint = getDeviceFingerprint(req);
    const geo_ip = getGeoIP(req);

    if (!validator.isLength(password, { min: 8 })) {
      return res.status(400).json({ success: false, message: 'Password must be at least 8 characters long.' });
    }

    const { data: users, error: userErr } = await supabase
      .from('users')
      .select('*')
      .or(`email.eq.${email},username.eq.${email}`);

    if (userErr) throw new Error('Database query failed');

    const user = users && users[0];
    if (!user) {
      await loggerInfoAuthentication(null, email, false, ipAddress, userAgent, fingerprint, geo_ip, 'invalid_credentials');
      return res.status(400).json({ success: false, message: 'User not found' });
    }

    if (user.is_locked && new Date() - new Date(user?.last_failed_login) < LOCK_DURATION_MINUTES * 60000) {
      return res.status(400).json({ success: false, message: 'Account is locked. Please try again later.' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password_hash);
    if (!isPasswordValid) {
      const failedAttempts = (user.failed_login_attempts || 0) + 1;
      await supabase
        .from('users')
        .update({
          failed_login_attempts: failedAttempts,
          last_failed_login: new Date().toISOString(),
          is_locked: failedAttempts >= MAX_FAILED_ATTEMPTS
        })
        .eq('id', user.id);

      await loggerInfoAuthentication(user.id, email, false, ipAddress, userAgent, fingerprint, geo_ip, 'wrong_password');
      return res.status(401).json({ success: false, message: 'Invalid credentials.' });
    }

    await supabase
      .from('users')
      .update({
        failed_login_attempts: 0,
        is_locked: false,
        last_failed_login: null
      })
      .eq('id', user.id);

    const isNewDevice = fingerprint !== user.device_fingerprint;
    const isNewLocation = geo_ip !== user.geo_ip;

    //* Check for suspicious login
    // if (isNewDevice || isNewLocation) {
    //   await sendSuspiciousLoginEmail(user.email, ipAddress, fingerprint, geo_ip);
    //   await loggerInfoAuthentication(user.id, email, false, ipAddress, userAgent, fingerprint, geo_ip, 'suspicious_login');
    //   return res.status(200).json({ success: true, message: 'Suspicious login detected. Please verify your identity.' });
    // }

    const accessToken = jwt.sign(
      { userId: user.id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '1d' }
    );

    const refreshToken = jwt.sign(
      { userId: user.id },
      process.env.JWT_REFRESH_SECRET,
      { expiresIn: rememberMe ? '30d' : '7d' }
    );

    await supabase.from('refresh_tokens').insert({
      user_id: user.id,
      token: refreshToken,
      device_info: fingerprint,
      ip_address: ipAddress,
      expires_at: rememberMe
        ? new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
        : new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
    });

    await loggerInfoAuthentication({
      user_id: user.id,
      email: user.email,
      success: true,
      ip_address: ipAddress,
      user_agent: userAgent,
      device: getDeviceFingerprint(req),
      geo_location: getGeoIP(req),
      reason: 'success'
    });

    res.cookie('access_token', accessToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'Strict',
      maxAge: 15 * 60 * 1000
    });

    res.cookie('refresh_token', refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'Strict',
      maxAge: rememberMe ? 30 * 24 * 60 * 60 * 1000 : 7 * 24 * 60 * 60 * 1000
    });

    res.status(200).json({ message: 'Login successful.', accessToken });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
};

//* [POST] /api/auth/register - Register a new user
export const registerUser = async (req, res) => {
  try {
    const { email, username, password, confirmPassword, agreeToTerms, phone } = req.body;

    // Validate required fields
    if (!email || !username || !password || !confirmPassword || !phone) {
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
      geo_ip: geo_ip,
      phone: phone
    }).select().single();

    if (insertErr) {
      console.error('Database error during user creation:', insertErr);
      return res.status(500).json({ success: false, message: 'Failed to create user account.', error: insertErr.message });
    }

    // Add user to Supabase Auth
    const { data: authUser, error: authErr } = await supabase.auth.admin.createUser({
      email: emailNormalized,
      password: password,
      user_metadata: {
        displayName: usernameNormalized,
      },
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

//* [POST] /api/auth/forgot-password - Request password reset
export const forgotUserPassword = async (req, res) => {
  const { email, phone, username } = req.body;

  if (!email && !phone && !username) {
    return res.status(400).json({ success: false, message: 'Email, phone, or username is required.' });
  }

  try {
    const { data: user, error: userErr } = await supabase
      .from('users')
      .select('*')
      .or(`email.eq.${email},phone.eq.${phone},username.eq.${username}`)
      .single();

    // Trả về thông báo chung, không tiết lộ user có tồn tại hay không
    if (userErr || !user || !user.email) {
      return res.status(400).json({ message: "Account not found." });
    }

    const resetCode = generateRandomCode(6);
    const expireAt = new Date(Date.now() + 24 * 60 * 60 * 1000);

    const { error: insertErr } = await supabase.from("password_reset_tokens").insert({
      user_id: user.id,
      token: resetCode,
      expires_at: expireAt.toISOString(),
    });
    if (insertErr) {
      return res.status(500).json({ message: 'Could not process password reset request.' });
    }

    try {
      await sendPasswordResetEmail(user.email, resetCode);
    } catch (mailErr) {
      // Không tiết lộ lỗi gửi mail
    }
    return res.status(200).json({ message: 'If the account exists, a reset code has been sent to the registered email.' });
  } catch (error) {
    return res.status(500).json({ message: 'Internal server error.' });
  }
}

//* [POST] /api/auth/verify-reset-code - Verify reset code
export const verifyResetCode = async (req, res) => {
  const { email, code } = req.body;
  if (!email || !code) return res.status(400).json({ success: false, message: 'Email and code are required.' });

  try {
    const { data: user, error: userErr } = await supabase.from('users').select('id').eq('email', email.toLowerCase()).single();
    if (userErr || !user) {
      return res.status(400).json({ message: 'Invalid or expired reset code.' });
    }

    const { data: tokenRows, error: tokenErr } = await supabase
      .from('password_reset_tokens')
      .select('*')
      .eq('user_id', user.id)
      .eq('token', code)
      .eq('used', false);

    const token = tokenRows?.[0];
    if (tokenErr || !token || Date.parse(token.expires_at) < Date.now()) {
      return res.status(400).json({ message: 'Invalid or expired reset code.' });
    }

    return res.status(200).json({ message: 'Reset code verified.' });
  } catch (error) {
    return res.status(500).json({ message: 'Internal server error.' });
  }
}

//* [POST] /api/auth/reset-password - Reset password
export const resetPassword = async (req, res) => {
  const { email, code, newPassword } = req.body;
  if (!email || !code || !newPassword)
    return res.status(400).json({ message: 'Email, code, and new password are required.' });

  // Kiểm tra strong password
  if (newPassword.length < 8 || !validator.isStrongPassword(newPassword)) {
    return res.status(400).json({ message: 'Password must be at least 8 characters and strong (uppercase, lowercase, number, special character).' });
  }

  try {
    const { data: user, error: userErr } = await supabase.from('users').select('id').eq('email', email.toLowerCase()).single();
    if (userErr || !user) return res.status(400).json({ message: 'Invalid email or code.' });

    const { data: tokenRows, error: tokenErr } = await supabase
      .from('password_reset_tokens')
      .select('*')
      .eq('user_id', user.id)
      .eq('token', code)
      .eq('used', false);

    const token = tokenRows?.[0];
    if (tokenErr || !token || Date.parse(token.expires_at) < Date.now()) {
      return res.status(400).json({ message: 'Invalid or expired reset code.' });
    }

    const hash = await bcrypt.hash(newPassword, 10);
    const { error: updateErr } = await supabase.from('users').update({ password_hash: hash }).eq('id', user.id);
    if (updateErr) return res.status(500).json({ message: 'Could not reset password.' });

    await supabase.from('password_reset_tokens').update({ used: true }).eq('id', token.id);

    const { error: authUpdateError } = await supabase.auth.admin.updateUserById(userData.id, {
      password: newPassword
    });

    if (authUpdateError) {
      return res.status(500).json({ message: 'Updated password in DB, but failed to update Supabase Auth.', error: authUpdateError.message });
    }

    return res.status(200).json({ message: 'Password reset successfully.' });
  } catch (error) {
    return res.status(500).json({ message: 'Internal server error.' });
  }
};