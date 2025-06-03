import bcrypt from 'bcrypt';
import supabase from '../config/supabaseClient.js';
import { createLoginLog } from '../services/log.service.js';
import { isDeviceNew, isLocationNew } from '../utils/securityCheck.js';
import { sendOTP } from '../utils/sendOTP.js';

export const login = async (req, res) => {
  const { email, password, deviceFingerprint, timezone } = req.body;

  try {
    // 1. Check user in custom `users` table
    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('email', email)
      .single();

    if (error || !user) {
      return res.status(401).json({ message: 'Account does not exist.' });
    }

    // 2.Check locked or unverified
    if (user.is_locked) {
      return res.status(403).json({ message: 'Account has been locked.' });
    }

    if (!user.is_email_verified) {
      return res.status(403).json({ message: 'Email not verified.' });
    }

    // 3. Check Password
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      // Increase failed_login_attempts + lock if needed
      const newAttempts = user.failed_login_attempts + 1;
      await supabase
        .from('users')
        .update({
          failed_login_attempts: newAttempts,
          is_locked: newAttempts >= 5,
        })
        .eq('id', user.id);

      return res.status(401).json({ message: 'Wrong password.' });
    }

    // 4. Reset failed_login_attempts if login is correct
    await supabase
      .from('users')
      .update({ failed_login_attempts: 0 })
      .eq('id', user.id);

    // 5. Check GeoIP, new fingerprint
    const ip = req.ip;
    const userAgent = req.headers['user-agent'];

    const isNewDevice = await isDeviceNew(user.id, deviceFingerprint);
    const isNewLocation = await isLocationNew(user.id, ip);

    if (isNewDevice || isNewLocation) {
      // Send OTP verification
      await sendOTP(user.email, user.id);
      return res.status(403).json({ message: 'New device/IP. OTP sent.' });
    }

    // 6. Login Logging
    await createLoginLog({
      user_id: user.id,
      ip,
      user_agent: userAgent,
      timezone,
      device_fingerprint: deviceFingerprint,
    });

    // 7. Supabase Auth Login
    const { data: authData, error: authError } = await supabase.auth.signInWithPassword({
      email,
      password,
    });

    if (authError) {
      return res.status(500).json({ message: 'Supabase Auth failed.', error: authError.message });
    }

    // 8. Return access token, refresh token or save cookie
    return res.status(200).json({
      message: 'Login successful.',
      access_token: authData.session.access_token,
      refresh_token: authData.session.refresh_token,
      user: authData.user,
    });

  } catch (err) {
    console.error('Login Error:', err);
    return res.status(500).json({ message: 'Server error.' });
  }
};