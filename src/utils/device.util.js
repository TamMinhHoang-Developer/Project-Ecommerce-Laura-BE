import crypto from 'crypto';

export const getDeviceFingerprint = (req) => {
  const userAgent = req.headers['user-agent'] || '';
  const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress || '';
  const raw = `${userAgent}|${ip}`;

  return crypto.createHash('sha256').update(raw).digest('hex');
};
