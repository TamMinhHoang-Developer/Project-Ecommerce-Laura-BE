import geoip from 'geoip-lite';

export const getGeoIP = (req) => {
  const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.connection.remoteAddress;

  if (!ip) return null;

  const geo = geoip.lookup(ip);
  if (!geo) return null;

  return `${geo.city || ''}, ${geo.region || ''}, ${geo.country || ''}`;
};
