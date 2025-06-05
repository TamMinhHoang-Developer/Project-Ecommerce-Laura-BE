// No need to import crypto anymore since we're not hashing

export const getDeviceFingerprint = (req) => {
  const userAgent = req.headers['user-agent'] || '';
  const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress || '';

  // Extract device information from user-agent
  const deviceInfo = {
    browser: extractBrowser(userAgent),
    os: extractOS(userAgent),
    device: extractDevice(userAgent),
    ip: ip
  };

  // Return as JSON string for easy storage and analysis
  return JSON.stringify(deviceInfo);
};

// Function to extract browser information from user-agent
function extractBrowser(userAgent) {
  // Chrome
  if (userAgent.indexOf('Chrome') > -1) {
    return 'Chrome';
  }
  // Firefox
  else if (userAgent.indexOf('Firefox') > -1) {
    return 'Firefox';
  }
  // Safari
  else if (userAgent.indexOf('Safari') > -1) {
    return 'Safari';
  }
  // Edge
  else if (userAgent.indexOf('Edg') > -1 || userAgent.indexOf('Edge') > -1) {
    return 'Edge';
  }
  // IE
  else if (userAgent.indexOf('MSIE') > -1 || userAgent.indexOf('Trident/') > -1) {
    return 'Internet Explorer';
  }
  // Unknown
  return 'Unknown';
}

// Function to extract operating system information from user-agent
function extractOS(userAgent) {
  // Windows
  if (userAgent.indexOf('Windows') > -1) {
    return 'Windows';
  }
  // macOS
  else if (userAgent.indexOf('Mac OS X') > -1) {
    return 'macOS';
  }
  // iOS
  else if (userAgent.indexOf('iPhone') > -1 || userAgent.indexOf('iPad') > -1) {
    return 'iOS';
  }
  // Android
  else if (userAgent.indexOf('Android') > -1) {
    return 'Android';
  }
  // Linux
  else if (userAgent.indexOf('Linux') > -1) {
    return 'Linux';
  }
  // Unknown
  return 'Unknown';
}

// Function to extract device type information from user-agent
function extractDevice(userAgent) {
  // Mobile
  if (userAgent.indexOf('Mobile') > -1) {
    // iPhone
    if (userAgent.indexOf('iPhone') > -1) {
      return 'iPhone';
    }
    // Android Phone
    else if (userAgent.indexOf('Android') > -1) {
      return 'Android Phone';
    }
    return 'Mobile';
  }
  // Tablet
  else if (userAgent.indexOf('Tablet') > -1 || userAgent.indexOf('iPad') > -1) {
    return 'Tablet';
  }
  // Desktop
  return 'Desktop';
}
