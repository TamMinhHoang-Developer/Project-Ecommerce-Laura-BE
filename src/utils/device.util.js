// Không cần import crypto nữa vì không hash

export const getDeviceFingerprint = (req) => {
  const userAgent = req.headers['user-agent'] || '';
  const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress || '';
  
  // Trích xuất thông tin thiết bị từ user-agent
  const deviceInfo = {
    browser: extractBrowser(userAgent),
    os: extractOS(userAgent),
    device: extractDevice(userAgent),
    ip: ip
  };
  
  // Trả về dưới dạng JSON string để dễ lưu trữ và phân tích
  return JSON.stringify(deviceInfo);
};

// Hàm trích xuất thông tin trình duyệt từ user-agent
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
  // Không xác định được
  return 'Unknown';
}

// Hàm trích xuất thông tin hệ điều hành từ user-agent
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
  // Không xác định được
  return 'Unknown';
}

// Hàm trích xuất thông tin thiết bị từ user-agent
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
