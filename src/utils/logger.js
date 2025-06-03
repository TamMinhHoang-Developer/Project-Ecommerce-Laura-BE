const fs = require('fs');
const path = require('path');

exports.logSuccessfulLogin = (email, ip, deviceId) => {
  const log = `SUCCESS | Email: ${email} | IP: ${ip} | DeviceID: ${deviceId} | Time: ${new Date().toISOString()}\n`;
  fs.appendFileSync(path.join(__dirname, '../logs/login.log'), log);
};

exports.logFailedLogin = (email, ip, deviceId, reason) => {
  const log = `FAILED | Email: ${email} | IP: ${ip} | DeviceID: ${deviceId} | Reason: ${reason} | Time: ${new Date().toISOString()}\n`;
  fs.appendFileSync(path.join(__dirname, '../logs/login.log'), log);
};
