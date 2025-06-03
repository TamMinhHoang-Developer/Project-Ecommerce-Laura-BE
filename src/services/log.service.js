import supabase from '../config/supabaseClient.js';

export const createLoginLog = async ({
  user_id,
  ip,
  user_agent,
  timezone,
  device_fingerprint,
}) => {
  await supabase.from('login_logs').insert([
    {
      user_id,
      ip,
      user_agent,
      timezone,
      device_fingerprint,
      created_at: new Date().toISOString(),
    },
  ]);
};
