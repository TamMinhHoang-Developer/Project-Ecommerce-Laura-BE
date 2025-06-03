import supabase from '../config/supabaseClient.js';

export const isDeviceNew = async (userId, fingerprint) => {
    const { data, error } = await supabase
        .from('device_fingerprints')
        .select('*')
        .eq('user_id', userId)
        .eq('fingerprint', fingerprint);

    return !data || data.length === 0;
};

export const isLocationNew = async (userId, ip) => {
    const { data, error } = await supabase
        .from('login_logs')
        .select('ip')
        .eq('user_id', userId)
        .eq('ip', ip);

    return !data || data.length === 0;
};