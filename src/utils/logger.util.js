import supabase from "../config/supabaseClient.js"

export const loggerInfoAuthentication = async ({
    user_id = null,
    email,
    success,
    ip_address,
    user_agent,
    device,
    geo_location,
    reason = null
}) => {
    const { err } = await supabase.from('login_logs').insert({
        user_id,
        email,
        success,
        ip_address,
        user_agent,
        device,
        geo_location,
        reason
    })

    if (err) {
        console.log('Error logging login attempt:', err.message)
    }
}