export const sendOTP = async (email, userId) => {
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString(); // 5 phút

    await supabase.from('otp_tokens').insert([
        { user_id: userId, otp, expires_at: expiresAt },
    ]);

    // TODO: Gửi email thực bằng nodemailer / supabase functions
    console.log(`Gửi OTP ${otp} đến email ${email}`);
};
