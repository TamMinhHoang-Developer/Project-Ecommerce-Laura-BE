import supabase from '../config/supabaseClient.js';

export const getAllTodos = async () => {
    const { data, error } = await supabase.from('todos').select('*');
    if (error) {
        throw error;
    }
    return data;
}