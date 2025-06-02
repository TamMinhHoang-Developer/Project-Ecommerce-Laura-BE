import { getAllTodos as getAllTodosService } from '../services/todosService.js';

export const getAllTodos = async (req, res) => {
  try {
    const todo = await getAllTodosService();
    res.json(todo);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};