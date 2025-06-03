import express from 'express';
import * as todoController from '../controllers/todosController.js';

const router = express.Router();

router.get('/todos', todoController.getAllTodos);

export default router;