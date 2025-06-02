const express = require('express');
const app = express();
const port = 3000; // Or any port you prefer

app.get('/', (req, res) => {
  res.send('Hello, Express!');
});

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});