import express, { json } from 'express';

const app = express();
const PORT = 3000;

// Middleware to parse JSON
app.use(json());
// Add this CORS middleware BEFORE your routes
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', 'http://localhost:5173');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.sendStatus(204); // handle preflight
  next();
});

const users = {}

// Routes
app.get('/', (req, res) => {
  res.send('Hello, World!');
});

app.post('/register', (req, res) => {
  const body = req.body;

  users[body.registerEmail] = body

  res.json({ received: body });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
