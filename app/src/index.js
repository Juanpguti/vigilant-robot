const express = require('express');
const helmet = require('helmet');

const app = express();

app.disable('x-powered-by');
app.use(helmet());
app.use(express.json({ limit: '10kb' }));

app.get('/health', (_req, res) => {
  res.json({ status: 'ok', service: 'demo-secure-api' });
});

app.get('/api/v1/hello', (_req, res) => {
  res.json({ message: 'Hello, secure world!' });
});

app.use((_req, res) => {
  res.status(404).json({ error: 'not found' });
});

const port = process.env.PORT || 3000;
if (process.env.NODE_ENV !== 'test') {
  app.listen(port, () => console.log(`API listening on :${port}`));
}

module.exports = app;
