const request = require('supertest');
const app = require('../src/index.js');

describe('Demo secure API', () => {
  it('GET /health responde 200 con status ok', async () => {
    const res = await request(app).get('/health');
    expect(res.statusCode).toBe(200);
    expect(res.body.status).toBe('ok');
  });

  it('GET /api/v1/hello responde con message', async () => {
    const res = await request(app).get('/api/v1/hello');
    expect(res.statusCode).toBe(200);
    expect(res.body).toHaveProperty('message');
  });

  it('incluye cabeceras de seguridad (helmet)', async () => {
    const res = await request(app).get('/health');
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['content-security-policy']).toBeDefined();
    expect(res.headers['x-powered-by']).toBeUndefined();
  });

  it('rutas desconocidas responden 404 JSON', async () => {
    const res = await request(app).get('/no-existe');
    expect(res.statusCode).toBe(404);
    expect(res.body.error).toBe('not found');
  });
});
