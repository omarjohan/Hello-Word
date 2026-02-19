/*
=============================================================================
BACKEND PRINCIPAL - API de Saonatech (versión con logging detallado)
=============================================================================
*/

const express = require('express');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const fs = require('fs');
const path = require('path');
const csv = require('csv-parser');
const OpenAI = require('openai');
require('dotenv').config();

// ---------------------------------------------------------------------------
// CONFIGURACIÓN
// ---------------------------------------------------------------------------

const app = express();

// 🔒 Parsers obligatorios (Android friendly)
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// ---------------------------------------------------------------------------
// BASE DE DATOS (Nile Postgres compatible)
// ---------------------------------------------------------------------------

const pool = new Pool({
  connectionString: process.env.POSTGRES_URL,
  ssl:
    process.env.NODE_ENV === 'production'
      ? { rejectUnauthorized: false }
      : false,
});

// ---------------------------------------------------------------------------
// SECRETOS
// ---------------------------------------------------------------------------

const JWTSECRET = process.env.JWTSECRET || 'fallback_secret_local';

const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
});

// ---------------------------------------------------------------------------
// MIDDLEWARE AUTH
// ---------------------------------------------------------------------------

const authenticateToken = (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ message: 'Token requerido' });
    }

    jwt.verify(token, JWTSECRET, (err, user) => {
      if (err) return res.status(403).json({ message: 'Token inválido' });
      req.user = user;
      next();
    });
  } catch (err) {
    console.error('Auth middleware error:', err);
    res.status(500).json({ message: 'Error de autenticación' });
  }
};

// ---------------------------------------------------------------------------
// LOGIN (BLINDADO Y CON LOGS DETALLADOS)
// ---------------------------------------------------------------------------

app.post('/api/login', async (req, res) => {
  console.log('\n============================================');
  console.log('🚀 [API /api/login] Petición Recibida 🚀');
  console.log(`[Login] Timestamp: ${new Date().toISOString()}`)
  console.log(`[Login] Headers de la petición: ${JSON.stringify(req.headers, null, 2)}`);
  console.log(`[Login] Body de la petición: ${JSON.stringify(req.body, null, 2)}`);
  console.log('--------------------------------------------');

  try {
    const email = req.body?.email;
    const password = req.body?.password;

    if (!email || !password) {
      console.warn('[Login] RECHAZADO: Email o password ausentes en el body.');
      return res.status(400).json({
        message: 'Email y password son obligatorios',
      });
    }

    console.log(`[Login] Buscando usuario en DB: ${email}`);
    const result = await pool.query(
      'SELECT * FROM users WHERE email = $1',
      [email]
    );

    const user = result.rows?.[0];

    if (!user) {
      console.warn(`[Login] Usuario NO encontrado en DB: ${email}`);
      return res.status(401).json({
        message: 'Email o contraseña incorrectos',
      });
    }

    console.log(`[Login] Usuario encontrado: ${user.email}. Verificando hash de contraseña...`);
    const validPassword = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!validPassword) {
      console.warn(`[Login] Contraseña INCORRECTA para: ${email}`);
      return res.status(401).json({
        message: 'Email o contraseña incorrectos',
      });
    }

    console.log(`[Login] Contraseña VÁLIDA para: ${email}. Generando token JWT...`);
    const accessToken = jwt.sign(
      {
        user_id: user.user_id,
        role: user.role,
        client_id: user.client_id,
        name: user.name,
      },
      JWTSECRET,
      { expiresIn: '8h' }
    );

    console.log(`[Login] Login EXITOSO para: ${email}. Token enviado.`);
    return res.json({ token: accessToken });

  } catch (error) {
    console.error('Error CRÍTICO en /api/login:', error);
    res.status(500).json({ message: 'Error interno del servidor.' });
  } finally {
    console.log('🔚 [API /api/login] Fin de la Petición 🔚');
    console.log('============================================\n');
  }
});

// ---------------------------------------------------------------------------
// CHAT IA (OpenAI v6)
// ---------------------------------------------------------------------------

app.post('/api/chat', authenticateToken, async (req, res) => {
  try {
    const query = req.body?.query;

    if (!query) {
      return res
        .status(400)
        .json({ message: 'La consulta (query) es obligatoria.' });
    }

    const completion = await openai.chat.completions.create({
      model: 'gpt-3.5-turbo',
      messages: [
        {
          role: 'system',
          content:
            'Eres un asistente experto en análisis de datos empresariales.',
        },
        { role: 'user', content: query },
      ],
    });

    const chatResponse = completion.choices?.[0]?.message?.content;

    res.status(200).json({ response: chatResponse });
  } catch (error) {
    console.error('Error en /api/chat con OpenAI:', error);
    res
      .status(500)
      .json({ message: 'Error al comunicarse con el servicio de IA.' });
  }
});

// ---------------------------------------------------------------------------
// HEALTH CHECK (recomendado)
// ---------------------------------------------------------------------------

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok' });
});

// ---------------------------------------------------------------------------
// SERVER
// ---------------------------------------------------------------------------

const PORT = process.env.PORT || 3000;

if (process.env.VERCEL !== '1') {
  app.listen(PORT, () => {
    console.log(`Servidor corriendo en puerto ${PORT}`);
  });
}

module.exports = app;