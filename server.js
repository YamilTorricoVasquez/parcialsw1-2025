const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');


const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

app.use(express.json());
app.use(express.static('public'));


const pool = new Pool({
  user: 'postgres',
  host: 'localhost',
  database: 'uml_diagrams',
  password: '1234',
  port: 5432,
});

const JWT_SECRET = 'tu_clave_secreta';

async function initDb() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL
      );
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS rooms (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        data JSONB NOT NULL,
        password VARCHAR(255)
      );
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS many_to_many_relations (
        id SERIAL PRIMARY KEY,
        room_id INTEGER REFERENCES rooms(id),
        class_a_id INTEGER NOT NULL,
        class_b_id INTEGER NOT NULL,
        table_name VARCHAR(255) NOT NULL,
        UNIQUE (room_id, class_a_id, class_b_id)
      );
    `);
    console.log('Tablas creadas o ya existen');
  } catch (err) {
    console.error('Error al inicializar la DB:', err);
  } finally {
    client.release();
  }
}

initDb();

let idCounter = 1;
const generateId = () => idCounter++;

async function getRooms() {
  const result = await pool.query('SELECT id, name, data FROM rooms');
  const rooms = result.rows.map(row => ({
    id: row.id,
    name: row.name,
    classes: row.data.classes || [],
    relationships: row.data.relationships || []
  }));

  for (let room of rooms) {
    const manyToManyResult = await pool.query(
      'SELECT * FROM many_to_many_relations WHERE room_id = $1',
      [room.id]
    );
    room.manyToManyRelations = manyToManyResult.rows.map(row => ({
      id: row.id,
      classAId: row.class_a_id,
      classBId: row.class_b_id,
      tableName: row.table_name
    }));
  }
  return rooms;
}

async function createRoom(room) {
  let hashedPassword = null;
  if (room.password) {
    hashedPassword = await bcrypt.hash(room.password, 10);
  }
  const result = await pool.query(
    'INSERT INTO rooms (name, data, password) VALUES ($1, $2, $3) RETURNING *',
    [room.name, { classes: room.classes || [], relationships: room.relationships || [] }, hashedPassword]
  );
  return {
    id: result.rows[0].id,
    name: result.rows[0].name,
    classes: result.rows[0].data.classes,
    relationships: result.rows[0].data.relationships,
    manyToManyRelations: []
  };
}

async function updateRoom(room) {
  // Asignar IDs a nuevas clases
  const updatedClasses = room.classes.map(cls => ({
    ...cls,
    id: cls.id || generateId()
  }));

  // Asignar IDs a nuevas relaciones y resolver relaciones ManyToMany
  const updatedRelationships = room.relationships.map(rel => {
    const newRel = {
      ...rel,
      id: rel.id || generateId()
    };
    if (rel.tempTarget) {
      const targetClass = updatedClasses.find(cls => cls.name === rel.tempTarget);
      if (targetClass) {
        newRel.toClassId = targetClass.id;
        delete newRel.tempTarget;
      }
    }
    return newRel;
  });

  // Guardar en la base de datos
  await pool.query(
    'UPDATE rooms SET name = $1, data = $2 WHERE id = $3',
    [room.name, { classes: updatedClasses, relationships: updatedRelationships }, room.id]
  );

  if (room.manyToManyRelations) {
    await pool.query('DELETE FROM many_to_many_relations WHERE room_id = $1', [room.id]);
    for (let rel of room.manyToManyRelations) {
      await pool.query(
        'INSERT INTO many_to_many_relations (room_id, class_a_id, class_b_id, table_name) VALUES ($1, $2, $3, $4)',
        [room.id, rel.classAId, rel.classBId, rel.tableName]
      );
    }
  }

  const updatedRoom = {
    id: room.id,
    name: room.name,
    classes: updatedClasses,
    relationships: updatedRelationships,
    manyToManyRelations: room.manyToManyRelations || []
  };

  console.log('Backend updated room:', JSON.stringify(updatedRoom)); // Log para depuración
  return updatedRoom;
}

async function verifyRoomPassword(roomId, password) {
  const result = await pool.query('SELECT password FROM rooms WHERE id = $1', [roomId]);
  const room = result.rows[0];
  if (!room.password) return true;
  return password && await bcrypt.compare(password, room.password);
}

async function registerUser(username, password) {
  const hashedPassword = await bcrypt.hash(password, 10);
  const result = await pool.query(
    'INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id, username',
    [username, hashedPassword]
  );
  return result.rows[0];
}

async function loginUser(username, password) {
  const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
  const user = result.rows[0];
  if (user && await bcrypt.compare(password, user.password)) {
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });
    return { token, username: user.username };
  }
  throw new Error('Credenciales inválidas');
}

app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await registerUser(username, password);
    res.status(201).json({ message: 'Usuario registrado', username: user.username });
  } catch (err) {
    res.status(400).json({ error: err.message || 'Error al registrar usuario' });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const { token, username: userUsername } = await loginUser(username, password);
    res.json({ token, username: userUsername });
  } catch (err) {
    res.status(401).json({ error: err.message });
  }
});

wss.on('connection', (ws) => {
  console.log('Nuevo cliente intentando conectar');

  ws.on('message', async (message) => {
    const data = JSON.parse(message);

    if (!data.token) {
      ws.send(JSON.stringify({ type: 'error', message: 'Token requerido' }));
      return;
    }

    let decoded;
    try {
      decoded = jwt.verify(data.token, JWT_SECRET);
    } catch (err) {
      ws.send(JSON.stringify({ type: 'error', message: 'Token inválido o expirado' }));
      return;
    }

    console.log(`Usuario ${decoded.username} autenticado`);

    switch (data.type) {
      case 'getRooms':
        const rooms = await getRooms();
        ws.send(JSON.stringify({ type: 'rooms', rooms }));
        break;
      case 'createRoom':
        const newRoom = await createRoom(data.room);
        broadcast({ type: 'rooms', rooms: await getRooms() });
        break;
      case 'updateRoom':
        const updatedRoom = await updateRoom(data.room);
        broadcast({ type: 'roomUpdate', room: updatedRoom });
        break;
      case 'joinRoom':
        const { roomId, password } = data;
        const isValid = await verifyRoomPassword(roomId, password);
        if (isValid) {
          const rooms = await getRooms();
          const room = rooms.find(r => r.id === roomId);
          ws.send(JSON.stringify({ type: 'roomAccess', room }));
        } else {
          ws.send(JSON.stringify({ type: 'error', message: 'Contraseña incorrecta' }));
        }
        break;
    }
  });

  ws.on('close', () => console.log('Cliente desconectado'));
});

function broadcast(data) {
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify(data));
    }
  });
}

server.listen(3000, () => {
  console.log('Servidor corriendo en http://localhost:3000');
});