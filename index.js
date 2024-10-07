const express = require("express");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");

const app = express();
const cors = require("cors");

const PORT = 3000;
const SECRET_KEY = "tu_clave_secreta";

// Configura la conexión con la base de datos PostgreSQL
const pool = new Pool({
  host: "localhost",
  user: "postgres",
  password: "1234",
  database: "softjobs",
  allowExitOnIdle: true,
});

app.use(bodyParser.json());
app.use(cors());

// Middleware para verificar la existencia de credenciales
const verificarCredenciales = (req, res, next) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({
      message: "Credenciales faltantes: email y password son requeridos",
    });
  }
  next();
};

// Middleware para validar el token
const validarToken = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1]; // Obtiene el token del encabezado
  if (!token) {
    return res.status(401).json({ message: "Token no proporcionado" });
  }

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: "Token inválido" });
    }
    req.user = decoded;
    next();
  });
};

// Middleware para registrar consultas en la terminal
const registrarConsultas = (req, res, next) => {
  console.log(
    `Consulta recibida: ${req.method} ${
      req.originalUrl
    } - ${new Date().toISOString()}`
  );
  next();
};

app.use(registrarConsultas); // Usamos este middleware para todas las rutas

// Ruta para registrar nuevos usuarios
app.post("/usuarios", verificarCredenciales, async (req, res) => {
  try {
    const { email, password, rol, lenguage } = req.body;

    //contraseña
    const hashedPassword = await bcrypt.hash(password, 10);

    // Inserta el nuevo usuario en la base de datos
    const result = await pool.query(
      "INSERT INTO usuarios (email, password, rol, lenguage) VALUES ($1, $2, $3, $4) RETURNING *",
      [email, hashedPassword, rol, lenguage]
    );

    res.status(201).json({
      message: "Usuario registrado exitosamente",
      user: result.rows[0],
    });
  } catch (error) {
    res
      .status(400)
      .json({ message: "Error al registrar el usuario", error: error.message });
  }
});

// Ruta para login y generación de token JWT
app.post("/login", verificarCredenciales, async (req, res) => {
  try {
    const { email, password } = req.body;
    const result = await pool.query("SELECT * FROM usuarios WHERE email = $1", [
      email,
    ]);

    if (result.rows.length > 0) {
      const user = result.rows[0];
      const match = await bcrypt.compare(password, user.password);

      if (match) {
        const token = jwt.sign(
          { email: user.email, rol: user.rol },
          SECRET_KEY,
          { expiresIn: "1h" }
        );
        res.json({ token });
      } else {
        return res.status(401).json({ message: "Credenciales inválidas" });
      }
    } else {
      return res.status(401).json({ message: "Credenciales inválidas" });
    }
  } catch (error) {
    res
      .status(500)
      .json({ message: "Error en el servidor", error: error.message });
  }
});

// información del usuario
app.get("/usuarios", validarToken, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT email, rol, lenguage FROM usuarios WHERE email = $1",
      [req.user.email]
    );

    if (result.rows.length > 0) {
      res.json(result.rows[0]);
    } else {
      res.status(404).json({ message: "Usuario no encontrado" });
    }
  } catch (error) {
    res
      .status(500)
      .json({ message: "Error interno en el servidor", error: error.message });
  }
});

// Inicia el servidor
app.listen(PORT, () => {
  console.log(`Servidor escuchando en http://localhost:${PORT}`);
});
