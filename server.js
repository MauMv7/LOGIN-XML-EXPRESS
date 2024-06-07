const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const fs = require('fs');
const xml2js = require('xml2js');
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const cors = require('cors');
const validatePassword = require('./passwordValidator'); // Importar el validador de contraseña

const app = express();
const port = 5000;
const xmlFile = 'users.xml';
const saltRounds = 10;
const secretKey = 'your_jwt_secret';  // Cambia esto por una clave secreta fuerte

app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors()); // Usar cors para permitir todas las solicitudes CORS

// Función para leer el archivo XML y convertirlo a objeto JavaScript
const readXML = () => {
    const data = fs.readFileSync(xmlFile);
    let result = null;
    xml2js.parseString(data, (err, jsonData) => {
        if (err) throw err;
        result = jsonData;
    });
    return result;
};

// Función para escribir objeto JavaScript en archivo XML
const writeXML = (data) => {
    const builder = new xml2js.Builder();
    const xml = builder.buildObject(data);
    fs.writeFileSync(xmlFile, xml);
};

// Inicializar el archivo XML si no existe
const initializeXML = () => {
    if (!fs.existsSync(xmlFile)) {
        const initialData = { users: { user: [] } };
        writeXML(initialData);
    } else {
        const usersData = readXML();
        if (!usersData.users) {
            usersData.users = { user: [] };
            writeXML(usersData);
        } else if (!Array.isArray(usersData.users.user)) {
            usersData.users.user = [];
            writeXML(usersData);
        }
    }
};

// Llamar a la función de inicialización al inicio
initializeXML();

// Ruta para registrar un nuevo usuario
app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    // Validar la contraseña
    const passwordValidationError = validatePassword(password);
    if (passwordValidationError) {
        return res.status(400).send(passwordValidationError);
    }

    // Leer usuarios del archivo XML
    let usersData = readXML();
    if (!usersData.users) {
        usersData.users = { user: [] };
    }
    const users = usersData.users.user;

    // Verificar si el usuario ya existe
    if (Array.isArray(users) && users.some(user => user.username[0] === username)) {
        return res.status(400).send('Usuario ya existe.');
    }

    // Encriptar la contraseña
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Generar una clave secreta para 2FA
    const secret = speakeasy.generateSecret({ name: `MyApp (${username})` });

    // Agregar el nuevo usuario
    users.push({ username: [username], password: [hashedPassword], secret: [secret.base32] });

    // Escribir de nuevo en el archivo XML
    writeXML(usersData);

    // Generar un QR Code para escanear con la aplicación de autenticación
    qrcode.toDataURL(secret.otpauth_url, (err, data_url) => {
        if (err) {
            return res.status(500).send('Error al generar QR Code.');
        }
        res.send({ message: 'Usuario registrado exitosamente.', qrCodeUrl: data_url });
    });
});

// Ruta para iniciar sesión
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    // Leer usuarios del archivo XML
    let usersData = readXML();
    if (!usersData.users || !Array.isArray(usersData.users.user)) {
        return res.status(400).send('Usuario o contraseña incorrectos.');
    }
    const users = usersData.users.user;

    // Buscar el usuario por nombre de usuario
    const user = users.find(user => user.username[0] === username);

    if (!user) {
        return res.status(400).send('Usuario o contraseña incorrectos.');
    }

    // Verificar la contraseña
    const match = await bcrypt.compare(password, user.password[0]);

    if (match) {
        // Generar un token JWT para la sesión
        const token = jwt.sign({ username }, secretKey, { expiresIn: '15m' });

        res.send(`Inicio de sesión exitoso. Use este token para 2FA: ${token}`);
    } else {
        res.status(400).send('Usuario o contraseña incorrectos.');
    }
});

// Ruta para verificar el token de 2FA
app.post('/verify-2fa', (req, res) => {
    const { token, code } = req.body;

    try {
        // Verificar el token JWT
        const decoded = jwt.verify(token, secretKey);
        const username = decoded.username;

        // Leer usuarios del archivo XML
        let usersData = readXML();
        if (!usersData.users || !Array.isArray(usersData.users.user)) {
            return res.status(400).send('Usuario o token incorrecto.');
        }
        const users = usersData.users.user;

        // Buscar el usuario por nombre de usuario
        const user = users.find(user => user.username[0] === username);

        if (!user) {
            return res.status(400).send('Usuario o token incorrecto.');
        }

        // Verificar el código de 2FA
        const verified = speakeasy.totp.verify({
            secret: user.secret[0],
            encoding: 'base32',
            token: code,
        });

        if (verified) {
            res.send('Autenticación de dos factores exitosa.');
        } else {
            res.status(400).send('Código de autenticación incorrecto.');
        }
    } catch (err) {
        res.status(400).send('Token inválido.');
    }
});

// Ruta para mostrar el contenido del archivo XML desencriptado
app.get('/show-users', async (req, res) => {
    let usersData = readXML();
    if (!usersData.users || !Array.isArray(usersData.users.user)) {
        return res.status(400).send('No hay usuarios registrados.');
    }
    const users = usersData.users.user.map(user => ({
        username: user.username ? user.username[0] : 'N/A',
        password: user.password ? '********' : 'N/A',  // No enviamos la contraseña desencriptada por seguridad
        secret: user.secret ? user.secret[0] : 'N/A'
    }));

    res.json(users);
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}/`);
});
