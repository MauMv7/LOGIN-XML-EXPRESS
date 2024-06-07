const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const fs = require('fs');
const xml2js = require('xml2js');
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const cors = require('cors');
const validatePassword = require('./passwordValidator');

const app = express();
const port = 5000;
const xmlFile = 'users.xml';
const saltRounds = 10;
const secretKey = 'secretito';

app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors());

const readXML = () => {
    const data = fs.readFileSync(xmlFile);
    let result = null;
    xml2js.parseString(data, (err, jsonData) => {
        if (err) throw err;
        result = jsonData;
    });
    return result;
};

const writeXML = (data) => {
    const builder = new xml2js.Builder();
    const xml = builder.buildObject(data);
    fs.writeFileSync(xmlFile, xml);
};

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

initializeXML();

app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    const passwordValidationError = validatePassword(password);
    if (passwordValidationError) {
        return res.status(400).send(passwordValidationError);
    }

    let usersData = readXML();
    if (!usersData.users) {
        usersData.users = { user: [] };
    }
    const users = usersData.users.user;

    if (Array.isArray(users) && users.some(user => user.username[0] === username)) {
        return res.status(400).send('Usuario ya existe.');
    }

    const hashedPassword = await bcrypt.hash(password, saltRounds);

    const secret = speakeasy.generateSecret({ name: `MyApp (${username})` });

    users.push({ username: [username], password: [hashedPassword], secret: [secret.base32] });

    writeXML(usersData);

    qrcode.toDataURL(secret.otpauth_url, (err, data_url) => {
        if (err) {
            return res.status(500).send('Error al generar QR Code.');
        }
        res.send({ message: 'Usuario registrado exitosamente.', qrCodeUrl: data_url });
    });
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    let usersData = readXML();
    if (!usersData.users || !Array.isArray(usersData.users.user)) {
        return res.status(400).send('Usuario o contraseña incorrectos.');
    }
    const users = usersData.users.user;

    const user = users.find(user => user.username[0] === username);

    if (!user) {
        return res.status(400).send('Usuario o contraseña incorrectos.');
    }

    const match = await bcrypt.compare(password, user.password[0]);

    if (match) {
        const token = jwt.sign({ username }, secretKey, { expiresIn: '15m' });

        res.send(`Inicio de sesión exitoso. Use este token para 2FA: ${token}`);
    } else {
        res.status(400).send('Usuario o contraseña incorrectos.');
    }
});

app.post('/verify-2fa', (req, res) => {
    const { token, code } = req.body;

    try {
        const decoded = jwt.verify(token, secretKey);
        const username = decoded.username;

        let usersData = readXML();
        if (!usersData.users || !Array.isArray(usersData.users.user)) {
            return res.status(400).send('Usuario o token incorrecto.');
        }
        const users = usersData.users.user;

        const user = users.find(user => user.username[0] === username);

        if (!user) {
            return res.status(400).send('Usuario o token incorrecto.');
        }

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

app.get('/show-users', async (req, res) => {
    let usersData = readXML();
    if (!usersData.users || !Array.isArray(usersData.users.user)) {
        return res.status(400).send('No hay usuarios registrados.');
    }
    const users = usersData.users.user.map(user => ({
        username: user.username ? user.username[0] : 'N/A',
        password: user.password ? '********' : 'N/A',
        secret: user.secret ? user.secret[0] : 'N/A'
    }));

    res.json(users);
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}/`);
});
