const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());

// Servir la carpeta 'public' (Frontend y Admin)
app.use(express.static(path.join(__dirname, 'public')));

const dataPath = path.join(__dirname, 'data.json');

// API: Obtener perfumes
app.get('/api/perfumes', (req, res) => {
    try {
        const data = fs.readFileSync(dataPath, 'utf8');
        res.json(JSON.parse(data));
    } catch (err) {
        res.status(500).json({ error: 'Error leyendo la base de datos' });
    }
});

// API: Actualizar perfumes (Requiere contraseña)
app.post('/api/perfumes', (req, res) => {
    const { password, perfumes } = req.body;
    
    // Contraseña simple para proteger tu backend
    if (password !== 'arenas2026') {
        return res.status(401).json({ error: 'Contraseña incorrecta' });
    }
    
    try {
        fs.writeFileSync(dataPath, JSON.stringify(perfumes, null, 2));
        res.json({ success: true, message: 'Catálogo actualizado correctamente' });
    } catch (err) {
        res.status(500).json({ error: 'Error guardando en la base de datos' });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Servidor Backend corriendo en el puerto ${PORT}`);
});
