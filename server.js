const express = require('express');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());

app.use(express.static(path.join(__dirname, 'public')));

const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
const REPO_OWNER = "Maiom2109"; // Tu usuario de GitHub
const REPO_NAME = "Perfumeria"; // El nombre de tu repositorio
const FILE_PATH = "data.json";

// Endpoint para leer los datos directamente desde GitHub
app.get('/api/data', async (req, res) => {
    try {
        const response = await fetch(`https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/contents/${FILE_PATH}`, {
            headers: { 
                'Authorization': `token ${GITHUB_TOKEN}`, 
                'User-Agent': 'Node.js',
                'Accept': 'application/vnd.github.v3+json'
            }
        });
        
        if (!response.ok) {
            throw new Error(`GitHub API error: ${response.statusText}`);
        }

        const fileData = await response.json();
        const content = Buffer.from(fileData.content, 'base64').toString('utf8');
        res.json(JSON.parse(content));
    } catch (err) {
        console.error("Error leyendo desde GitHub:", err);
        res.status(500).json({ error: 'Error leyendo la base de datos desde GitHub' });
    }
});

// Endpoint para guardar los datos modificando el archivo data.json en GitHub automáticamente
app.post('/api/data', async (req, res) => {
    const { password, data } = req.body;
    
    if (password !== 'arenas2026') {
        return res.status(401).json({ error: 'Contraseña incorrecta' });
    }
    
    try {
        // 1. Obtener el SHA actual del archivo data.json en GitHub
        const getResponse = await fetch(`https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/contents/${FILE_PATH}`, {
            headers: { 
                'Authorization': `token ${GITHUB_TOKEN}`, 
                'User-Agent': 'Node.js',
                'Accept': 'application/vnd.github.v3+json'
            }
        });
        
        if (!getResponse.ok) {
            throw new Error(`No se pudo obtener el archivo de GitHub: ${getResponse.statusText}`);
        }

        const fileJson = await getResponse.json();
        const fileSha = fileJson.sha;

        // 2. Enviar la actualización del archivo data.json a GitHub
        const updatedContent = Buffer.from(JSON.stringify(data, null, 2)).toString('base64');
        const updateResponse = await fetch(`https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/contents/${FILE_PATH}`, {
            method: 'PUT',
            headers: { 
                'Authorization': `token ${GITHUB_TOKEN}`, 
                'User-Agent': 'Node.js',
                'Content-Type': 'application/json',
                'Accept': 'application/vnd.github.v3+json'
            },
            body: JSON.stringify({
                message: "Actualización automática desde el Panel Admin - ARENAS",
                content: updatedContent,
                sha: fileSha
            })
        });

        if (updateResponse.ok) {
            res.json({ success: true, message: '¡Datos guardados y respaldados en GitHub con éxito!' });
        } else {
            const errorData = await updateResponse.json();
            console.error("Error de GitHub al actualizar:", errorData);
            res.status(500).json({ error: 'Error al actualizar el repositorio en GitHub: ' + (errorData.message || '') });
        }
    } catch (err) {
        console.error("Error interno en servidor:", err);
        res.status(500).json({ error: 'Error interno al guardar los datos: ' + err.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Servidor corriendo en el puerto ${PORT}`);
});
