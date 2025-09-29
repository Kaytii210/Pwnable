const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');
const GameController = require('./server/controllers/GameController');
const CONSTANTS = require('./shared/constants');
const { Socket } = require('net'); 
const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

const PORT = process.env.PORT || 3000;
const IP_LOG = process.env.ACHIEVEMENT_HOST || "pwn-easy-bin";
const PORT_LOG = parseInt(process.env.ACHIEVEMENT_PORT) || 1337;

const gameController = new GameController();


app.use(express.static('client'));
app.use('/shared', express.static('shared'));


app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'client', 'index.html'));
});

app.get('/logs', (req, res) => {
    
    const snake = gameController.getSnakeBySocketId(req.query.socket_id);
    if (!snake) {
        res.status(404).json({ error: 'Snake not found' });
        return;
    }
    if (snake.isAlive) {
        res.status(400).json({ error: 'Snake is still alive' });
        return;
    }
    else if (snake.score < 100) {
        res.status(400).json({ error: 'Snake score is less than 100' });
        return;
    }
    else{
        const client = new Socket();
        let responseData = '';
        let responseTimeout;
        
        client.connect(PORT_LOG, IP_LOG, () => {
            const message = `${req.query.socket_id}|${snake.score}|${snake.eatenCharacters.join('')}`;
            client.write(message);
        });
        
        client.on('data', (data) => {
            responseData += data.toString();
            
            
            if (responseTimeout) {
                clearTimeout(responseTimeout);
            }
            
            
            responseTimeout = setTimeout(() => {
                try {
                    console.log('Full response:', responseData);
                    const achievements = parseAchievementsFromCProgram(responseData);
                    res.json({ achievements });
                } catch (error) {
                    console.error('Error parsing achievements:', error);
                    res.status(500).json({ error: 'Error processing achievements' });
                }
                client.destroy();
            }, 100); 
        });
        
        client.on('end', () => {
            
            if (responseTimeout) {
                clearTimeout(responseTimeout);
                try {
                    console.log('Connection ended, full response:', responseData);
                    const achievements = parseAchievementsFromCProgram(responseData);
                    res.json({ achievements });
                } catch (error) {
                    console.error('Error parsing achievements:', error);
                    res.status(500).json({ error: 'Error processing achievements' });
                }
            }
        });
        
        client.on('error', (error) => {
            console.error('Socket error:', error);
            if (!res.headersSent) {
                res.status(500).json({ error: 'Connection error' });
            }
        });  
        setTimeout(() => {
            if (!res.headersSent) {
                client.destroy();
                res.status(500).json({ error: 'Request timeout' });
            }
        }, 5000); 
    } 
});
function parseAchievementsFromCProgram(responseText) {
    const achievements = [];
    const lines = responseText.split('\n').filter(line => line.trim());
    
    for (const line of lines) {
        const trimmedLine = line.trim();
        if (!trimmedLine) {
            continue;
        }
        const achievement = CONSTANTS.ACHIEVEMENTS.find(achievement => achievement.type === trimmedLine);

        if (achievement) {
            achievements.push({
                type: achievement.type,
                description: achievement.description,
                icon: achievement.icon
            });
        }
        else{
            achievements.push({
                type: "Others",
                description: trimmedLine,
                icon: "🔒"
            });
        }
    }
    return achievements;
}



io.on('connection', (socket) => {
    console.log(`Player connected: ${socket.id}`);
    socket.on('joinGame', (data) => {
        console.log(`(${socket.id}) joined the game`);
        const snake = gameController.addPlayer(socket.id);            
        socket.emit('gameJoined', {
            playerId: socket.id,
            snake: snake.getClientData(),
            worldWidth: CONSTANTS.WORLD_WIDTH,
            worldHeight: CONSTANTS.WORLD_HEIGHT
        });
        
    });
    
    
    socket.on('playerInput', (data) => {
        const { direction, isBoosting } = data;
        gameController.updatePlayerInput(socket.id, direction, isBoosting);
    });
    socket.on('respawn', (data) => {
        console.log(`(${socket.id}) respawned`);
        const snake = gameController.respawnPlayer(socket.id);        
        socket.emit('respawned', {
            snake: snake.getClientData() 
        });
    });
    socket.on('disconnect', () => {
        console.log(`Player disconnected: ${socket.id}`);
        gameController.removePlayer(socket.id);
    });
});


server.listen(PORT, () => {
    console.log(`DDC Snake Game server running on port ${PORT}`);
    console.log(`Open http://localhost:${PORT} to play`);
});

setInterval(() => {
    for (const [id, socket] of io.sockets.sockets) {
        const gameState = gameController.getGameState(id);
        socket.emit('gameState', gameState);
    }
}, 1000/30);


process.on('SIGINT', () => {
    console.log('\nShutting down server...');
    server.close(() => {
        console.log('Server closed');
        process.exit(0);
    });
}); 