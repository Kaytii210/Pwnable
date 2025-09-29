const Snake = require('../models/Snake');
const Food = require('../models/Food');
const CONSTANTS = require('../../shared/constants');

class GameController {
    constructor() {
        this.snakes = new Map();
        this.foods = new Map();
        this.gameLoop = null;
        this.lastUpdate = Date.now();
        this.startGameLoop();
    }
    
    initializeFoodForPlayer(playerId) {
        const foods = [];
        for (let i = 0; i < CONSTANTS.FOOD_COUNT; i++) {
            foods.push(Food.generateRandomFood());
        }
        this.foods.set(playerId, foods);
    }
    
    startGameLoop() {
        this.gameLoop = setInterval(() => {
            this.update();
        }, CONSTANTS.TICK_RATE);
    }
    
    update() {
        const now = Date.now();
        const deltaTime = (now - this.lastUpdate) / 1000;
        this.lastUpdate = now;
        for (const [playerId, snake] of this.snakes.entries()) {
            if (snake.isAlive) {
                snake.update(deltaTime);
                this.checkFoodCollisions(snake, playerId);
            } else if (now - snake.lastUpdate > 5000) {
                this.snakes.delete(playerId);
                this.foods.delete(playerId);
            }
            this.maintainFood(playerId);
        }
        
    }
    
    checkFoodCollisions(snake, playerId) {
        const foods = this.foods.get(playerId) || [];
        const head = snake.segments[0];
        for (let i = foods.length - 1; i >= 0; i--) {
            const food = foods[i];
            const distance = Math.sqrt(
                Math.pow(head.x - food.x, 2) + 
                Math.pow(head.y - food.y, 2)
            );
            if (distance < CONSTANTS.SEGMENT_SIZE + food.size) {
                snake.eatFood(food);
                foods.splice(i, 1);
                break;
            }
        }
        this.foods.set(playerId, foods);
    }
    
    maintainFood(playerId) {
        const foods = this.foods.get(playerId) || [];
        const foodNeeded = CONSTANTS.FOOD_COUNT - foods.length;
        for (let i = 0; i < foodNeeded; i++) {
            foods.push(Food.generateRandomFood());
        }
        this.foods.set(playerId, foods);
    }
    
    addPlayer(id) {
        const spawnPos = this.findSpawnPosition();
        const snake = new Snake(id, spawnPos.x, spawnPos.y);
        this.snakes.set(id, snake);
        this.initializeFoodForPlayer(id);
        return snake;
    }
    
    removePlayer(id) {
        this.snakes.delete(id);
        this.foods.delete(id);
    }
    
    updatePlayerInput(id, direction, isBoosting) {
        const snake = this.snakes.get(id);
        if (snake && snake.isAlive) {
            snake.setDirection(direction);
            snake.setBoosting(isBoosting);
        }
    }
    
    findSpawnPosition() {
        return {
            x: Math.random() * CONSTANTS.WORLD_WIDTH,
            y: Math.random() * CONSTANTS.WORLD_HEIGHT
        };
    }
    
    getGameState(socketId) {
        const snake = this.snakes.get(socketId);
        const foods = this.foods.get(socketId) || [];
        return {
            snakes: snake ? [snake.getClientData()] : [],
            foods: foods.map(food => food.getClientData())
        };
    }
    
    respawnPlayer(id) {
        const existingSnake = this.snakes.get(id);
        if (existingSnake) {
            const spawnPos = this.findSpawnPosition();
            existingSnake.x = spawnPos.x;
            existingSnake.y = spawnPos.y;
            existingSnake.direction = Math.random() * Math.PI * 2;
            existingSnake.isAlive = true;
            existingSnake.score = 0;
            existingSnake.length = CONSTANTS.INITIAL_LENGTH;
            existingSnake.eatenCharacters = [];
            existingSnake.letterCounts = { C: 0, B: 0, J: 0, S: 0 };
            existingSnake.segments = [];
            existingSnake.initializeSegments();
            this.initializeFoodForPlayer(id);
            return existingSnake;
        } else {
            return this.addPlayer(id);
        }
    }
    getSnakeBySocketId(socketId) {
        return this.snakes.get(socketId);
    }
}

module.exports = GameController; 