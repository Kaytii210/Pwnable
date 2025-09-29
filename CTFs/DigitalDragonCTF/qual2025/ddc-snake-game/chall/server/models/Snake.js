const CONSTANTS = require('../../shared/constants');

class Snake {
    constructor(id, x, y) {
        this.id = id;
        this.x = x;
        this.y = y;
        this.direction = Math.random() * Math.PI * 2;
        this.speed = CONSTANTS.SNAKE_SPEED;
        this.isBoosting = false;
        this.isAlive = true;
        this.score = 0;
        this.length = CONSTANTS.INITIAL_LENGTH;
        this.color = CONSTANTS.SNAKE_COLORS[Math.floor(Math.random() * CONSTANTS.SNAKE_COLORS.length)];
        this.achievements = [];
        
        this.segments = [];
        this.initializeSegments();
        
        this.eatenCharacters = [];
        this.letterCounts = { C: 0, B: 0, J: 0, S: 0 };
        
        this.lastUpdate = Date.now();
        this.lastBoostConsume = 0;
        this.boostConsumeInterval = 500;
        this.lastCollisionCheck = 0;
        this.collisionCheckInterval = 50;
    }
    
    initializeSegments() {
        for (let i = 0; i < CONSTANTS.INITIAL_LENGTH; i++) {
            this.segments.push({
                x: this.x - i * CONSTANTS.SEGMENT_SPACING,
                y: this.y
            });
        }
    }
    
    update(deltaTime) {
        if (!this.isAlive) return;
        
        const now = Date.now();
        
        this.speed = this.isBoosting ? CONSTANTS.BOOST_SPEED : CONSTANTS.SNAKE_SPEED;
        
        const moveDistance = this.speed * deltaTime;
        this.x += Math.cos(this.direction) * moveDistance;
        this.y += Math.sin(this.direction) * moveDistance;
        
        if (this.x < 0 || this.x > CONSTANTS.WORLD_WIDTH || 
            this.y < 0 || this.y > CONSTANTS.WORLD_HEIGHT) {
            this.isAlive = false;
            return;
        }
        
        if (this.segments.length > 0) {
            this.segments[0].x = this.x;
            this.segments[0].y = this.y;
            
            for (let i = 1; i < this.segments.length; i++) {
                const segment = this.segments[i];
                const prevSegment = this.segments[i - 1];
                
                const dx = prevSegment.x - segment.x;
                const dy = prevSegment.y - segment.y;
                const distance = Math.sqrt(dx * dx + dy * dy);
                
                if (distance > CONSTANTS.SEGMENT_SPACING) {
                    const moveRatio = Math.min((distance - CONSTANTS.SEGMENT_SPACING) / distance, 1);
                    segment.x += dx * moveRatio;
                    segment.y += dy * moveRatio;
                }
                else if (distance < CONSTANTS.SEGMENT_SPACING && distance > 0) {
                    const moveRatio = Math.min((CONSTANTS.SEGMENT_SPACING - distance) / distance, 1);
                    segment.x -= dx * moveRatio;
                    segment.y -= dy * moveRatio;
                }
            }
        }
        
        if (this.isBoosting && this.eatenCharacters.length > 0) {
            if (now - this.lastBoostConsume > this.boostConsumeInterval) {
                this.consumeCharacter();
                this.lastBoostConsume = now;
            }
        }
        
        if (this.segments.length > 20 && now - this.lastCollisionCheck > this.collisionCheckInterval) {
            this.checkSelfCollision();
            this.lastCollisionCheck = now;
        }
        
        this.lastUpdate = now;
    }
    
    consumeCharacter() {
        if (this.eatenCharacters.length === 0) return;
        
        const removedChar = this.eatenCharacters.pop();
        
        if (CONSTANTS.TARGET_LETTERS.includes(removedChar)) {
            if (this.letterCounts[removedChar] > 0) {
                this.letterCounts[removedChar]--;
            }
        }
        
        if (this.segments.length > CONSTANTS.INITIAL_LENGTH) {
            this.segments.pop();
            this.length = this.segments.length;
        }
    }
    
    eatFood(food) {
        const tail = this.segments[this.segments.length - 1];
        const newSegment = {
            x: tail.x,
            y: tail.y
        };
        this.segments.push(newSegment);
        this.length = this.segments.length;
        
        if (CONSTANTS.TARGET_LETTERS.includes(food.char)) {
            this.eatenCharacters.push(food.char);
            this.letterCounts[food.char]++;
            this.score += CONSTANTS.CBJS_POINTS;
        } else {
            this.eatenCharacters.push(food.char);
            this.score += 10;
        }
    }
    
    checkSelfCollision() {
        const head = this.segments[0];
        const headX = head.x;
        const headY = head.y;
        const collisionThreshold = CONSTANTS.SEGMENT_SIZE * 0.8;
        const collisionThresholdSquared = collisionThreshold * collisionThreshold;
        
        for (let i = 10; i < this.segments.length; i++) {
            const segment = this.segments[i];
            const dx = headX - segment.x;
            const dy = headY - segment.y;
            const distanceSquared = dx * dx + dy * dy;
            
            if (distanceSquared < collisionThresholdSquared) {
                this.isAlive = false;
                return true;
            }
        }
        
        return false;
    }
    
    setDirection(direction) {
        this.direction = direction;
    }
    
    setBoosting(boosting) {
        this.isBoosting = boosting;
    }
    
    getClientData() { 
        return {
            id: this.id,
            x: this.x,
            y: this.y,
            direction: this.direction,
            segments: this.segments,
            score: this.score,
            length: this.length,
            isAlive: this.isAlive,
            isBoosting: this.isBoosting,
            color: this.color,
            eatenCharacters: this.eatenCharacters,
            letterCounts: this.letterCounts
        };
    }
}

module.exports = Snake; 