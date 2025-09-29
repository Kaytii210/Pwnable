const CONSTANTS = require('../../shared/constants');

class Food {
    constructor(x, y) {
        this.x = x;
        this.y = y;
        this.size = CONSTANTS.FOOD_SIZE;
        this.points = 10;

        if (Math.random() < CONSTANTS.CBJS_SPAWN_RATE) {
            this.char = CONSTANTS.TARGET_LETTERS[Math.floor(Math.random() * CONSTANTS.TARGET_LETTERS.length)];
            this.color = CONSTANTS.CBJS_COLORS[this.char];
            this.points = CONSTANTS.CBJS_POINTS;
            this.size = CONSTANTS.FOOD_SIZE + 4;
        } 
        else if(Math.random() > CONSTANTS.CBJS_SPAWN_RATE && Math.random() < CONSTANTS.CBJS_SPAWN_RATE*5) {
            this.char = this.generageSpecialChar();
            this.color = CONSTANTS.FOOD_COLORS[Math.floor(Math.random() * CONSTANTS.FOOD_COLORS.length)];
        }
        else {
            this.char = this.generateRandomChar();
            this.color = CONSTANTS.FOOD_COLORS[Math.floor(Math.random() * CONSTANTS.FOOD_COLORS.length)];
        }
    }
    
    generateRandomChar() {
        const chars = 'CSPDGAFEIUOBKMQRTUVWYZ0123456789#$';
        return chars.charAt(Math.floor(Math.random() * chars.length));
    }
    generageSpecialChar(){
        const chars = '%XNLH';
        return chars.charAt(Math.floor(Math.random() * chars.length));
    }
    
    static generateRandomFood() {
        const x = Math.random() * CONSTANTS.WORLD_WIDTH;
        const y = Math.random() * CONSTANTS.WORLD_HEIGHT;
        return new Food(x, y);
    }
    
    getClientData() {
        return {
            x: this.x,
            y: this.y,
            size: this.size,
            color: this.color,
            char: this.char,
            points: this.points
        };
    }
}

module.exports = Food; 