USE nasv2db;

DROP TABLE IF EXISTS users;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    session VARCHAR(255) DEFAULT NULL
);

INSERT INTO users (username, password, session) VALUES ('admin', '674b3669e744b9e73340591fc87cdf708748ba0f1712169f417b5e754afe0bb8b2d09081ea49bb4bf94ef4e6222e54fb9009827d92615bf9aebdee477d2b9e42', 'HDBH{fake-flag}');
INSERT INTO users (username, password, session) VALUES ('guest', '', SHA2(CONCAT(UUID(), NOW(), RAND(), 'guest'), 256));
INSERT INTO users (username, password, session) VALUES ('quycn', '0ed9ec9c9afad4e820cb1ccbd6fdc8f757e0651da372789b742b248f428a0f287bd62d6af2caec620c915d4af50251179bf44e012ba39852279cf1bb022cb2f7', SHA2(CONCAT(UUID(), NOW(), RAND(), 'quycn'), 256));
INSERT INTO users (username, password, session) VALUES ('trinh', '5d4cf233bf0d3df3fa26cabbc7d46282f96052e0f9f6c1e36420a1a07a317d1fb5d94423b2d34222cd292401ed5abff0b389715ae5b62dfb88ba3599a3f200c4', SHA2(CONCAT(UUID(), NOW(), RAND(), 'trinh'), 256));
INSERT INTO users (username, password, session) VALUES ('anhnlq', '31d0f646439e74b79f0fd57d7e1da93588692c7ec4f8212f2b54a7e66c6a3da506f722a0888d12675a5a30276e541ac4fd19dbacff8406b3e8201d0edf0d1c79', SHA2(CONCAT(UUID(), NOW(), RAND(), 'anhnlq'), 256));
INSERT INTO users (username, password, session) VALUES ('thunq', '96c8c962ec3e2d41df075b06942aa2c6075c41f1188b9cf61ae5191be91c392a6db873e25e32117cee87faf30f1e4e691610aad4f06e45fd68388333e3e3eadb', SHA2(CONCAT(UUID(), NOW(), RAND(), 'thunq'), 256));
INSERT INTO users (username, password, session) VALUES ('chilq', '2c125eb268c562e73ef0cc68be0c83bde80e662c240f56f087ae550b74378ba2dcc9bc090a208c53ff0d023b8cc7e19228ef12d15f5f5c0c44c298ff9d39dc67', SHA2(CONCAT(UUID(), NOW(), RAND(), 'chilq'), 256));
INSERT INTO users (username, password, session) VALUES ('khanhlq', '26eacf54c71eda698dd1ae3f9e1e4f95c03beebcb8591eca192de2bc1cc1b40dec029f263c68104200b5cbefbbde05e3ae458a4ecae78e6d9684e31b26520abf', SHA2(CONCAT(UUID(), NOW(), RAND(), 'khanhlq'), 256));
