const crypto = require('crypto');
const fs = require('fs');

// Загрузка данных из файлов
const publicKeyPem = fs.readFileSync('public1.pem', 'utf8');
const signature = fs.readFileSync('signature1.txt');
const data = fs.readFileSync('data1.txt', 'utf8');
console.log('signature:', signature);

// Верификация подписи
const verify = crypto.createVerify('SHA256');
verify.update(data);
verify.end();

const isValid = verify.verify(publicKeyPem, signature);
console.log('Is Valid:', isValid);

