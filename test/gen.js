const crypto = require('crypto');
const fs = require('fs');

// Генерация ключей
const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
  namedCurve: 'P-256',
  publicKeyEncoding: {
    type: 'spki',
    format: 'pem',
  },
  privateKeyEncoding: {
    type: 'pkcs8',
    format: 'pem',
  },
});

// Сохранение ключей в файлы
fs.writeFileSync('private.pem', privateKey);
fs.writeFileSync('public.pem', publicKey);

// Данные для подписи
const data = '302a300506032b6570032100fb1407a0a82f034bcd8d4c61bd260f1aeb0519d8ce73736506116ce9113fa328';
fs.writeFileSync('data.txt', data);

// Подпись данных
const sign = crypto.createSign('SHA256');
sign.update(data);
sign.end();
const signature = sign.sign(privateKey);
fs.writeFileSync('signature.bin', signature);

