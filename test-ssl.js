const mysql = require('mysql2');
const dotenv = require('dotenv');

dotenv.config();

console.log('🔍 Testing TiDB Cloud SSL connection...');
console.log('Host:', process.env.DB_HOST);
console.log('Port:', process.env.DB_PORT);
console.log('User:', process.env.DB_USER);
console.log('Database:', process.env.DB_NAME);

const pool = mysql.createPool({
    host: process.env.DB_HOST,
    port: Number(process.env.DB_PORT) || 4000,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    ssl: {
        rejectUnauthorized: true
    }
});

pool.query('SELECT 1+1 AS solution', (err, results) => {
    if (err) {
        console.error('❌ SSL Connection FAILED:', err.message);
    } else {
        console.log('✅ SSL Connection SUCCESSFUL!');
        console.log('Test query result:', results[0].solution);
    }
    pool.end();
});