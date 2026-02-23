const mysql = require('mysql2');
require('dotenv').config();

const pool = mysql.createPool({
    host: process.env.DB_HOST,
    port: Number(process.env.DB_PORT),
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    ssl: { rejectUnauthorized: true }
});

const promisePool = pool.promise();

async function showTables() {
    try {
        const [rows] = await promisePool.query('SHOW TABLES');
        console.log('📋 Tables in database:');
        rows.forEach(row => {
            console.log(`   - ${Object.values(row)[0]}`);
        });
    } catch (err) {
        console.error('❌ Error:', err.message);
    }
    pool.end();
}

showTables();