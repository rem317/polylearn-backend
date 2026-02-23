const mysql = require('mysql2/promise');
require('dotenv').config();

const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT || 3306,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    enableKeepAlive: true,
    keepAliveInitialDelay: 0
});

// Test connection
pool.getConnection()
    .then(connection => {
        console.log('✅ Connected to MySQL database');
        console.log(`📊 Database: ${process.env.DB_NAME}`);
        connection.release();
    })
    .catch(err => {
        console.error('❌ Database connection failed:', err.message);
        console.log('💡 Please check:');
        console.log('   1. MySQL is running');
        console.log('   2. Database exists (run schema.sql)');
        console.log('   3. .env file has correct credentials');
        process.exit(1);
    });

module.exports = pool;