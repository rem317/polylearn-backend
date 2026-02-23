const mysql = require('mysql2');
const pool = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: 'thesis',  // your actual MySQL password
    database: 'polylearn_db'
});

pool.getConnection((err, connection) => {
    if (err) {
        console.log('❌ MySQL Error:', err.message);
        console.log('💡 Solutions:');
        console.log('   1. Check if MySQL is running');
        console.log('   2. Check password in .env');
        console.log('   3. Run: CREATE DATABASE polylearn_db;');
    } else {
        console.log('✅ MySQL Connected!');
        
        // Check tables
        connection.query('SHOW TABLES', (err, results) => {
            if (err) throw err;
            console.log('📊 Tables:', results.map(r => Object.values(r)[0]));
            connection.release();
        });
    }
});