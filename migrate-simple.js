const mysql = require('mysql2');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

console.log('🔄 Creating tables in TiDB Cloud...');

const pool = mysql.createPool({
    host: process.env.DB_HOST,
    port: Number(process.env.DB_PORT),
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    ssl: { rejectUnauthorized: true },
    multipleStatements: true,
    connectTimeout: 60000
});

const promisePool = pool.promise();

async function createTables() {
    try {
        // Read schema file
        const schemaSQL = fs.readFileSync(path.join(__dirname, 'create_tables_only.sql'), 'utf8');
        
        console.log('📋 Executing entire schema...');
        console.log('SQL length:', schemaSQL.length, 'characters');
        
        // Execute entire schema at once
        await promisePool.query(schemaSQL);
        console.log('✅ Schema executed successfully!');
        
        // Show tables after creation
        const [tables] = await promisePool.query('SHOW TABLES');
        console.log('\n📋 Tables in database:');
        if (tables.length === 0) {
            console.log('   No tables found');
        } else {
            tables.forEach(row => {
                console.log(`   - ${Object.values(row)[0]}`);
            });
        }
        
    } catch (err) {
        console.error('❌ Migration failed:', err.message);
        console.error('❌ SQL Error Code:', err.code);
    } finally {
        pool.end();
    }
}

createTables();