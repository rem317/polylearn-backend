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
        
        // Split into individual statements
        const statements = schemaSQL
            .split(';')
            .map(stmt => stmt.trim())
            .filter(stmt => stmt && !stmt.startsWith('--'));
        
        console.log(`📋 Creating ${statements.length} tables...`);
        
        // Execute each statement
        for (let i = 0; i < statements.length; i++) {
            try {
                await promisePool.query(statements[i]);
                console.log(`✅ Created table ${i + 1}/${statements.length}`);
            } catch (err) {
                if (err.code === 'ER_TABLE_EXISTS_ERROR') {
                    console.log(`⚠️ Table ${i + 1}/${statements.length} already exists`);
                } else {
                    console.error(`❌ Error creating table ${i + 1}:`, err.message);
                }
            }
        }
        
        // Show tables after creation
        const [tables] = await promisePool.query('SHOW TABLES');
        console.log('\n📋 Tables created:');
        tables.forEach(row => {
            console.log(`   - ${Object.values(row)[0]}`);
        });
        
    } catch (err) {
        console.error('❌ Migration failed:', err.message);
    } finally {
        pool.end();
    }
}

createTables();