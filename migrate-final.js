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
        
        // Split into individual statements using regex to handle multiple semicolons
        const statements = schemaSQL
            .split(/;\s*\r?\n/)
            .map(stmt => stmt.trim())
            .filter(stmt => stmt && !stmt.startsWith('--') && stmt.length > 0);
        
        console.log(`📋 Found ${statements.length} SQL statements`);
        
        let successCount = 0;
        let errorCount = 0;
        
        // Execute each statement
        for (let i = 0; i < statements.length; i++) {
            try {
                await promisePool.query(statements[i]);
                console.log(`✅ [${i + 1}/${statements.length}] Executed successfully`);
                successCount++;
            } catch (err) {
                if (err.code === 'ER_TABLE_EXISTS_ERROR') {
                    console.log(`⚠️ [${i + 1}/${statements.length}] Table already exists`);
                    successCount++;
                } else {
                    console.error(`❌ [${i + 1}/${statements.length}] Error:`, err.message);
                    errorCount++;
                }
            }
        }
        
        console.log('\n📊 Migration Summary:');
        console.log(`   ✅ Successful: ${successCount}`);
        console.log(`   ❌ Failed: ${errorCount}`);
        
        // Show tables after creation
        const [tables] = await promisePool.query('SHOW TABLES');
        console.log('\n📋 Tables in database:');
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