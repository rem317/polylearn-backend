const mysql = require('mysql2');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

console.log('🔄 Starting migration to TiDB Cloud...');

// Create connection with SSL
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

async function migrateDatabase() {
    try {
        // Read schema file
        const schemaSQL = fs.readFileSync(path.join(__dirname, 'polylearn_schema.sql'), 'utf8');
        
        console.log('📦 Schema file loaded, size:', schemaSQL.length, 'bytes');
        
        // Split into individual statements (remove comments and empty lines)
        const statements = schemaSQL
            .split(';')
            .map(stmt => stmt.trim())
            .filter(stmt => stmt && !stmt.startsWith('--'));
        
        console.log(`📋 Found ${statements.length} SQL statements`);
        
        // Execute each statement
        let successCount = 0;
        let errorCount = 0;
        
        for (let i = 0; i < statements.length; i++) {
            const stmt = statements[i];
            try {
                await promisePool.query(stmt);
                console.log(`✅ [${i + 1}/${statements.length}] Executed successfully`);
                successCount++;
            } catch (err) {
                // Ignore "already exists" errors
                if (err.code === 'ER_TABLE_EXISTS_ERROR') {
                    console.log(`⚠️ [${i + 1}/${statements.length}] Table already exists (skipped)`);
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
        
        // Show tables after migration
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

migrateDatabase();