const fs = require('fs');
const path = require('path');
const mysql = require('mysql2/promise');
require('dotenv').config({ path: path.join(__dirname, '../.env') });

async function initializeCloudDatabase() {
    console.log('Connecting to cloud database...');
    try {
        const connection = await mysql.createConnection({
            host: process.env.DB_HOST,
            user: process.env.DB_USER,
            password: process.env.DB_PASSWORD,
            database: process.env.DB_NAME,
            port: process.env.DB_PORT,
            multipleStatements: true // Allows running the entire SQL file at once
        });

        console.log('Reading schema.sql file...');
        const schemaPath = path.join(__dirname, 'schema.sql');
        const sqlSchema = fs.readFileSync(schemaPath, 'utf8');

        console.log('Executing tables creation structure on Aiven...');
        await connection.query(sqlSchema);
        console.log('🎉 Success! All database tables created successfully on the cloud.');
        await connection.end();
    } catch (error) {
        console.error('❌ Error executing schema initialization:', error);
    }
}

initializeCloudDatabase();