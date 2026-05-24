import mysql from 'mysql2';
import dotenv from 'dotenv';

dotenv.config({ path: '../.env' });

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT ? Number(process.env.DB_PORT) : 3307,
  database: process.env.DB_NAME,
});

const db = pool.promise();

pool.getConnection((err, conn) => {
  if (err) console.log("May error sa database:", err);
  else {
    console.log("MySQL Connected!");
    conn.release();
  }
});

export default db;