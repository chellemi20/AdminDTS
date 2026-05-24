const mysql = require('mysql2/promise');

(async () => {
  try {
    const db = await mysql.createPool({
      host: 'localhost',
      user: 'root',
      password: '',
      port: 3307,
      database: 'dts_da_new',
      waitForConnections: true,
    });

    const [rows] = await db.query('SELECT user_id, full_name, username, email_address, password, status FROM users LIMIT 20');
    console.log('RESULTS:', JSON.stringify(rows, null, 2));
    process.exit(0);
  } catch (err) {
    console.error('ERROR:', err.message);
    process.exit(1);
  }
})();
