const mysql = require('mysql2/promise');

(async () => {
  try {
    const db = await mysql.createPool({
      host: 'localhost',
      user: 'root',
      password: '',
      port: 3307,
      database: 'dts_da_new',
    });

    const [rows] = await db.query('SELECT * FROM users WHERE username = ? AND password = ?', ['maria@2026', '12345']);
    console.log('MATCH:', JSON.stringify(rows, null, 2));
  } catch (err) {
    console.error('ERROR:', err.message);
  }
})();
