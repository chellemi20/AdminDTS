(async () => {
  try {
    const res = await fetch('http://localhost:5000/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'maria@2026', password: '12345' })
    });
    const data = await res.json();
    console.log('STATUS', res.status);
    console.log('BODY', JSON.stringify(data, null, 2));
  } catch (err) {
    console.error('ERR', err.message);
  }
})();
