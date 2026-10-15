const { exec } = require('child_process');

exec('netstat -ano -p tcp', (err, stdout) => {
  if (err) {
    console.error('Error:', err);
    return;
  }
  const lines = stdout.split('\n');
  const external = [];
  for (const line of lines) {
    const parts = line.trim().split(/\s+/);
    if (parts.length >= 5 && parts[0] === 'TCP' && parts[3] === 'ESTABLISHED') {
      const remote = parts[2];
      if (!remote.startsWith('127.') && !remote.startsWith('[::1]')) {
        external.push({ local: parts[1], remote: parts[2], pid: parts[4] });
      }
    }
  }
  console.log('Online?', external.length > 0);
  console.log('Count:', external.length);
  console.log('Sample:', external.slice(0, 5));
});
