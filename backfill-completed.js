// backfill-completed.js
const fs = require('fs');
const path = require('path');
const dbPath = path.join(__dirname, 'db.json');
const db = JSON.parse(fs.readFileSync(dbPath, 'utf8'));

let changed = 0;
db.projects.forEach(p => {
  (p.tasks || []).forEach(t => {
    if (t.status === 'done' && t.dueDate) {
      t.completedAt = t.dueDate;
      changed++;
    }
  });
});

fs.writeFileSync(dbPath, JSON.stringify(db, null, 2));
console.log(`Set completedAt = dueDate on ${changed} task(s).`);