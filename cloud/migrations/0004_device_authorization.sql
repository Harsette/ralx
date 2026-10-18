CREATE TABLE device_authorizations (
  device_hash TEXT PRIMARY KEY,
  user_hash TEXT UNIQUE NOT NULL,
  machine_name TEXT NOT NULL,
  clients TEXT NOT NULL,
  expires INTEGER NOT NULL,
  interval INTEGER NOT NULL DEFAULT 5,
  polled_early INTEGER NOT NULL DEFAULT 0,
  next_poll INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'pending',
  user_id TEXT,
  grant_hash TEXT UNIQUE,
  grant_expires INTEGER
);
CREATE TABLE device_clients (
  device_hash TEXT NOT NULL,
  client TEXT NOT NULL,
  PRIMARY KEY(device_hash,client)
);
CREATE INDEX device_expiry ON device_authorizations(expires);
