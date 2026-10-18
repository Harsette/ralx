CREATE TABLE vault_imports (id TEXT PRIMARY KEY,user_id TEXT NOT NULL,format TEXT NOT NULL CHECK(format IN ('chrome-csv','1password-csv','1password-1pux')),items INTEGER NOT NULL,created_at TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'ready');
CREATE TABLE vault_chunks (import_id TEXT NOT NULL,part INTEGER NOT NULL,payload TEXT NOT NULL,PRIMARY KEY(import_id,part));
CREATE TABLE vault_items (id TEXT PRIMARY KEY,user_id TEXT NOT NULL,source TEXT NOT NULL CHECK(source IN ('manual','chrome-csv','1password-csv','1password-1pux')),kind TEXT NOT NULL CHECK(kind IN ('login','private')),payload TEXT NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
CREATE INDEX vault_items_user ON vault_items(user_id,kind);
CREATE TABLE vault_origins (item_id TEXT NOT NULL,user_id TEXT NOT NULL,origin_hash TEXT NOT NULL,PRIMARY KEY(user_id,origin_hash,item_id));
CREATE INDEX vault_origins_item ON vault_origins(user_id,item_id);
CREATE INDEX vault_imports_user ON vault_imports(user_id);
CREATE TABLE login_requests (id TEXT PRIMARY KEY,user_id TEXT NOT NULL,agent_id TEXT NOT NULL,origin_hash TEXT NOT NULL,payload TEXT NOT NULL,expires INTEGER NOT NULL,status TEXT NOT NULL DEFAULT 'pending',item_id TEXT);
