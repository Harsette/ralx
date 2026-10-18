CREATE TABLE native_accounts (id TEXT PRIMARY KEY,user_id TEXT NOT NULL,provider TEXT NOT NULL,subject TEXT NOT NULL,label TEXT NOT NULL,scopes TEXT NOT NULL,payload TEXT NOT NULL,created_at TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'active',UNIQUE(user_id,provider,subject));
CREATE INDEX native_accounts_user ON native_accounts(user_id);
CREATE TABLE provider_states (hash TEXT PRIMARY KEY,user_id TEXT NOT NULL,provider TEXT NOT NULL,slug TEXT NOT NULL,verifier TEXT NOT NULL,expires INTEGER NOT NULL);
