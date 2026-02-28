CREATE TABLE IF NOT EXISTS chat_sessions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    server_id uuid NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    title text NOT NULL DEFAULT 'Server troubleshooting',
    mode text NOT NULL DEFAULT 'suggest_only' CHECK (mode IN ('suggest_only')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    last_message_at timestamptz NULL
);

CREATE INDEX IF NOT EXISTS idx_chat_sessions_user_server_updated_desc
    ON chat_sessions (user_id, server_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_chat_sessions_user_last_message_desc
    ON chat_sessions (user_id, last_message_at DESC NULLS LAST, created_at DESC);

CREATE TABLE IF NOT EXISTS chat_messages (
    id bigserial PRIMARY KEY,
    session_id uuid NOT NULL REFERENCES chat_sessions(id) ON DELETE CASCADE,
    user_id uuid NULL REFERENCES users(id) ON DELETE SET NULL,
    role text NOT NULL CHECK (role IN ('system', 'user', 'assistant')),
    content text NOT NULL,
    context_snapshot jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_chat_messages_session_created_at_asc
    ON chat_messages (session_id, created_at ASC, id ASC);
CREATE INDEX IF NOT EXISTS idx_chat_messages_user_created_desc
    ON chat_messages (user_id, created_at DESC);
