-- A coarse "Browser · OS" label from the User-Agent at session creation, shown in the user's
-- own session list. The full User-Agent is not stored.
ALTER TABLE sessions
    ADD device TEXT;
