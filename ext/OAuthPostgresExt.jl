module OAuthPostgresExt
    
using OAuth, Postgres
import OAuth: JSON

"""
    PostgresAccessTokenStore <: OAuth.AccessTokenStore

PostgreSQL-backed token store for issued access tokens.

Requires a table with the following schema:
```sql
CREATE TABLE access_tokens (
    token TEXT PRIMARY KEY,
    scope TEXT[] NOT NULL DEFAULT '{}',
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    client_id TEXT,
    subject TEXT,
    claims JSONB NOT NULL DEFAULT '{}',
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    confirmation_jkt TEXT
);

CREATE INDEX idx_access_tokens_expires_at ON access_tokens (expires_at);
CREATE INDEX idx_access_tokens_subject ON access_tokens (subject) WHERE subject IS NOT NULL;
```
"""
Base.@kwdef struct PostgresAccessTokenStore{F} <: OAuth.AccessTokenStore
    with_conn::F # with_conn(); do conn; # do conn; end;
    table::String
end

function OAuth.store_access_token!(store::PostgresAccessTokenStore, issued::OAuth.IssuedAccessToken)
    query = """
        INSERT INTO \"$(store.table)\" (token, scope, issued_at, expires_at, client_id, subject, claims, revoked, confirmation_jkt)
        VALUES (\$1, \$2, \$3, \$4, \$5, \$6, \$7, \$8, \$9)
        ON CONFLICT (token) DO UPDATE SET
            scope = EXCLUDED.scope,
            issued_at = EXCLUDED.issued_at,
            expires_at = EXCLUDED.expires_at,
            client_id = EXCLUDED.client_id,
            subject = EXCLUDED.subject,
            claims = EXCLUDED.claims,
            revoked = EXCLUDED.revoked,
            confirmation_jkt = EXCLUDED.confirmation_jkt
        RETURNING token
    """
    scope_array = isempty(issued.scope) ? "{}" : "{" * join(issued.scope, ",") * "}"
    claims_json = JSON.json(issued.claims)

    store.with_conn() do conn
        DBInterface.execute(
            conn, query, [
                issued.token,
                scope_array,
                issued.issued_at,
                issued.expires_at,
                issued.client_id,
                issued.subject,
                claims_json,
                false,
                issued.confirmation_jkt,
            ]
        )
    end

    return OAuth.AccessTokenRecord(
        issued.token,
        copy(issued.scope),
        issued.issued_at,
        issued.expires_at,
        issued.client_id,
        issued.subject,
        Dict{String, Any}(issued.claims),
        false,
        issued.confirmation_jkt,
    )
end

function OAuth.lookup_access_token(store::PostgresAccessTokenStore, token::AbstractString)
    query = """
        SELECT token, scope, issued_at, expires_at, client_id, subject, claims, revoked, confirmation_jkt
        FROM $(store.table)
        WHERE token = \$1
    """
    result = store.with_conn() do conn
        DBInterface.execute(conn, query, [String(token)])
    end

    if LibPQ.num_rows(result) == 0
        return nothing
    end

    row = first(LibPQ.rowtable(result))

    # Parse scope array from Postgres format
    scope_str = row.scope
    scope = if scope_str == "{}" || scope_str === nothing
        String[]
    else
        # Remove braces and split
        String.(split(scope_str[2:(end - 1)], ","))
    end

    # Parse claims JSON
    claims = Dict{String, Any}(JSON3.read(row.claims))

    return OAuth.AccessTokenRecord(
        row.token,
        scope,
        row.issued_at,
        row.expires_at,
        row.client_id,
        row.subject,
        claims,
        row.revoked,
        row.confirmation_jkt,
    )
end

function OAuth.revoke_access_token!(store::PostgresAccessTokenStore, token::AbstractString)
    query = """
        UPDATE $(store.table)
        SET revoked = TRUE
        WHERE token = \$1 AND revoked = FALSE
        RETURNING token
    """
    result = LibPQ.execute(store.conn, query, [String(token)])
    return LibPQ.num_rows(result) > 0
end

"""
    cleanup_expired_tokens!(store::PostgresAccessTokenStore; before=Dates.now(Dates.UTC)) -> Int

Delete expired tokens from the store. Returns the number of tokens deleted.
"""
function cleanup_expired_tokens!(store::PostgresAccessTokenStore; before::DateTime = Dates.now(Dates.UTC))
    query = """
        DELETE FROM $(store.table)
        WHERE expires_at < \$1
        RETURNING token
    """
    result = LibPQ.execute(store.conn, query, [before])
    return LibPQ.num_rows(result)
end


end # module