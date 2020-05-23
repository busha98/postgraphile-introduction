exports.up = async function up(db) {
  await db.runSql(`
    CREATE TABLE "groups" (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL
    );

    insert into "groups" (id, "name") values
      (1, 'basic'),
      (2, 'standard');

    CREATE TABLE users (
        id SERIAL PRIMARY KEY,
        email text NOT NULL UNIQUE,
        password text NOT NULL,
        "role" text NOT NULL,
        created_at TIMESTAMP DEFAULT current_timestamp,
        updated_at TIMESTAMP DEFAULT current_timestamp
    );

    CREATE TABLE posts (
      id SERIAL PRIMARY KEY,
      author_id integer references "users" not null,
      group_id integer references "groups" not null,
      text TEXT,
      created_at TIMESTAMP DEFAULT current_timestamp,
      updated_at TIMESTAMP DEFAULT current_timestamp
    );

    CREATE TABLE user_group (
      user_id integer references "users",
      group_id integer references "groups",
      primary key (user_id, group_id)
    );

    comment on table user_group is E'@omit manyToMany';

    CREATE OR REPLACE FUNCTION update_modified_column()
      RETURNS TRIGGER AS $$
        BEGIN
            NEW.updated_at = now();
            RETURN NEW;
        END;
      $$ language 'plpgsql';

    CREATE TRIGGER update_users_updated_at_time
      BEFORE UPDATE ON users FOR EACH ROW
      EXECUTE PROCEDURE update_modified_column();

    CREATE TRIGGER update_posts_update_at_time
      BEFORE UPDATE ON posts FOR EACH ROW
      EXECUTE PROCEDURE update_modified_column();


    CREATE TYPE jwt_token AS (
        role TEXT,
        user_id INTEGER,
        email text,
        exp bigint
    );

    CREATE EXTENSION IF NOT EXISTS pgcrypto;

    CREATE OR REPLACE FUNCTION SIGNUPUSER(email TEXT, password TEXT) RETURNS jwt_token AS
    $$
      DECLARE
            token_information jwt_token;
      BEGIN
            INSERT INTO users (email, password, "role") values
                ($1, crypt($2, gen_salt('bf', 8)), 'user');

            insert into user_group (user_id, group_id ) values
              (
                (select id from users u1 where u1.email = $1),
                (select id from "groups" g1 where g1.name = 'basic')
              );

            SELECT "role", id, u.email, (EXTRACT(EPOCH FROM (SELECT NOW())) + 60*60*24*7) as exp
                   INTO token_information
                   FROM users u
                   WHERE u.email = $1;
            RETURN token_information::jwt_token;
        END;
    $$ LANGUAGE PLPGSQL VOLATILE SECURITY DEFINER;

    CREATE OR REPLACE FUNCTION SIGNIN(email TEXT, password TEXT) RETURNS jwt_token AS
    $$
      DECLARE
            token_information jwt_token;
      BEGIN
            SELECT "role", id, u.email, (EXTRACT(EPOCH FROM (SELECT NOW())) + 60*60*24*7) as exp
                   INTO token_information
                   FROM users u
                   WHERE u.email = $1
                         AND u.password = crypt($2, u.password);
           RETURN token_information::jwt_token;
      END;
    $$ LANGUAGE PLPGSQL VOLATILE STRICT SECURITY DEFINER;

    create function current_user_id() returns integer as $$
      select nullif(current_setting('jwt.claims.user_id', true), '')::integer;
    $$ language sql stable;


    -- ROLES
    DO
    $do$
    BEGIN
       IF NOT EXISTS (
          SELECT FROM pg_catalog.pg_roles
          WHERE  rolname = 'guest') THEN

          CREATE ROLE "guest";
       END IF;
    END
    $do$;
    GRANT EXECUTE ON FUNCTION SIGNUPUSER(email TEXT, password TEXT) TO guest;
    GRANT EXECUTE ON FUNCTION SIGNIN(email TEXT, password TEXT) TO guest;

    DO
    $do$
    BEGIN
       IF NOT EXISTS (
          SELECT FROM pg_catalog.pg_roles
          WHERE  rolname = 'user') THEN

          CREATE ROLE "user";
       END IF;
    END
    $do$;
    GRANT select, insert, update, DELETE ON users TO "user";
    GRANT SELECT, INSERT, UPDATE, DELETE ON "groups" TO "user";
    GRANT SELECT ON user_group TO "user";
    GRANT SELECT, INSERT, UPDATE, DELETE ON posts TO "user";
    GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO "user";

    DO
    $do$
    BEGIN
       IF NOT EXISTS (
          SELECT FROM pg_catalog.pg_roles
          WHERE  rolname = 'admin') THEN

          CREATE ROLE admin;
       END IF;
    END
    $do$;
    GRANT SELECT, INSERT, UPDATE, DELETE ON users TO admin;
    GRANT SELECT, INSERT, UPDATE, DELETE ON "groups" TO admin;
    GRANT SELECT, INSERT, UPDATE, DELETE ON user_group TO admin;
    GRANT SELECT, INSERT, UPDATE, DELETE ON posts TO admin;
    GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO admin;


    -- ROW LEVEL SECURITY
    ALTER TABLE users ENABLE ROW LEVEL SECURITY;
    ALTER TABLE "groups" ENABLE ROW LEVEL SECURITY;
    ALTER TABLE posts ENABLE ROW LEVEL SECURITY;
    ALTER TABLE user_group ENABLE ROW LEVEL SECURITY;

    CREATE POLICY ensure_current_user ON users
      using (
        ("id" = current_user_id()) or
        (current_user = 'admin')
      )
      with check (
        ("id" = current_user_id()) or
        (current_user = 'admin')
      );

    CREATE POLICY ensure_current_user ON user_group
      using (
        ("user_id" = current_user_id()) or
        (current_user = 'admin')
      )
      with check (
        ("user_id" = current_user_id()) or
        (current_user = 'admin')
      );

    CREATE POLICY ensure_current_user ON posts
      using (
        ("group_id" in 
          (
            select group_id from user_group ug
              where ug.user_id = current_user_id()
          )
        ) OR
        ("author_id" = current_user_id()) or 
        (current_user = 'admin')
      )
      with check (
        ("author_id" = current_user_id()) or 
        (current_user = 'admin')
      );
  `)
}

exports._meta = {
  version: 1
}
