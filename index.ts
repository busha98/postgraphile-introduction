require('dotenv').config()

process.env.TZ = 'UTC'

import express from 'express'
import { postgraphile } from 'postgraphile'
import PgManyToManyPlugin from "@graphile-contrib/pg-many-to-many"


const app = express();

app.use(
  postgraphile(
    process.env.DATABASE_URL || "postgres://root:password@localhost:5432/sandbox",
    "public",
    {
      ignoreRBAC: false,
      watchPg: true,
      graphiql: process.env.NODE_ENV === 'prod' ? false : true,
      enhanceGraphiql: true,
      pgDefaultRole: process.env.DEFAULT_ROLE || 'guest',
      jwtSecret: process.env.JWT_SECRET || 'secret',
      jwtPgTypeIdentifier: process.env.JWT_TYPE_IDENTIFIER || 'public.jwt_token',
      enableCors: true,
      appendPlugins: [PgManyToManyPlugin],
    }
  )
)

app.listen(process.env.PORT || 3000, () => {
  console.log(`App started | PORT=${process.env.PORT || 3000}`)
})
