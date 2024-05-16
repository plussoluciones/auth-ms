import 'dotenv/config';
import * as joi from 'joi';

interface EnvVars {
  NATS_SERVERS: string;
  DATABASE_URL: string;
  JWT_SECRET: string;
}

const envsSchema = joi
  .object({
    NATS_SERVERS: joi.array().items(joi.string()).required(),
    DATABASE_URL: joi.required(),
    JWT_SECRET: joi.required(),
  })
  .unknown(true);

const { error, value } = envsSchema.validate({
  ...process.env,
  NATS_SERVERS: process.env.NATS_SERVERS?.split(','),
});

if (error) {
  throw new Error(`Config validation error: ${error.message}`);
}

const envVars: EnvVars = value;

export const envs = {
  natsServers: envVars.NATS_SERVERS,
  databaseUrl: envVars.DATABASE_URL,
  jwtSecret: envVars.JWT_SECRET,
};
