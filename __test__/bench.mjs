import { Bench } from 'tinybench';
import { JwtService } from '../index.js'
import jwt from 'jsonwebtoken';
import fs from 'node:fs';

const PRIVATE_KEY = fs.readFileSync('./__test__/private_key.pem', 'utf8');
const jwtService = new JwtService('your-kid', PRIVATE_KEY)

const payload = {
  iss: 'your-issuer',
  sub: 'subject',
  aud: ['audience'],
  exp: Math.floor(Date.now() / 1000) + (60 * 60), // expires in 1 hour
};

const bench = new Bench({ time: 3000 });

bench
  .add('rust sign jwt', async () => {
    const token = jwtService.generateToken(payload)
    return token
  })
  .add('js sign jwt', () => {
    const token = jwt.sign(payload, PRIVATE_KEY, { algorithm: 'RS256' });
    return token
  });

await bench.run();

console.table(bench.table());
