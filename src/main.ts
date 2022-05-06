import express from 'express';
import logger from 'morgan';
import helmet from 'helmet';
import httpProxy from 'express-http-proxy';
import { resolve } from 'path';
import { readFileSync } from 'fs';
import { safeLoad } from 'js-yaml';
import jwt from 'jsonwebtoken' 

const app = express();

const pathfile = resolve(process.cwd(), 'config.yml');
const readConfig = readFileSync(pathfile, { encoding: 'utf8' });
const { services } = safeLoad(readConfig, { json: true });


app.use(logger('dev'));
app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const PORT = process.env.PORT || 3000
const USER_URL_MS: string = 'http://localhost:3002'
const SERVICE_URL_MS: string = 'http://localhost:3001'
app.get('/', (req, res) => {
  return res.json({ message: 'Running application' });
});

let checkToken = (req, res, next) => { 
  let authToken = req.headers["authorization"] 
  if (!authToken) {         
      res.status(401).json({ message: 'Token de acesso requerida' }) 
  } 
  else { 
      let token = authToken.split(' ')[1] 
      req.token = token 
  } 

  jwt.verify(req.token, 'secretKey', (err, decodeToken) => { 
      if (err) { 
          res.status(401).json({ message: 'Acesso negado'}) 
          return 
      }
      req.user_id = decodeToken.userId 
      next() 
  }) 
} 

app.post(`/auth/sessions`, httpProxy(USER_URL_MS, { timeout: 3000 }));

app.get(`/users`, checkToken, httpProxy(USER_URL_MS, { timeout: 3000 }));
app.post(`/users`, httpProxy(USER_URL_MS, { timeout: 3000 }));
app.get(`/users/:id`, checkToken, httpProxy(USER_URL_MS, { timeout: 3000 }));

app.get(`/roles`, httpProxy(USER_URL_MS, { timeout: 3000 }));
app.post(`/roles`, checkToken, httpProxy(USER_URL_MS, { timeout: 3000 }));
app.delete(`/roles/:id`, checkToken, httpProxy(USER_URL_MS, { timeout: 3000 }));
app.get(`/roles/:id`, checkToken, httpProxy(USER_URL_MS, { timeout: 3000 }));

app.get(`/categories`, checkToken, httpProxy(SERVICE_URL_MS, { timeout: 3000 }));
app.post(`/categories`, checkToken, httpProxy(SERVICE_URL_MS, { timeout: 3000 }));
app.delete(`/categories/:id`, checkToken, httpProxy(SERVICE_URL_MS, { timeout: 3000 }));
app.get(`/categories/:id`, checkToken, httpProxy(SERVICE_URL_MS, { timeout: 3000 }));

app.get(`/services`, checkToken, httpProxy(SERVICE_URL_MS, { timeout: 3000 }));
app.post(`/services`, checkToken, httpProxy(SERVICE_URL_MS, { timeout: 3000 }));
app.delete(`/services/:id`, checkToken, httpProxy(SERVICE_URL_MS, { timeout: 3000 }));
app.get(`/services/:id`, checkToken, httpProxy(SERVICE_URL_MS, { timeout: 3000 }));

app.get(`/service-users`, checkToken, httpProxy(SERVICE_URL_MS, { timeout: 3000 }));
app.post(`/service-users`, checkToken, httpProxy(SERVICE_URL_MS, { timeout: 3000 }));
app.delete(`/service-users/:id`, checkToken, httpProxy(SERVICE_URL_MS, { timeout: 3000 }));
app.get(`/service-users/:id`, checkToken, httpProxy(SERVICE_URL_MS, { timeout: 3000 }));
app.patch(`/service-users`, checkToken, httpProxy(SERVICE_URL_MS, { timeout: 3000 }));

app.get(`/service-user-items`, checkToken, httpProxy(SERVICE_URL_MS, { timeout: 3000 }));
app.post(`/service-user-items`, checkToken, httpProxy(SERVICE_URL_MS, { timeout: 3000 }));
app.delete(`/service-user-items/:id`, checkToken, httpProxy(SERVICE_URL_MS, { timeout: 3000 }));
app.get(`/service-user-items/:id`, checkToken, httpProxy(SERVICE_URL_MS, { timeout: 3000 }));
app.patch(`/service-user-items`, checkToken, httpProxy(SERVICE_URL_MS, { timeout: 3000 }));

app.listen(PORT, () => console.log('Running application'));
