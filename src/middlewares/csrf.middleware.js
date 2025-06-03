import csurf from 'csurf';
const csrfProtection = csurf({ cookie: true });
export default csrfProtection;