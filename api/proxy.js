// api/proxy.js - Vercel Serverless Function entry point delegating to proxy_server.js
const { handleRequest } = require('../proxy_server');

module.exports = async function handler(req, res) {
  return handleRequest(req, res);
};
