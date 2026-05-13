'use strict';

const express = require('express');
const helmet = require('helmet');
const morgan = require('morgan');
const path = require('path');
const cors = require('cors');
const { ipRateLimiter, userRateLimiter } = require('./middleware/rate-limit.middleware');
const { authenticateJWT } = require('./middleware/auth.middleware');
const { errorHandler } = require('./middleware/error.middleware');
const { proxyToAuth, proxyToMail, proxyToZone } = require('./services/proxy.service');

const app = express();
const allowedOrigins = [
  'http://localhost:3000',
  'http://localhost:5173',
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true); // allow server-to-server / postman

    const isAllowed = allowedOrigins.some(o => {
      if (o.includes('*')) {
        return origin.endsWith(o.replace('*', ''));
      }
      return o === origin;
    });

    if (isAllowed) {
      callback(null, true);
    } else {
      callback(new Error(`CORS blocked: ${origin}`));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-api-key'],
}));
// ── Security & logging ────────────────────────────────────────────────────────
app.use(helmet());
app.use(morgan(process.env.NODE_ENV === 'production' ? 'combined' : 'dev'));

// ── Body parsing ──────────────────────────────────────────────────────────────
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// ── IP-level rate limit (applied globally) ───────────────────────────────────
app.use(ipRateLimiter);

// ── API Docs (serves unified docs for all services) ───────────────────────────
app.use('/api-docs', express.static(path.join(__dirname, '../docs')));
app.get('/api-docs', (_req, res) => {
  res.sendFile(path.join(__dirname, '../docs/index.html'));
});

// ── Health check (no auth required) ──────────────────────────────────────────
app.get('/health', (_req, res) => {
  res.status(200).json({
    success: true,
    message: 'API Gateway is running',
    timestamp: new Date().toISOString(),
  });
});

// ── Auth Service routes — JWT optional (some are public login/register) ───────
//    Gateway forwards the x-user-id / x-user-role headers when a valid JWT is
//    present, but does NOT block these routes if no token is provided —
//    because /customer-auth/* contains login & registration endpoints.
app.use(
  '/api/v1/customer-auth',
  (req, res, next) => authenticateJWT(req, res, next, { optional: true }),
  userRateLimiter,
  proxyToAuth,
);

// ── Auth Service — protected customer-data routes ────────────────────────────
const AUTH_PROTECTED = [
  '/api/v1/customers',
  '/api/v1/customer-addresses',
  '/api/v1/cart',
  '/api/v1/wishlist',
  '/api/v1/coupons',
  '/api/v1/reviews',
  '/api/v1/notifications',
];

AUTH_PROTECTED.forEach((prefix) => {
  app.use(prefix, authenticateJWT, userRateLimiter, proxyToAuth);
});

// ── Mail Service routes — internal only, still JWT-protected ─────────────────
const MAIL_ROUTES = [
  '/api/v1/mail-templates',
  '/api/v1/mail-queues',
  '/api/v1/mail-logs',
  '/api/v1/otp',
];

MAIL_ROUTES.forEach((prefix) => {
  app.use(prefix, authenticateJWT, userRateLimiter, proxyToMail);
});

// ── Zone Service routes — JWT required, pin_code-based routing ────────────────
const ZONE_ROUTES = [
  '/api/v1/operators',
  '/api/v1/zones',
  '/api/v1/stores',
  '/api/v1/products',
  '/api/v1/orders',
  '/api/v1/payments',
  '/api/v1/delivery',
  '/api/v1/store-categories',
  '/api/v1/store-users',
  '/api/v1/product-categories',
  '/api/v1/product-variants',
  '/api/v1/order-deliveries',
  '/api/v1/orders-status-histories',
  '/api/v1/coupons',
  '/api/v1/coupon-usages',
  '/api/v1/reviews'
];

ZONE_ROUTES.forEach((prefix) => {
  app.use(prefix, authenticateJWT, userRateLimiter, proxyToZone);
});
const ZONE_ROUTES_WITHOUT_AUTH = [
  '/api/v1/zone-lookup',
  '/api/v1/demo-admin',
  '/api/v1/administrators',

];
ZONE_ROUTES_WITHOUT_AUTH.forEach((prefix) => {
  app.use(prefix, userRateLimiter, proxyToZone);
});

// ── 404 fallback ──────────────────────────────────────────────────────────────
app.use((_req, res) => {
  res.status(404).json({
    success: false,
    message: 'Route not found',
    error: { reason: 'NOT_FOUND' },
  });
});

// ── Global error handler ──────────────────────────────────────────────────────
app.use(errorHandler);

module.exports = app;
