// db/postgres.js
// Requires: npm install pg
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  // Most managed Postgres providers (Render, Railway, RDS, Supabase) require
  // SSL for external connections but use a self-signed/internal cert chain,
  // so rejectUnauthorized is commonly disabled for the provider's proxy.
  // Check your provider's docs — if they give you a CA cert, use that
  // instead of disabling verification.
  ssl: process.env.DATABASE_URL?.includes('sslmode=require')
    ? { rejectUnauthorized: false }
    : false,
});

async function findOrCreateDonor({ stripeCustomerId, email, name, country }) {
  if (!stripeCustomerId) return null;

  const existing = await pool.query(
    'SELECT id FROM donors WHERE stripe_customer_id = $1',
    [stripeCustomerId]
  );
  if (existing.rows.length > 0) return existing.rows[0].id;

  const inserted = await pool.query(
    `INSERT INTO donors (stripe_customer_id, email, name, country)
     VALUES ($1, $2, $3, $4)
     ON CONFLICT (stripe_customer_id) DO UPDATE
       SET email = EXCLUDED.email, name = EXCLUDED.name, country = EXCLUDED.country
     RETURNING id`,
    [stripeCustomerId, email || null, name || null, country || null]
  );
  return inserted.rows[0].id;
}

// Used at checkout-creation time, when we've already collected the full
// "My Information" form ourselves — richer than findOrCreateDonor, which
// only has what Stripe's own billing address collection gathered.
async function upsertDonorProfile({
  stripeCustomerId,
  email,
  name,
  phone,
  organization,
  spouseName,
  addressLine1,
  addressLine2,
  city,
  state,
  postalCode,
  country,
}) {
  const result = await pool.query(
    `INSERT INTO donors
       (stripe_customer_id, email, name, phone, organization, spouse_name,
        address_line1, address_line2, city, state, postal_code, country)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
     ON CONFLICT (stripe_customer_id) DO UPDATE SET
       email = EXCLUDED.email,
       name = EXCLUDED.name,
       phone = EXCLUDED.phone,
       organization = EXCLUDED.organization,
       spouse_name = EXCLUDED.spouse_name,
       address_line1 = EXCLUDED.address_line1,
       address_line2 = EXCLUDED.address_line2,
       city = EXCLUDED.city,
       state = EXCLUDED.state,
       postal_code = EXCLUDED.postal_code,
       country = EXCLUDED.country
     RETURNING id`,
    [
      stripeCustomerId,
      email || null,
      name || null,
      phone || null,
      organization || null,
      spouseName || null,
      addressLine1 || null,
      addressLine2 || null,
      city || null,
      state || null,
      postalCode || null,
      country || null,
    ]
  );
  return result.rows[0].id;
}

// Called at PaymentIntent-creation time. Unlike the old redirect-based
// Checkout flow, we already know the donor (we collected their info
// ourselves before payment) and, for recurring gifts, the subscription id
// (we create the Subscription object ourselves) — so both are set
// immediately rather than waiting for a webhook to backfill them.
async function createPendingDonation({
  stripePaymentIntentId,
  donorId,
  stripeSubscriptionId,
  fund,
  amountCents,
  currency,
  recurring,
  isAnonymous,
}) {
  await pool.query(
    `INSERT INTO donations
       (stripe_payment_intent_id, donor_id, stripe_subscription_id,
        fund, amount_cents, currency, recurring, is_anonymous, status)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'pending')
     ON CONFLICT (stripe_payment_intent_id) DO NOTHING`,
    [stripePaymentIntentId, donorId, stripeSubscriptionId || null, fund, amountCents, currency, recurring, !!isAnonymous]
  );
}

// Called from the webhook once payment_intent.succeeded actually fires —
// donor_id and stripe_subscription_id are already set, so this just flips
// the status.
async function markDonationSucceeded({ stripePaymentIntentId }) {
  await pool.query(
    `UPDATE donations SET status = 'completed' WHERE stripe_payment_intent_id = $1`,
    [stripePaymentIntentId]
  );
}

async function markSubscriptionCanceled({ subscriptionId }) {
  await pool.query(
    `UPDATE donations SET status = 'canceled' WHERE stripe_subscription_id = $1`,
    [subscriptionId]
  );
}

async function isEventProcessed(eventId) {
  const result = await pool.query(
    'SELECT 1 FROM processed_webhook_events WHERE event_id = $1',
    [eventId]
  );
  return result.rows.length > 0;
}

async function markEventProcessed(eventId, eventType) {
  // ON CONFLICT DO NOTHING makes this safe to call concurrently for the
  // same event without throwing on the primary key collision.
  await pool.query(
    `INSERT INTO processed_webhook_events (event_id, event_type)
     VALUES ($1, $2)
     ON CONFLICT (event_id) DO NOTHING`,
    [eventId, eventType]
  );
}

module.exports = {
  findOrCreateDonor,
  upsertDonorProfile,
  createPendingDonation,
  markDonationSucceeded,
  markSubscriptionCanceled,
  isEventProcessed,
  markEventProcessed,
};