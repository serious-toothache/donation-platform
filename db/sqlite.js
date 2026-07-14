// db/sqlite.js
// Requires: npm install better-sqlite3
// better-sqlite3 is synchronous under the hood (which is its main selling
// point — no callback/promise overhead for local file access), but every
// function here is still declared async so server.js can use the exact same
// `await db.method(...)` calls regardless of which driver is active.
const Database = require('better-sqlite3');

const db = new Database(process.env.SQLITE_PATH || 'donations.db');
db.pragma('journal_mode = WAL'); // better concurrent read/write behavior for a file DB

async function findOrCreateDonor({ stripeCustomerId, email, name, country }) {
  if (!stripeCustomerId) return null;

  const existing = db
    .prepare('SELECT id FROM donors WHERE stripe_customer_id = ?')
    .get(stripeCustomerId);
  if (existing) return existing.id;

  const insert = db.prepare(
    `INSERT INTO donors (stripe_customer_id, email, name, country) VALUES (?, ?, ?, ?)
     ON CONFLICT(stripe_customer_id) DO UPDATE
       SET email = excluded.email, name = excluded.name, country = excluded.country`
  );
  const result = insert.run(stripeCustomerId, email || null, name || null, country || null);
  if (result.lastInsertRowid) return result.lastInsertRowid;

  // ON CONFLICT path doesn't return lastInsertRowid for the existing row
  const row = db
    .prepare('SELECT id FROM donors WHERE stripe_customer_id = ?')
    .get(stripeCustomerId);
  return row.id;
}

// Used at checkout-creation time, when we've already collected the full
// "My Information" form ourselves — richer than findOrCreateDonor.
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
  db.prepare(
    `INSERT INTO donors
       (stripe_customer_id, email, name, phone, organization, spouse_name,
        address_line1, address_line2, city, state, postal_code, country)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(stripe_customer_id) DO UPDATE SET
       email = excluded.email,
       name = excluded.name,
       phone = excluded.phone,
       organization = excluded.organization,
       spouse_name = excluded.spouse_name,
       address_line1 = excluded.address_line1,
       address_line2 = excluded.address_line2,
       city = excluded.city,
       state = excluded.state,
       postal_code = excluded.postal_code,
       country = excluded.country`
  ).run(
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
    country || null
  );

  const row = db
    .prepare('SELECT id FROM donors WHERE stripe_customer_id = ?')
    .get(stripeCustomerId);
  return row.id;
}

// Called at PaymentIntent-creation time. donor_id and, for recurring gifts,
// stripe_subscription_id are already known (we collect donor info and
// create the Subscription ourselves before payment), so both are set here
// rather than waiting for a webhook to backfill them.
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
  db.prepare(
    `INSERT INTO donations
       (stripe_payment_intent_id, donor_id, stripe_subscription_id,
        fund, amount_cents, currency, recurring, is_anonymous, status)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending')
     ON CONFLICT(stripe_payment_intent_id) DO NOTHING`
  ).run(
    stripePaymentIntentId,
    donorId || null,
    stripeSubscriptionId || null,
    fund,
    amountCents,
    currency,
    recurring ? 1 : 0,
    isAnonymous ? 1 : 0
  );
}

// Called from the webhook once payment_intent.succeeded fires — donor_id
// and stripe_subscription_id are already set, so this just flips status.
async function markDonationSucceeded({ stripePaymentIntentId }) {
  db.prepare(
    `UPDATE donations SET status = 'completed' WHERE stripe_payment_intent_id = ?`
  ).run(stripePaymentIntentId);
}

async function markSubscriptionCanceled({ subscriptionId }) {
  db.prepare(
    `UPDATE donations SET status = 'canceled' WHERE stripe_subscription_id = ?`
  ).run(subscriptionId);
}

async function isEventProcessed(eventId) {
  const row = db
    .prepare('SELECT 1 FROM processed_webhook_events WHERE event_id = ?')
    .get(eventId);
  return !!row;
}

async function markEventProcessed(eventId, eventType) {
  db.prepare(
    `INSERT INTO processed_webhook_events (event_id, event_type)
     VALUES (?, ?)
     ON CONFLICT(event_id) DO NOTHING`
  ).run(eventId, eventType);
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