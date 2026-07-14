const express = require('express');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const db = require('./db'); // picks postgres.js or sqlite.js based on DB_DRIVER

// Pin the API version per docs.stripe.com/sdks/set-version — this guarantees
// consistent request/response behavior even if your account's default
// version changes later. Update deliberately, not automatically.
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY, {
  apiVersion: '2026-06-24.dahlia',
});

const app = express();

// ---- IMPORTANT ORDERING ----
// The webhook route MUST be registered with express.raw() BEFORE any
// global express.json() middleware. Per docs.stripe.com/webhooks/signature,
// Stripe's constructEvent() needs the exact raw request bytes to verify the
// signature. If express.json() runs first (even as global middleware
// mounted earlier), req.body is already parsed into an object and
// signature verification will fail on every single request.
app.post(
  '/webhook',
  express.raw({ type: 'application/json' }),
  async (req, res) => {
    const sig = req.headers['stripe-signature'];
    if (!sig) {
      return res.status(400).send('Missing stripe-signature header');
    }

    let event;
    try {
      event = stripe.webhooks.constructEvent(
        req.body,
        sig,
        process.env.STRIPE_WEBHOOK_SECRET
      );
    } catch (err) {
      // Signature didn't match, payload was mutated in transit, or the
      // wrong secret/mode (test vs live) was used.
      console.error('Webhook signature verification failed:', err.message);
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    try {
      // Stripe guarantees at-least-once delivery, so the same event.id can
      // arrive more than once (retries, redeploys, network hiccups).
      // Check the DB, not memory, so this survives restarts/redeploys and
      // works correctly across multiple server instances.
      if (await db.isEventProcessed(event.id)) {
        return res.json({ received: true, duplicate: true });
      }

      switch (event.type) {
        case 'checkout.session.completed': {
          const session = event.data.object;
          // We already wrote the full donor profile to the DB at checkout-
          // creation time (see upsertDonorProfile below), since we collect
          // it ourselves via the "My Information" form. This just confirms
          // the donor record exists, keyed by the same Stripe customer id.
          const donorId = await db.findOrCreateDonor({
            stripeCustomerId: session.customer,
            email: session.customer_details?.email,
            name: session.customer_details?.name,
            country: session.customer_details?.address?.country,
          });
          await db.markDonationCompleted({
            checkoutSessionId: session.id,
            donorId,
            subscriptionId: session.subscription || null,
          });
          console.log('Donation completed:', session.id, session.amount_total);
          break;
        }
        case 'invoice.paid': {
          console.log('Recurring donation charge succeeded:', event.data.object.id);
          break;
        }
        case 'customer.subscription.deleted': {
          await db.markSubscriptionCanceled({
            subscriptionId: event.data.object.id,
          });
          console.log('Donor canceled their subscription:', event.data.object.id);
          break;
        }
        default:
          console.log(`Unhandled event type: ${event.type}`);
      }

      await db.markEventProcessed(event.id, event.type);
      // Respond fast — Stripe expects a 2xx within a few seconds or it will
      // treat the delivery as failed and retry with backoff for up to 3 days.
      res.json({ received: true });
    } catch (err) {
      // If our own processing fails (e.g. DB briefly unreachable), return
      // a 500 so Stripe retries this event later instead of silently
      // losing the donation record.
      console.error('Error processing webhook event:', err);
      res.status(500).json({ error: 'Internal error processing event' });
    }
  }
);

// JSON parsing for every other route is registered AFTER the webhook route.
app.use(express.json({ limit: '10kb' }));
app.use(express.static('public'));

// The publishable key is designed to be public (it's embedded in every
// Stripe.js page load anyway) — safe to expose via a plain GET, unlike
// STRIPE_SECRET_KEY. Useful if you add Stripe.js/Elements client-side
// later; not needed by the current hosted-Checkout-redirect flow.
app.get('/config', (req, res) => {
  res.json({ publishableKey: process.env.STRIPE_PUBLISHABLE_KEY });
});

// ---- Server-side source of truth for donation input. Never trust the client. ----

const MIN_AMOUNT_USD = 5;
const MAX_AMOUNT_USD = 999999;

const VALID_FUNDS = new Set([
  'Fred Hutch greatest need',
  'Cancer research',
  'Patient care programs',
  'Clinical trials',
]);

// Server-side country whitelist, mirroring the <select> options offered on
// the frontend. Never trust a country code sent from the client — someone
// could POST any string directly to this endpoint. Full ISO 3166-1 alpha-2 list.
const VALID_COUNTRIES = new Set([
  'AF','AL','DZ','AD','AO','AG','AR','AM','AU','AT','AZ','BS','BH','BD','BB',
  'BY','BE','BZ','BJ','BT','BO','BA','BW','BR','BN','BG','BF','BI','CV','KH',
  'CM','CA','CF','TD','CL','CN','CO','KM','CG','CD','CR','CI','HR','CU','CY',
  'CZ','DK','DJ','DM','DO','EC','EG','SV','GQ','ER','EE','SZ','ET','FJ','FI',
  'FR','GA','GM','GE','DE','GH','GR','GD','GT','GN','GW','GY','HT','HN','HU',
  'IS','IN','ID','IR','IQ','IE','IL','IT','JM','JP','JO','KZ','KE','KI','KP',
  'KR','KW','KG','LA','LV','LB','LS','LR','LY','LI','LT','LU','MG','MW','MY',
  'MV','ML','MT','MH','MR','MU','MX','FM','MD','MC','MN','ME','MA','MZ','MM',
  'NA','NR','NP','NL','NZ','NI','NE','NG','MK','NO','OM','PK','PW','PS','PA',
  'PG','PY','PE','PH','PL','PT','QA','RO','RU','RW','KN','LC','VC','WS','SM',
  'ST','SA','SN','RS','SC','SL','SG','SK','SI','SB','SO','ZA','SS','ES','LK',
  'SD','SR','SE','CH','SY','TW','TJ','TZ','TH','TL','TG','TO','TT','TN','TR',
  'TM','TV','UG','UA','AE','GB','US','UY','UZ','VU','VA','VE','VN','YE','ZM','ZW',
]);

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function validateDonorInput(donor) {
  const errors = [];
  if (typeof donor !== 'object' || donor === null) {
    return { errors: ['Donor information is required.'] };
  }

  const firstName = typeof donor.firstName === 'string' ? donor.firstName.trim() : '';
  const lastName = typeof donor.lastName === 'string' ? donor.lastName.trim() : '';
  const email = typeof donor.email === 'string' ? donor.email.trim() : '';
  const addressLine1 = typeof donor.addressLine1 === 'string' ? donor.addressLine1.trim() : '';
  const addressLine2 = typeof donor.addressLine2 === 'string' ? donor.addressLine2.trim() : '';
  const country = typeof donor.country === 'string' ? donor.country.trim().toUpperCase() : '';
  const isUS = country === 'US';
  // City and State are only collected (and only required) for US addresses
  // — matches the frontend, which hides those fields for every other country.
  const city = isUS && typeof donor.city === 'string' ? donor.city.trim() : '';
  const state = isUS && typeof donor.state === 'string' ? donor.state.trim() : '';
  const postalCode = typeof donor.postalCode === 'string' ? donor.postalCode.trim() : '';
  const onBehalfOfOrg = donor.onBehalfOfOrg === true;
  const organization = typeof donor.organization === 'string' ? donor.organization.trim() : '';
  const anonymous = donor.anonymous === true;
  const includeSpouse = donor.includeSpouse === true;
  const spouseName = typeof donor.spouseName === 'string' ? donor.spouseName.trim() : '';

  // Cap every free-text field's length — cheap defense against someone
  // stuffing megabytes of text into a name/address field.
  const MAX_LEN = 200;
  const fields = { firstName, lastName, addressLine1, addressLine2, city, postalCode, organization, spouseName };
  for (const [key, val] of Object.entries(fields)) {
    if (val.length > MAX_LEN) errors.push(`${key} is too long.`);
  }

  if (firstName.length === 0) errors.push('First name is required.');
  if (lastName.length === 0) errors.push('Last name is required.');
  if (!EMAIL_RE.test(email)) errors.push('A valid email address is required.');
  if (addressLine1.length === 0) errors.push('Street address is required.');
  if (postalCode.length === 0) errors.push('Postal code is required.');
  if (!VALID_COUNTRIES.has(country)) errors.push('A valid country is required.');
  if (isUS) {
    if (city.length === 0) errors.push('City is required.');
    if (state.length === 0) errors.push('State/Province is required.');
  }
  if (onBehalfOfOrg && organization.length === 0) {
    errors.push('Organization name is required.');
  }

  return {
    errors,
    firstName, lastName, email,
    onBehalfOfOrg, organization,
    addressLine1, addressLine2, city, state, postalCode, country,
    anonymous, includeSpouse, spouseName,
  };
}

const checkoutLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests. Please wait a moment and try again.' },
});

function validateDonationInput(body) {
  const errors = [];

  const rawAmount = body.amount;
  const amount = typeof rawAmount === 'number' ? rawAmount : NaN;

  if (!Number.isFinite(amount)) {
    errors.push('Amount must be a valid number.');
  } else if (amount < MIN_AMOUNT_USD) {
    errors.push(`Amount must be at least $${MIN_AMOUNT_USD}.`);
  } else if (amount > MAX_AMOUNT_USD) {
    errors.push(`Amount must be no more than $${MAX_AMOUNT_USD.toLocaleString()}.`);
  } else if (Math.round(amount * 100) !== amount * 100) {
    errors.push('Amount cannot have more than 2 decimal places.');
  }

  const recurring = body.recurring;
  if (typeof recurring !== 'boolean') {
    errors.push('Recurring flag must be true or false.');
  }

  const fund = body.fund;
  if (typeof fund !== 'string' || !VALID_FUNDS.has(fund)) {
    errors.push('Fund selection is invalid.');
  }

  return { errors, amount, recurring, fund };
}

app.post('/create-checkout-session', checkoutLimiter, async (req, res) => {
  const { errors, amount, recurring, fund } = validateDonationInput(req.body);
  const donorResult = validateDonorInput(req.body.donor);

  const allErrors = [...errors, ...donorResult.errors];
  if (allErrors.length > 0) {
    return res.status(400).json({ error: allErrors[0] });
  }

  const {
    firstName, lastName, email,
    onBehalfOfOrg, organization,
    addressLine1, addressLine2, city, state, postalCode, country,
    anonymous, includeSpouse, spouseName,
  } = donorResult;

  const fullName = onBehalfOfOrg && organization ? organization : `${firstName} ${lastName}`;
  const unitAmount = Math.round(amount * 100);

  // Per docs.stripe.com/api/idempotent_requests: an idempotency key lets you
  // safely retry this request (e.g. the browser retries after a dropped
  // connection) without Stripe creating a second, duplicate Checkout
  // Session/charge. Generate a fresh key per logical donation attempt —
  // don't reuse one key across genuinely different requests.
  const idempotencyKey = crypto.randomUUID();

  try {
    // We already collected the full billing address ourselves via the
    // "My Information" form, so create the Customer object directly rather
    // than asking Stripe's hosted page to collect it again.
    const customer = await stripe.customers.create({
      name: fullName,
      email,
      address: {
        line1: addressLine1,
        line2: addressLine2 || undefined,
        city,
        state: state || undefined,
        postal_code: postalCode,
        country,
      },
      metadata: {
        first_name: firstName,
        last_name: lastName,
        organization: onBehalfOfOrg ? organization : '',
        spouse_name: includeSpouse ? spouseName : '',
      },
    });

    const session = await stripe.checkout.sessions.create(
      {
        payment_method_types: ['card'],
        // Per docs.stripe.com/payments/payment-method-configurations:
        // "Checkout supports Apple Pay and Google Pay with no integration
        // changes" — the 'card' payment method type above already renders
        // both wallets automatically for eligible browsers/devices. This
        // works because Checkout redirects to Stripe's own hosted page
        // (checkout.stripe.com), so the domain-registration requirement
        // that applies to *embedded* Elements/Checkout integrations does
        // not apply here.
        //
        // Two things to know:
        // 1. Apple Pay is enabled by default; Google Pay is NOT — toggle
        //    it on in Dashboard → Settings → Payment methods.
        // 2. Stripe never renders either wallet for India-based IPs or
        //    India-based Stripe accounts, regardless of configuration —
        //    don't mistake that for a bug while testing.
        mode: recurring ? 'subscription' : 'payment',
        customer: customer.id,
        line_items: [
          {
            price_data: {
              currency: 'usd',
              product_data: {
                name: recurring ? 'Monthly donation' : 'One-time donation',
                // product_data.metadata is the only place line-item-level
                // metadata is accepted by Checkout Sessions — a plain
                // metadata key on the line item itself is rejected by
                // the API with a parameter_unknown error.
                metadata: { fund },
              },
              unit_amount: unitAmount,
              ...(recurring ? { recurring: { interval: 'month' } } : {}),
            },
            quantity: 1,
          },
        ],
        metadata: {
          fund,
          recurring: String(recurring),
          anonymous: String(anonymous),
          spouse_name: includeSpouse ? spouseName : '',
        },
        // We already collected the address ourselves — 'auto' lets Stripe
        // skip re-asking unless a specific payment method requires more.
        billing_address_collection: 'auto',
        success_url: `${process.env.APP_URL}/success`,
        cancel_url: `${process.env.APP_URL}/cancel`,
      },
      { idempotencyKey }
    );

    // Store the donor profile immediately — we already have it in full,
    // no need to wait for the webhook the way we do for payment status.
    await db.upsertDonorProfile({
      stripeCustomerId: customer.id,
      email,
      name: fullName,
      organization: onBehalfOfOrg ? organization : null,
      spouseName: includeSpouse ? spouseName : null,
      addressLine1,
      addressLine2,
      city,
      state,
      postalCode,
      country,
    });

    // Record the donation as "pending" immediately, before the donor even
    // reaches Stripe's payment page. The webhook above flips it to
    // "completed" once payment actually succeeds. This means abandoned
    // checkouts show up as pending rather than vanishing entirely.
    await db.createPendingDonation({
      checkoutSessionId: session.id,
      fund,
      amountCents: unitAmount,
      currency: 'usd',
      recurring,
      isAnonymous: anonymous,
    });

    res.json({ url: session.url });
  } catch (err) {
    // Stripe's Node SDK throws typed errors (docs.stripe.com/error-handling).
    // Branch on err.type to react appropriately and avoid leaking internals.
    switch (err.type) {
      case 'StripeCardError':
        // Won't normally happen at Checkout Session creation time (card
        // isn't collected yet), but handled defensively.
        res.status(402).json({ error: 'Your card was declined.' });
        break;
      case 'StripeInvalidRequestError':
        console.error('Invalid request to Stripe:', err.message);
        res.status(400).json({ error: 'Invalid donation request.' });
        break;
      case 'StripeAPIError':
      case 'StripeConnectionError':
        console.error('Stripe API/connection error:', err.message);
        res.status(502).json({ error: 'Payment provider is temporarily unavailable. Please try again.' });
        break;
      case 'StripeAuthenticationError':
        console.error('Stripe authentication failed — check STRIPE_SECRET_KEY:', err.message);
        res.status(500).json({ error: 'Could not start checkout. Please try again.' });
        break;
      case 'StripeRateLimitError':
        console.error('Hit Stripe rate limit:', err.message);
        res.status(429).json({ error: 'Too many requests. Please try again shortly.' });
        break;
      default:
        console.error('Unexpected error creating checkout session:', err);
        res.status(500).json({ error: 'Could not start checkout. Please try again.' });
    }
  }
});

const PORT = process.env.PORT || 4242;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));