const RATE_LIMIT_WINDOW_MS = Number.parseInt(process.env.RATE_LIMIT_WINDOW_MS || '', 10) || 60_000;
const RATE_LIMIT_MAX = Number.parseInt(process.env.RATE_LIMIT_MAX || '', 10) || 5;
const MAX_MESSAGE_LENGTH = Number.parseInt(process.env.MAX_MESSAGE_LENGTH || '', 10) || 900;
const MAX_FIELD_LENGTH = Number.parseInt(process.env.MAX_FIELD_LENGTH || '', 10) || 500;

const rateLimiters = {
  user: new Map(),
  ip: new Map()
};

const ROLE_IDS = {
  application: ['1362838321570643998', '1362837635164541048'],
  business: ['1362839626632528204', '1362837867511939272'],
  nationalId: ['1362839743301157085', '1362838421575307485'],
  gunLicense: ['1362837557217333539', '1362839986424119458']
};

const ALLOWED_TOP_LEVEL_KEYS = new Set(['eventType', 'data', 'allowEveryone']);

const EVENT_DEFINITIONS = {
  application_submitted: {
    requiresAdmin: false,
    webhookEnv: ['DISCORD_WEBHOOK_URL'],
    roleIds: ROLE_IDS.application,
    allowedFields: new Set([
      'firstName',
      'lastName',
      'dob',
      'email',
      'discordUsername',
      'phone',
      'department',
      'positionTitle',
      'yearsExperience',
      'availability',
      'addressLine1',
      'resumeLink',
      'portfolioLink',
      'message',
      'certifyInfo',
      'consentBackgroundCheck',
      'referenceNumber',
      'applicationId',
      'submittedAt'
    ])
  },
  business_registration_submitted: {
    requiresAdmin: false,
    webhookEnv: ['DISCORD_WEBHOOK_BUSINESS_URL', 'DISCORD_WEBHOOK_URL'],
    roleIds: ROLE_IDS.business,
    allowedFields: new Set([
      'businessName',
      'businessAddress',
      'phoneNumber',
      'businessEmail',
      'mailingAddress',
      'city',
      'state',
      'ownershipType',
      'otherOwnership',
      'resaleTaxNo',
      'businessType',
      'industry',
      'responsiblePersonName',
      'responsiblePersonRole',
      'responsiblePersonPhone',
      'responsiblePersonEmail',
      'reasonForRegister',
      'registrationDocLink',
      'permitsDocLink',
      'applicantSignature',
      'certifyInfo',
      'referenceNumber',
      'applicationId',
      'submittedAt'
    ])
  },
  national_id_submitted: {
    requiresAdmin: false,
    webhookEnv: ['DISCORD_WEBHOOK_NATIONALID_URL', 'DISCORD_WEBHOOK_URL'],
    roleIds: ROLE_IDS.nationalId,
    allowedFields: new Set([
      'firstName',
      'lastName',
      'nationalIdNumber',
      'dob',
      'placeOfBirth',
      'email',
      'discordUsername',
      'phone',
      'addressLine1',
      'photoLink',
      'message',
      'referenceNumber',
      'applicationId',
      'submittedAt'
    ])
  },
  gun_license_submitted: {
    requiresAdmin: false,
    webhookEnv: ['DISCORD_WEBHOOK_GUNLICENSE_URL', 'DISCORD_WEBHOOK_URL'],
    roleIds: ROLE_IDS.gunLicense,
    allowedFields: new Set([
      'fullName',
      'dateOfBirth',
      'nationalIdNumber',
      'licenseType',
      'firearmExperience',
      'email',
      'phone',
      'reasonForApplication',
      'agreeSafetyRegulations',
      'referenceNumber',
      'applicationId',
      'submittedAt'
    ])
  },
  blog_post_published: {
    requiresAdmin: true,
    webhookEnv: ['DISCORD_WEBHOOK_BLOG_URL', 'DISCORD_WEBHOOK_AUDIT_URL', 'DISCORD_WEBHOOK_URL'],
    roleIds: [],
    allowedFields: new Set(['title', 'content', 'category', 'postId', 'origin'])
  },
  'admin/audit/log': {
    requiresAdmin: true,
    webhookEnv: ['DISCORD_WEBHOOK_AUDIT_URL', 'DISCORD_WEBHOOK_URL'],
    roleIds: [],
    allowedFields: new Set(['message', 'context', 'severity'])
  }
};

const parseJson = (value) => {
  if (!value) return null;
  if (typeof value === 'object') return value;
  try {
    return JSON.parse(value);
  } catch (err) {
    return null;
  }
};

const getHeader = (req, name) => {
  const headers = req?.headers || {};
  const target = name.toLowerCase();
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === target) {
      return headers[key];
    }
  }
  return null;
};

const isRateLimited = (store, key) => {
  if (!key) return false;
  const now = Date.now();
  const entries = store.get(key) || [];
  const filtered = entries.filter((ts) => now - ts < RATE_LIMIT_WINDOW_MS);
  if (filtered.length >= RATE_LIMIT_MAX) {
    store.set(key, filtered);
    return true;
  }
  filtered.push(now);
  store.set(key, filtered);
  return false;
};

const stripHtml = (value) => String(value ?? '').replace(/<[^>]*>/g, '');

const blockMentions = (value, allowEveryone) => {
  if (!value) return '';
  let text = String(value);
  text = text.replace(/<@&\\d+>/g, 'role');
  text = text.replace(/<@!?\\d+>/g, 'user');
  if (!allowEveryone) {
    text = text.replace(/@everyone/gi, 'everyone');
    text = text.replace(/@here/gi, 'here');
  }
  return text;
};

const truncate = (value, maxLength) => {
  const text = String(value ?? '');
  if (text.length <= maxLength) return text;
  return `${text.slice(0, Math.max(0, maxLength - 3))}...`;
};

const sanitizeText = (value, { maxLength = MAX_FIELD_LENGTH, allowEveryone = false, preserveNewlines = false } = {}) => {
  if (value === null || value === undefined) return null;
  let text = stripHtml(value);
  text = blockMentions(text, allowEveryone);
  text = text.replace(/\\u0000/g, '');
  if (!preserveNewlines) {
    text = text.replace(/\\s+/g, ' ');
  }
  text = text.trim();
  if (!text) return null;
  return truncate(text, maxLength);
};

const sanitizeUrl = (value) => {
  if (!value) return null;
  try {
    const url = new URL(String(value));
    if (!['http:', 'https:'].includes(url.protocol)) return null;
    return url.toString();
  } catch (err) {
    return null;
  }
};

const parseDate = (value) => {
  if (!value) return null;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  return date.toISOString();
};

const toYesNo = (value) => (value ? 'Yes' : 'No');

const formatField = (name, value, inline = true, maxLength = MAX_FIELD_LENGTH) => ({
  name,
  value: sanitizeText(value ?? 'Not provided', { maxLength, allowEveryone: false }) || 'Not provided',
  inline
});

const buildLinkFieldValue = (label, urlValue) => {
  const safeUrl = sanitizeUrl(urlValue);
  if (!safeUrl) return 'Not provided';
  return `[${label}](${safeUrl})`;
};

const buildApplicationPayload = (data) => {
  const submittedAt = parseDate(data.submittedAt) || new Date().toISOString();
  const fullName = `${data.firstName || ''} ${data.lastName || ''}`.trim();
  const fields = [
    formatField('Name', fullName || 'Not provided', true),
    formatField('DOB', data.dob, true),
    formatField('Email', data.email, true),
    formatField('Discord', data.discordUsername, true),
    formatField('Phone', data.phone, true),
    formatField('Department', data.department, true),
    formatField('Position', data.positionTitle, true),
    formatField('Years experience', data.yearsExperience, true),
    formatField('Availability', data.availability, true),
    formatField('Address', data.addressLine1, false),
    formatField('Resume', buildLinkFieldValue('Resume Link', data.resumeLink), false),
    formatField('Portfolio', buildLinkFieldValue('Portfolio Link', data.portfolioLink), false),
    formatField('Message', sanitizeText(data.message, { maxLength: MAX_MESSAGE_LENGTH }) || 'Not provided', false, MAX_MESSAGE_LENGTH),
    formatField('Certification', toYesNo(data.certifyInfo), true),
    formatField('Background Consent', toYesNo(data.consentBackgroundCheck), true),
    formatField('Reference Number', data.referenceNumber, true),
    formatField('Status', 'submitted', true),
    formatField('Application ID', data.applicationId, true),
    formatField('Submitted At', submittedAt, false)
  ];

  return {
    content: ROLE_IDS.application.map((id) => `<@&${id}>`).join(' '),
    embeds: [
      {
        title: 'New Application Received',
        description: 'A new application has been submitted to the Los Santos Government Portal.',
        color: 0x1f8b4c,
        fields,
        timestamp: submittedAt,
        footer: { text: 'Los Santos Government Portal' }
      }
    ],
    allowed_mentions: {
      roles: ROLE_IDS.application
    }
  };
};

const buildBusinessPayload = (data) => {
  const submittedAt = parseDate(data.submittedAt) || new Date().toISOString();
  const ownershipValue = data.ownershipType || (data.otherOwnership ? `Other: ${data.otherOwnership}` : null);
  const fields = [
    formatField('Business Name', data.businessName, true),
    formatField('Business Address', data.businessAddress, true),
    formatField('Phone', data.phoneNumber, true),
    formatField('Business Email', data.businessEmail, true),
    formatField('Mailing Address', data.mailingAddress, false),
    formatField('City', data.city, true),
    formatField('State', data.state, true),
    formatField('Ownership Type', ownershipValue, true),
    formatField('Resale Tax No', data.resaleTaxNo, true),
    formatField('Business Type', data.businessType, true),
    formatField('Industry', data.industry, true),
    formatField('Responsible Name', data.responsiblePersonName, true),
    formatField('Responsible Role', data.responsiblePersonRole, true),
    formatField('Responsible Phone', data.responsiblePersonPhone, true),
    formatField('Responsible Email', data.responsiblePersonEmail, true),
    formatField('Reason / Legality', data.reasonForRegister, false),
    formatField('Registration Link', buildLinkFieldValue('Registration', data.registrationDocLink), false),
    formatField('Permits Link', buildLinkFieldValue('Permits', data.permitsDocLink), false),
    formatField('Applicant Signature', data.applicantSignature, true),
    formatField('Certification', toYesNo(data.certifyInfo), true),
    formatField('Reference Number', data.referenceNumber, true),
    formatField('Status', 'submitted', true),
    formatField('Application ID', data.applicationId, true),
    formatField('Submitted At', submittedAt, false)
  ];

  return {
    content: ROLE_IDS.business.map((id) => `<@&${id}>`).join(' '),
    embeds: [
      {
        title: 'New Business Registration Submitted',
        description: 'A new business registration has been submitted to the Los Santos Government Portal.',
        color: 0x1f8b4c,
        fields,
        timestamp: submittedAt,
        footer: { text: 'Los Santos Government Portal' }
      }
    ],
    allowed_mentions: {
      roles: ROLE_IDS.business
    }
  };
};

const buildNationalIdPayload = (data) => {
  const submittedAt = parseDate(data.submittedAt) || new Date().toISOString();
  const fullName = `${data.firstName || ''} ${data.lastName || ''}`.trim();
  const fields = [
    formatField('Name', fullName || 'Not provided', true),
    formatField('National ID', data.nationalIdNumber, true),
    formatField('DOB', data.dob, true),
    formatField('Place of Birth', data.placeOfBirth, true),
    formatField('Email', data.email, true),
    formatField('Discord', data.discordUsername, true),
    formatField('Phone', data.phone, true),
    formatField('Address', data.addressLine1, false),
    formatField('Photo', buildLinkFieldValue('Photo Link', data.photoLink), false),
    formatField('Message', sanitizeText(data.message, { maxLength: MAX_MESSAGE_LENGTH }) || 'Not provided', false, MAX_MESSAGE_LENGTH),
    formatField('Reference Number', data.referenceNumber, true),
    formatField('Status', 'submitted', true),
    formatField('Application ID', data.applicationId, true),
    formatField('Submitted At', submittedAt, false)
  ];

  return {
    content: ROLE_IDS.nationalId.map((id) => `<@&${id}>`).join(' '),
    embeds: [
      {
        title: 'New National ID Application',
        description: 'A new national ID application has been submitted to the Los Santos Government Portal.',
        color: 0x1f8b4c,
        fields,
        timestamp: submittedAt,
        footer: { text: 'Los Santos Government Portal' }
      }
    ],
    allowed_mentions: {
      roles: ROLE_IDS.nationalId
    }
  };
};

const buildGunLicensePayload = (data) => {
  const submittedAt = parseDate(data.submittedAt) || new Date().toISOString();
  const fields = [
    formatField('Full Name', data.fullName, true),
    formatField('Date of Birth', data.dateOfBirth, true),
    formatField('National ID', data.nationalIdNumber, true),
    formatField('License Type', data.licenseType, true),
    formatField('Firearm Experience', data.firearmExperience, true),
    formatField('Email', data.email, true),
    formatField('Phone', data.phone, true),
    formatField('Reference Number', data.referenceNumber, true),
    formatField('Status', 'submitted', true),
    formatField('Reason for Application', sanitizeText(data.reasonForApplication, { maxLength: MAX_MESSAGE_LENGTH }) || 'Not provided', false, MAX_MESSAGE_LENGTH),
    formatField('Safety Agreement', toYesNo(data.agreeSafetyRegulations), true),
    formatField('Application ID', data.applicationId, true),
    formatField('Submitted At', submittedAt, false)
  ];

  return {
    content: ROLE_IDS.gunLicense.map((id) => `<@&${id}>`).join(' '),
    embeds: [
      {
        title: 'New Gun License Application',
        description: 'A new gun license application has been submitted to the Los Santos Government Portal.',
        color: 0x2f3136,
        fields,
        timestamp: submittedAt,
        footer: { text: 'Los Santos Government Portal' }
      }
    ],
    allowed_mentions: {
      roles: ROLE_IDS.gunLicense
    }
  };
};

const getCategoryHeadline = (category) => {
  const headlines = {
    Uncategorized: 'NEW PUBLICATION RELEASED',
    'Press Release': 'PRESS RELEASE ISSUED',
    Memorandum: 'MEMORANDUM PUBLISHED',
    Directive: 'DIRECTIVE ISSUED',
    Proclamation: 'PROCLAMATION DECLARED',
    'Executive Order': 'EXECUTIVE ORDER SIGNED',
    Regulation: 'REGULATION ENACTED',
    'Government Notice': 'GOVERNMENT NOTICE PUBLISHED',
    Advisory: 'OFFICIAL ADVISORY ISSUED',
    'Legal Notice': 'LEGAL NOTICE PUBLISHED',
    Act: 'NEW ACT ENACTED',
    Bill: 'BILL PROPOSED',
    'Government Announcement': 'GOVERNMENT ANNOUNCEMENT'
  };
  if (!category) return 'NEW PUBLICATION RELEASED';
  return headlines[category] || `NEW ${String(category).toUpperCase()} PUBLISHED`;
};

const processMarkdownForDiscord = (markdown, limit, allowEveryone) => {
  let processed = String(markdown || '');
  processed = stripHtml(processed);
  processed = blockMentions(processed, allowEveryone);
  processed = processed.replace(/^#{1,6}\s*(.+)$/gm, '**$1**');
  processed = processed.replace(/!\[([^\]]*)\]\(([^)]+)\)/g, 'Image: $1 ($2)');
  processed = processed.trim();

  if (processed.length > limit) {
    const truncated = processed.substring(0, limit);
    const lastParagraphBreak = truncated.lastIndexOf('\n\n');
    if (lastParagraphBreak > limit * 0.7) {
      processed = truncated.substring(0, lastParagraphBreak);
    } else {
      processed = truncated;
    }
  }

  return processed;
};

const buildBlogPayload = (data, allowEveryone) => {
  const headline = getCategoryHeadline(data.category);
  const publishDate = new Date().toLocaleDateString('en-US', {
    weekday: 'long',
    year: 'numeric',
    month: 'long',
    day: 'numeric'
  });

  const baseUrl = sanitizeUrl(process.env.PORTAL_BASE_URL) || sanitizeUrl(data.origin);
  const postUrl =
    baseUrl && data.postId ? new URL(`/post/${encodeURIComponent(data.postId)}`, baseUrl).toString() : null;

  const contentLimit = Math.max(200, MAX_MESSAGE_LENGTH - 320);
  const body = processMarkdownForDiscord(data.content || '', contentLimit, allowEveryone);

  let message = `# ${headline}\\n\\n${sanitizeText(data.title, { maxLength: 200 }) || 'Untitled'}\\n\\n${body}`;
  if (postUrl) {
    message += `\\n\\nRead the full article: ${postUrl}`;
  }
  message += `\\n\\nCategory: *${sanitizeText(data.category || 'General', { maxLength: 100 })}*`;
  message += `\\nPublished: *${publishDate}*`;

  if (allowEveryone) {
    message += '\\n\\n@everyone';
  }

  message = truncate(message, MAX_MESSAGE_LENGTH);

  return {
    content: message,
    allowed_mentions: allowEveryone ? { parse: ['everyone'] } : { parse: [] }
  };
};

const buildAuditPayload = (data) => {
  const message = sanitizeText(data.message, { maxLength: MAX_MESSAGE_LENGTH, preserveNewlines: true }) || 'Audit event';
  const context = sanitizeText(data.context, { maxLength: MAX_FIELD_LENGTH, preserveNewlines: true });
  const severity = sanitizeText(data.severity, { maxLength: 32 });
  const content = [severity ? `[${severity.toUpperCase()}]` : null, message, context].filter(Boolean).join(' ');
  return {
    content,
    allowed_mentions: { parse: [] }
  };
};

const getWebhookUrl = (definition) => {
  const envs = definition.webhookEnv || [];
  for (const key of envs) {
    const value = process.env[key];
    if (value) return value;
  }
  return null;
};

const buildDiscordPayload = (eventType, data, allowEveryone) => {
  switch (eventType) {
    case 'application_submitted':
      return buildApplicationPayload(data);
    case 'business_registration_submitted':
      return buildBusinessPayload(data);
    case 'national_id_submitted':
      return buildNationalIdPayload(data);
    case 'gun_license_submitted':
      return buildGunLicensePayload(data);
    case 'blog_post_published':
      return buildBlogPayload(data, allowEveryone);
    case 'admin/audit/log':
      return buildAuditPayload(data);
    default:
      return null;
  }
};

const hasAdminLabel = (user) => {
  const labels = Array.isArray(user?.labels) ? user.labels : [];
  return labels.includes('admin');
};

const fetchAccount = async (endpoint, project, jwt) => {
  const baseUrl = String(endpoint).replace(/\/+$/, '');
  const response = await fetch(`${baseUrl}/account`, {
    method: 'GET',
    headers: {
      'X-Appwrite-Project': project,
      'X-Appwrite-JWT': jwt
    }
  });

  if (!response.ok) {
    throw new Error('unauthenticated');
  }

  return response.json();
};

const authenticateUser = async (req) => {
  const endpoint = process.env.APPWRITE_ENDPOINT;
  const project = process.env.APPWRITE_PROJECT_ID;
  if (!endpoint || !project) {
    return { error: 'server_misconfigured' };
  }

  const jwt = getHeader(req, 'x-appwrite-user-jwt');
  if (!jwt) {
    return { error: 'unauthenticated' };
  }

  try {
    const user = await fetchAccount(endpoint, project, jwt);
    const headerUserId = getHeader(req, 'x-appwrite-user-id');
    if (headerUserId && user?.$id && headerUserId !== user.$id) {
      return { error: 'unauthenticated' };
    }
    return { user, isAdmin: hasAdminLabel(user) };
  } catch (err) {
    return { error: 'unauthenticated' };
  }
};

export default async ({ req, res, log, error }) => {
  const logger = log || console.log;
  const errLogger = error || console.error;

  if (req?.method && req.method.toUpperCase() !== 'POST') {
    return res.json({ ok: false, error: 'method_not_allowed' }, 405);
  }

  const payload = parseJson(req?.body);
  if (!payload || typeof payload !== 'object') {
    return res.json({ ok: false, error: 'invalid_payload' }, 400);
  }

  const topKeys = Object.keys(payload);
  const unexpectedTop = topKeys.filter((key) => !ALLOWED_TOP_LEVEL_KEYS.has(key));
  if (unexpectedTop.length) {
    return res.json({ ok: false, error: 'unexpected_fields' }, 400);
  }

  const eventType = payload.eventType;
  if (!eventType || typeof eventType !== 'string' || !EVENT_DEFINITIONS[eventType]) {
    return res.json({ ok: false, error: 'unsupported_event_type' }, 400);
  }

  const definition = EVENT_DEFINITIONS[eventType];
  const auth = await authenticateUser(req);
  if (auth.error === 'server_misconfigured') {
    errLogger('Missing APPWRITE_ENDPOINT or APPWRITE_PROJECT_ID.');
    return res.json({ ok: false, error: 'server_misconfigured' }, 500);
  }
  if (auth.error) {
    return res.json({ ok: false, error: 'unauthenticated' }, 401);
  }
  if (definition.requiresAdmin && !auth.isAdmin) {
    return res.json({ ok: false, error: 'forbidden' }, 403);
  }

  const ip =
    (getHeader(req, 'x-forwarded-for') || '').split(',')[0].trim() ||
    getHeader(req, 'x-real-ip') ||
    getHeader(req, 'cf-connecting-ip') ||
    getHeader(req, 'x-client-ip') ||
    '';

  if (isRateLimited(rateLimiters.user, auth.user?.$id) || isRateLimited(rateLimiters.ip, ip)) {
    return res.json({ ok: false, error: 'rate_limited' }, 429);
  }

  const data = payload.data;
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    return res.json({ ok: false, error: 'invalid_payload' }, 400);
  }

  const allowedFields = definition.allowedFields || new Set();
  const unexpectedFields = Object.keys(data).filter((key) => !allowedFields.has(key));
  if (unexpectedFields.length) {
    return res.json({ ok: false, error: 'unexpected_fields' }, 400);
  }

  const allowEveryone = Boolean(payload.allowEveryone) && auth.isAdmin;
  const webhookUrl = getWebhookUrl(definition);
  if (!webhookUrl) {
    errLogger(`Webhook not configured for ${eventType}.`);
    return res.json({ ok: false, error: 'webhook_not_configured' }, 500);
  }

  const discordPayload = buildDiscordPayload(eventType, data, allowEveryone);
  if (!discordPayload) {
    return res.json({ ok: false, error: 'unsupported_event_type' }, 400);
  }

  try {
    const response = await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(discordPayload)
    });

    if (!response.ok) {
      errLogger(`Webhook relay failed with status ${response.status}.`);
      return res.json({ ok: false, error: 'webhook_failed' }, 502);
    }
  } catch (err) {
    errLogger('Webhook relay failed.');
    return res.json({ ok: false, error: 'webhook_failed' }, 502);
  }

  logger(`Webhook relay delivered: ${eventType} by ${auth.user?.$id || 'unknown'}.`);
  return res.json({ ok: true });
};
