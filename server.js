const express = require('express');
require('dotenv').config();
const path = require('node:path');
const crypto = require('node:crypto');
const multer = require('multer');
const AdmZip = require('adm-zip');
const mongoose = require('mongoose');

const app = express();
const PORT = Number(process.env.PORT) || 8080;
const PUBLIC_DIR = path.join(__dirname, 'public');
const PUBLIC_IMAGE_DIR = path.join(PUBLIC_DIR, 'images');
const MONGODB_URI = [process.env.MONGODB_URI, process.env.MONGODB_ATLAS_URI]
  .map((uri) => typeof uri === 'string' ? uri.trim() : '')
  .find(Boolean);
const MASTER_PASSWORD = 'cat123123';
const DEFAULT_USERNAME = 'Admin';
const DEFAULT_PASSWORD = 'admin@123#';
const DEFAULT_PRODUCT = 'SiyanoAV Total Security';
const TICKET_STATUSES = ['Open', 'In Progress', 'Resolved', 'Closed'];
const TICKET_SEVERITIES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
const SUPPORTED_PRODUCTS = [
  DEFAULT_PRODUCT,
  'Sentinel AVPro',
  'Sentinel Endpoint Protection',
  'Mobile Security',
  'Endpoint Protection',
  'Cloud Shield',
];
const PASSWORD_HASH_BYTES = 64;
const MAX_FILE_SIZE = 10 * 1024 * 1024;
const MAX_FILES_PER_NOTE = 8;
const MAX_TOTAL_ATTACHMENT_SIZE = 12 * 1024 * 1024;
const MAX_BACKUP_SIZE = 250 * 1024 * 1024;
const MAX_BACKUP_CONTENT_SIZE = 500 * 1024 * 1024;
const MAX_BACKUP_ENTRIES = 5000;
let databaseReady = false;
let mongoInitialized = false;

const MIME_EXTENSIONS = new Map([
  ['image/png', '.png'],
  ['image/jpeg', '.jpg'],
  ['image/webp', '.webp'],
  ['application/pdf', '.pdf'],
  ['audio/webm', '.webm'],
  ['audio/ogg', '.ogg'],
  ['audio/mp4', '.m4a'],
  ['audio/mpeg', '.mp3'],
  ['audio/wav', '.wav'],
  ['audio/x-wav', '.wav'],
]);
const EXTENSION_MIMES = new Map([...MIME_EXTENSIONS].map(([mime, extension]) => [extension, mime]));

const ticketAttachmentSchema = new mongoose.Schema({
  fileName: { type: String, required: true },
  name: { type: String, required: true },
  contentType: { type: String, required: true },
  data: { type: Buffer, required: true },
  size: { type: Number, required: true },
}, { _id: false });
const activityLogSchema = new mongoose.Schema({
  action: { type: String, required: true },
  statusFrom: String,
  statusTo: String,
  titleFrom: String,
  titleTo: String,
  message: String,
  commentRole: String,
  performedBy: { type: String, required: true },
  timestamp: { type: Date, required: true },
}, { _id: false });
const ticketCommentSchema = new mongoose.Schema({
  author: { type: String, required: true },
  role: { type: String, enum: ['Developer', 'SiyanoAV Team', 'Auditor'], required: true },
  text: { type: String, required: true },
  attachments: { type: [ticketAttachmentSchema], default: [] },
  createdAt: { type: Date, default: Date.now },
});
const ticketSchema = new mongoose.Schema({
  _id: { type: String, required: true },
  title: { type: String, required: true },
  description: { type: String, required: true },
  status: String,
  severity: String,
  riskRating: String,
  product: String,
  activityLog: { type: [activityLogSchema], default: [] },
  comments: { type: [ticketCommentSchema], default: [] },
  attachments: { type: [ticketAttachmentSchema], default: [] },
}, {
  strict: false,
  versionKey: false,
  collection: 'tickets',
});
const Ticket = mongoose.models.Ticket || mongoose.model('Ticket', ticketSchema);
const noteSchema = new mongoose.Schema({
  _id: { type: String, required: true },
  ticketId: { type: String, required: true, index: true },
  text: { type: String, required: true },
  attachments: { type: [{
    fileName: { type: String, required: true },
    name: { type: String, required: true },
    mimeType: { type: String, required: true },
    size: { type: Number, required: true },
  }], default: [] },
  createdAt: { type: Date, required: true },
  updatedAt: { type: Date, required: true },
  author: { type: String, required: true },
  updatedBy: String,
}, { versionKey: false, collection: 'notes' });
const Note = mongoose.models.Note || mongoose.model('Note', noteSchema);
const userSchema = new mongoose.Schema({
  username: { type: String, required: true },
  usernameNormalized: { type: String, required: true, unique: true },
  role: { type: String, required: true },
  salt: { type: String, required: true },
  passwordHash: { type: String, required: true },
  createdAt: { type: Date, required: true },
}, { versionKey: false, collection: 'users' });
const User = mongoose.models.User || mongoose.model('User', userSchema);
const appMetadataSchema = new mongoose.Schema({
  _id: { type: String, required: true },
  value: { type: Buffer, required: true },
}, { versionKey: false, collection: 'app_metadata' });
const AppMetadata = mongoose.models.AppMetadata || mongoose.model('AppMetadata', appMetadataSchema);
let authSecret;

mongoose.connection.on('disconnected', () => {
  databaseReady = false;
  console.error('MongoDB disconnected; database-backed API requests will return HTTP 503 until the connection is restored.');
});
mongoose.connection.on('connected', () => {
  if (mongoInitialized) databaseReady = true;
});

function createTicketId(existingTickets) {
  let id;
  do {
    id = `TCK-${crypto.randomBytes(2).toString('hex').toUpperCase()}`;
  } while (existingTickets.some((ticket) => ticket.id === id));
  return id;
}

function normalizeTicketProducts(tickets) {
  let changed = false;
  const normalizedTickets = tickets.map((ticket) => {
    if (!ticket || typeof ticket !== 'object' || Array.isArray(ticket)) {
      const error = new Error('Ticket data must contain objects.');
      error.status = 400;
      throw error;
    }
    if (ticket.product === undefined || ticket.product === null || ticket.product === '') {
      changed = true;
      return { ...ticket, product: DEFAULT_PRODUCT };
    }
    if (!SUPPORTED_PRODUCTS.includes(ticket.product)) {
      const error = new Error(`Unsupported ticket product: ${ticket.product}`);
      error.status = 400;
      throw error;
    }
    return ticket;
  });
  return { tickets: normalizedTickets, changed };
}

function normalizeTicketActivityLogs(tickets) {
  let changed = false;
  const normalizedTickets = tickets.map((ticket) => {
    if (ticket.activityLog === undefined) {
      changed = true;
      return { ...ticket, activityLog: [] };
    }
    if (!Array.isArray(ticket.activityLog)) {
      const error = new Error('Ticket activity logs must contain arrays.');
      error.status = 400;
      throw error;
    }
    for (const event of ticket.activityLog) {
      if (!event || typeof event !== 'object' || Array.isArray(event)
        || !['status_changed', 'severity_changed', 'product_changed', 'title_changed', 'comment_added'].includes(event.action)
        || (event.action === 'title_changed'
          ? (typeof event.titleFrom !== 'string' || typeof event.titleTo !== 'string')
          : ((event.statusFrom !== null && typeof event.statusFrom !== 'string')
            || (event.statusTo !== null && typeof event.statusTo !== 'string')))
        || (event.action === 'comment_added'
          && !['Developer', 'SiyanoAV Team', 'Auditor'].includes(event.commentRole))
        || typeof event.performedBy !== 'string' || !event.performedBy.trim()
        || typeof event.timestamp !== 'string' || !Number.isFinite(Date.parse(event.timestamp))) {
        const error = new Error('Ticket activity log contains an invalid event.');
        error.status = 400;
        throw error;
      }
    }
    return ticket;
  });
  return { tickets: normalizedTickets, changed };
}

function appendTicketActivity(ticket, action, statusFrom, statusTo, performedBy, timestamp) {
  if (!Array.isArray(ticket.activityLog)) ticket.activityLog = [];
  ticket.activityLog.push({ action, statusFrom, statusTo, performedBy, timestamp });
}

function canonicalTicketStatus(value) {
  if (typeof value !== 'string') return null;
  return TICKET_STATUSES.find((status) => normalizedTicketStatus(status) === normalizedTicketStatus(value)) || null;
}

function canonicalTicketSeverity(value) {
  if (typeof value !== 'string') return null;
  const severity = value.trim().toLocaleUpperCase();
  return TICKET_SEVERITIES.includes(severity) ? severity : null;
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  return {
    salt,
    passwordHash: crypto.scryptSync(password, salt, PASSWORD_HASH_BYTES).toString('hex'),
  };
}

function passwordMatches(password, user) {
  if (typeof password !== 'string' || !user || typeof user.passwordHash !== 'string') return false;
  const supplied = crypto.scryptSync(password, user.salt, PASSWORD_HASH_BYTES);
  const expected = Buffer.from(user.passwordHash, 'hex');
  return supplied.length === expected.length && crypto.timingSafeEqual(supplied, expected);
}

function masterPasswordMatches(password) {
  if (typeof password !== 'string') return false;
  const supplied = Buffer.from(password);
  const expected = Buffer.from(MASTER_PASSWORD);
  return supplied.length === expected.length && crypto.timingSafeEqual(supplied, expected);
}

function newDefaultUser() {
  return {
    username: DEFAULT_USERNAME,
    usernameNormalized: DEFAULT_USERNAME.toLowerCase(),
    role: 'admin',
    ...hashPassword(DEFAULT_PASSWORD),
    createdAt: new Date(),
  };
}

function toMongoTicket(ticket) {
  const { id, _id, ...fields } = ticket;
  return { ...fields, _id: id || _id };
}

function toApiTicket(document) {
  const ticket = document.toObject ? document.toObject() : document;
  const { _id, __v, ...fields } = ticket;
  delete fields.attachments;
  if (Array.isArray(fields.comments)) fields.comments = fields.comments.map(toApiComment);
  return {
    ...fields,
    id: String(_id),
    activityLog: (fields.activityLog || []).map((event) => ({
      ...event,
      timestamp: new Date(event.timestamp).toISOString(),
    })),
  };
}

function toApiComment(comment) {
  return {
    id: String(comment._id),
    author: comment.author,
    role: comment.role,
    text: comment.text,
    createdAt: new Date(comment.createdAt).toISOString(),
  };
}

async function getTickets() {
  const documents = await Ticket.find({}).lean();
  return documents.map(toApiTicket);
}

async function initializeMongo() {
  if (!MONGODB_URI) {
    throw new Error('MONGODB_URI is missing. Set it to a MongoDB connection string.');
  }
  if (!/^mongodb(?:\+srv)?:\/\/(?:[^@/?#]+@)?[^/?#]+(?:[/?#].*)?$/i.test(MONGODB_URI)) {
    throw new Error('MONGODB_URI must be a valid mongodb:// or mongodb+srv:// connection string.');
  }
  if (mongoose.connection.readyState !== 1) {
    await mongoose.connect(MONGODB_URI, {
      serverSelectionTimeoutMS: 10000,
      connectTimeoutMS: 10000,
      socketTimeoutMS: 45000,
      family: 4,
    });
  }
  console.log('Connected to MongoDB successfully');
  for (const Model of [Ticket, Note]) {
    try {
      await Model.createCollection();
    } catch (error) {
      if (error.code !== 48) throw error;
    }
  }
  await User.updateOne(
    { usernameNormalized: DEFAULT_USERNAME.toLowerCase() },
    { $setOnInsert: newDefaultUser() },
    { upsert: true },
  );
  const metadata = await AppMetadata.findOneAndUpdate(
    { _id: 'auth-secret' },
    { $setOnInsert: { value: crypto.randomBytes(48) } },
    { upsert: true, new: true },
  ).lean();
  authSecret = Buffer.from(metadata.value);
  if (authSecret.length < 32) throw new Error('The stored auth-secret is invalid.');
  mongoInitialized = true;
  databaseReady = true;
}

function normalizedTicketStatus(value) {
  return String(value || '').trim().toLocaleLowerCase().replace(/\s+/g, ' ');
}

function queryValues(value) {
  const values = Array.isArray(value) ? value : [value];
  return values
    .filter((entry) => typeof entry === 'string')
    .flatMap((entry) => entry.split(','))
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function filterTickets(tickets, query) {
  const search = queryValues(query.search).join(' ').toLocaleLowerCase();
  const severity = queryValues(query.severity)[0]?.toLocaleLowerCase();
  const status = queryValues(query.status)[0]?.toLocaleLowerCase();
  const product = queryValues(query.product)[0]?.toLocaleLowerCase();
  const tags = queryValues(query.tag).map((tag) => tag.replace(/^#/, '').toLocaleLowerCase());

  return tickets.filter((ticket) => {
    if (search) {
      const searchableText = [ticket.title, ticket.description, ticket.author]
        .filter((value) => typeof value === 'string')
        .join(' ')
        .toLocaleLowerCase();
      if (!searchableText.includes(search)) return false;
    }
    if (severity && severity !== 'all') {
      const ticketSeverity = String(ticket.severity || ticket.riskRating || '').toLocaleLowerCase();
      if (ticketSeverity !== severity) return false;
    }
    if (status && status !== 'all') {
      if (normalizedTicketStatus(ticket.status) !== normalizedTicketStatus(status)) return false;
    }
    if (product && product !== 'all') {
      if (String(ticket.product || '').toLocaleLowerCase() !== product) return false;
    }
    if (tags.length) {
      const ticketTags = Array.isArray(ticket.tags)
        ? ticket.tags.map((tag) => String(tag).replace(/^#/, '').toLocaleLowerCase())
        : [];
      if (!tags.every((tag) => ticketTags.includes(tag))) return false;
    }
    return true;
  });
}

async function getNotes() {
  return Note.find({}).lean();
}

function toApiNote(note) {
  const { _id, __v, ...fields } = note;
  return {
    ...fields,
    id: String(_id || note.id),
    createdAt: new Date(note.createdAt).toISOString(),
    updatedAt: new Date(note.updatedAt).toISOString(),
    attachments: (fields.attachments || []).map((attachment) => {
      const fileName = typeof attachment.fileName === 'string'
        ? attachment.fileName
        : path.basename(attachment.url || '');
      return {
        ...attachment,
        ...(fileName ? { url: `/api/files/${encodeURIComponent(fileName)}` } : {}),
      };
    }),
  };
}

function signToken(username) {
  const payload = Buffer.from(JSON.stringify({ username })).toString('base64url');
  const signature = crypto.createHmac('sha256', authSecret).update(payload).digest('base64url');
  return `${payload}.${signature}`;
}

async function verifyToken(token) {
  if (typeof token !== 'string') return null;
  const [payload, signature, extra] = token.split('.');
  if (!payload || !signature || extra) return null;
  const expected = crypto.createHmac('sha256', authSecret).update(payload).digest();
  let supplied;
  try {
    supplied = Buffer.from(signature, 'base64url');
  } catch {
    return null;
  }
  if (expected.length !== supplied.length || !crypto.timingSafeEqual(expected, supplied)) return null;
  try {
    const claims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    return await User.findOne({ username: claims.username }).lean();
  } catch {
    return null;
  }
}

async function requireAuthentication(req, res, next) {
  const authorization = req.get('authorization') || '';
  const match = authorization.match(/^Bearer ([^\s]+)$/);
  try {
    const user = match ? await verifyToken(match[1]) : null;
    if (!user) return res.status(401).json({ error: 'Please sign in to continue.' });
    req.user = { username: user.username, role: user.role || 'auditor' };
    return next();
  } catch (error) {
    return next(error);
  }
}

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_FILE_SIZE, files: MAX_FILES_PER_NOTE, fields: 2, fieldSize: 12000 },
  fileFilter(req, file, callback) {
    const mimeType = file.mimetype.toLowerCase().split(';', 1)[0];
    if (!MIME_EXTENSIONS.has(mimeType)) {
      const error = new Error('Only PNG, JPG, WEBP, PDF, and supported audio files are allowed.');
      error.status = 400;
      return callback(error);
    }
    file.normalizedMimeType = mimeType;
    return callback(null, true);
  },
});

const backupUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_BACKUP_SIZE, files: 1, fields: 1, fieldSize: 1000 },
  fileFilter(req, file, callback) {
    if (path.extname(file.originalname).toLowerCase() !== '.zip') {
      const error = new Error('Select a ZIP backup file.');
      error.status = 400;
      return callback(error);
    }
    return callback(null, true);
  },
});

function receiveNoteUploads(req, res, next) {
  upload.array('attachments', MAX_FILES_PER_NOTE)(req, res, (error) => {
    if (error) {
      req.noteUploadError = error;
      req.files = req.files || [];
    }
    return next();
  });
}

function parseBackupArchive(archiveData) {
  let zip;
  let entries;
  try {
    zip = new AdmZip(archiveData);
    entries = zip.getEntries();
  } catch {
    const error = new Error('The uploaded file is not a valid ZIP backup.');
    error.status = 400;
    throw error;
  }

  if (entries.length > MAX_BACKUP_ENTRIES) {
    const error = new Error('The backup contains too many entries.');
    error.status = 400;
    throw error;
  }
  let totalSize = 0;
  const uploadFiles = [];
  const uploadSizes = new Map();
  const availableUploads = new Set();
  const normalizedUploadNames = new Set();
  const seenEntries = new Set();
  let tickets;
  let notes;
  for (const entry of entries) {
    if (entry.entryName.includes('\\') || entry.entryName.startsWith('/') || seenEntries.has(entry.entryName)) {
      const error = new Error('The backup contains an unsafe or duplicate path.');
      error.status = 400;
      throw error;
    }
    seenEntries.add(entry.entryName);
    if (entry.isDirectory) {
      if (!['data/', 'public/', 'public/uploads/'].includes(entry.entryName)) {
        const error = new Error('The backup contains an unexpected directory.');
        error.status = 400;
        throw error;
      }
      continue;
    }
    const entrySize = entry.header.size;
    if (!Number.isSafeInteger(entrySize) || entrySize < 0 || entrySize > MAX_BACKUP_CONTENT_SIZE) {
      const error = new Error('The backup contains an invalid or oversized file.');
      error.status = 400;
      throw error;
    }
    totalSize += entrySize;
    if (totalSize > MAX_BACKUP_CONTENT_SIZE) {
      const error = new Error('The uncompressed backup exceeds the allowed size.');
      error.status = 400;
      throw error;
    }
    if (entry.entryName === 'data/tickets.json' || entry.entryName === 'data/notes.json') {
      if (entrySize > 20 * 1024 * 1024) {
        const error = new Error('The backup JSON file is too large.');
        error.status = 400;
        throw error;
      }
      let parsed;
      try {
        parsed = JSON.parse(entry.getData().toString('utf8'));
      } catch {
        const error = new Error(`The backup entry ${entry.entryName} is not valid JSON.`);
        error.status = 400;
        throw error;
      }
      if (!Array.isArray(parsed)) {
        const error = new Error(`${entry.entryName} must contain a JSON array.`);
        error.status = 400;
        throw error;
      }
      if (entry.entryName === 'data/tickets.json') tickets = parsed;
      else notes = parsed;
      continue;
    }

    const uploadPrefix = 'public/uploads/';
    const fileName = entry.entryName.startsWith(uploadPrefix)
      ? entry.entryName.slice(uploadPrefix.length)
      : '';
    if (!fileName || fileName.length > 255 || fileName === '.' || fileName === '..'
      || /[\\/\x00-\x1f<>:"|?*]/.test(fileName) || /[. ]$/.test(fileName)) {
      const error = new Error('The backup contains an unexpected or unsafe file path.');
      error.status = 400;
      throw error;
    }
    const normalizedFileName = fileName.toLowerCase();
    if (normalizedUploadNames.has(normalizedFileName)) {
      const error = new Error('The backup contains duplicate attachment files.');
      error.status = 400;
      throw error;
    }
    normalizedUploadNames.add(normalizedFileName);
    availableUploads.add(fileName);
    try {
      uploadFiles.push({ fileName, data: entry.getData() });
      uploadSizes.set(fileName, entrySize);
    } catch {
      const error = new Error('The backup contains an unreadable attachment.');
      error.status = 400;
      throw error;
    }
  }

  if (!tickets || !notes) {
    const error = new Error('The ZIP must contain data/tickets.json and data/notes.json.');
    error.status = 400;
    throw error;
  }
  const normalizedProducts = normalizeTicketProducts(tickets);
  const normalizedTickets = normalizeTicketActivityLogs(normalizedProducts.tickets);
  const ticketIds = new Set();
  for (const ticket of normalizedTickets.tickets) {
    if (!ticket || typeof ticket !== 'object' || Array.isArray(ticket)
      || typeof ticket.id !== 'string' || typeof ticket.title !== 'string'
      || typeof ticket.description !== 'string' || ticketIds.has(ticket.id)) {
      const error = new Error('The backup contains invalid or duplicate ticket data.');
      error.status = 400;
      throw error;
    }
    ticketIds.add(ticket.id);
  }
  const noteIds = new Set();
  const ticketUploadNames = new Map();
  const ticketUploadSizes = new Map();
  for (const note of notes) {
    if (!note || typeof note !== 'object' || Array.isArray(note)
      || typeof note.id !== 'string' || noteIds.has(note.id)
      || typeof note.ticketId !== 'string' || !ticketIds.has(note.ticketId)
      || typeof note.text !== 'string'
      || (note.attachments !== undefined && !Array.isArray(note.attachments))) {
      const error = new Error('The backup contains invalid note data.');
      error.status = 400;
      throw error;
    }
    noteIds.add(note.id);
    for (const attachment of note.attachments || []) {
      const fileName = attachment && attachment.fileName;
      if (typeof fileName !== 'string' || !/^[\da-f-]{36}\.[a-z0-9]+$/i.test(fileName)
        || !EXTENSION_MIMES.has(path.extname(fileName).toLowerCase())
        || !availableUploads.has(fileName) || typeof attachment.mimeType !== 'string'
        || EXTENSION_MIMES.get(path.extname(fileName).toLowerCase()) !== attachment.mimeType) {
        const error = new Error('The backup references a missing or invalid attachment.');
        error.status = 400;
        throw error;
      }
      if (!ticketUploadNames.has(note.ticketId)) ticketUploadNames.set(note.ticketId, new Set());
      if (!ticketUploadNames.get(note.ticketId).has(fileName)) {
        ticketUploadNames.get(note.ticketId).add(fileName);
        const totalSize = (ticketUploadSizes.get(note.ticketId) || 0) + uploadSizes.get(fileName);
        if (totalSize > MAX_TOTAL_ATTACHMENT_SIZE) {
          const error = new Error('The backup contains more than 12 MB of attachments for one ticket.');
          error.status = 400;
          throw error;
        }
        ticketUploadSizes.set(note.ticketId, totalSize);
      }
    }
  }
  return { tickets: normalizedTickets.tickets, notes, uploadFiles };
}

async function persistUploadedFiles(filesToSave, ticketId) {
  const attachments = filesToSave.map((file) => {
    const contentType = file.normalizedMimeType || file.mimetype.toLowerCase().split(';', 1)[0];
    const extension = MIME_EXTENSIONS.get(contentType);
    if (!extension) {
      const error = new Error('Unsupported attachment type.');
      error.status = 400;
      throw error;
    }
    const fileName = `${crypto.randomUUID()}${extension}`;
    return {
      fileName,
      name: path.basename(file.originalname || fileName).slice(0, 200),
      contentType,
      data: file.buffer,
      size: file.size,
    };
  });
  const ticket = await Ticket.findById(ticketId).select('attachments.size').lean();
  if (!ticket) {
    const error = new Error('Ticket not found.');
    error.status = 404;
    throw error;
  }
  const existingSize = (ticket.attachments || []).reduce((total, attachment) => total + attachment.size, 0);
  const uploadedSize = attachments.reduce((total, attachment) => total + attachment.size, 0);
  if (existingSize + uploadedSize > MAX_TOTAL_ATTACHMENT_SIZE) {
    const error = new Error('A ticket cannot contain more than 12 MB of attachments.');
    error.status = 413;
    throw error;
  }
  if (attachments.length) {
    const update = await Ticket.updateOne({ _id: ticketId }, {
      $push: { attachments: { $each: attachments } },
    });
    if (!update.matchedCount) {
      const error = new Error('Ticket not found.');
      error.status = 404;
      throw error;
    }
  }
  return attachments.map(({ fileName, name, contentType, size }) => ({
    fileName,
    name,
    mimeType: contentType,
    size,
  }));
}

async function removeAttachmentFiles(notes) {
  const filesByTicket = new Map();
  for (const note of notes) {
    for (const attachment of note.attachments || []) {
      if (typeof note.ticketId !== 'string' || typeof attachment.fileName !== 'string') continue;
      if (!filesByTicket.has(note.ticketId)) filesByTicket.set(note.ticketId, []);
      filesByTicket.get(note.ticketId).push(attachment.fileName);
    }
  }
  await Promise.all([...filesByTicket].map(([ticketId, fileNames]) =>
    Ticket.updateOne({ _id: ticketId }, {
      $pull: { attachments: { fileName: { $in: fileNames } } },
    })));
}

function masterPasswordFromRequest(req) {
  return req.get('x-master-password') || req.body?.masterAuthorizationPassword || req.body?.masterPassword;
}

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: false, limit: '50mb' }));
app.use('/images', express.static(PUBLIC_IMAGE_DIR, { index: false, fallthrough: false }));
app.use('/api', (req, res, next) => {
  if (!databaseReady || mongoose.connection.readyState !== 1) {
    return res.status(503).json({ error: 'Database is temporarily unavailable. Please try again shortly.' });
  }
  return next();
});

app.post('/api/auth/login', async (req, res, next) => {
  try {
    const { username, password } = req.body || {};
    if (typeof username !== 'string' || typeof password !== 'string') {
      return res.status(400).json({ error: 'Username and password are required.' });
    }
    const user = await User.findOne({ usernameNormalized: username.trim().toLowerCase() }).lean();
    if (!passwordMatches(password, user)) return res.status(401).json({ error: 'Incorrect username or password.' });
    return res.json({ token: signToken(user.username), user: { username: user.username } });
  } catch (error) {
    return next(error);
  }
});

app.post('/api/auth/add-user', async (req, res, next) => {
  try {
    const {
      username,
      newUsername = username,
      password,
      newPassword = password,
      masterAuthorizationPassword,
      masterPassword,
    } = req.body || {};
    if (!masterPasswordMatches(masterAuthorizationPassword || masterPassword)) {
      return res.status(403).json({ error: 'Invalid Master Authorization Password.' });
    }
    if (typeof newPassword !== 'string' || newPassword.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters long.' });
    }
    if (newPassword.length > 200) {
      return res.status(400).json({ error: 'Password must be at most 200 characters long.' });
    }
    if (typeof newUsername !== 'string' || !/^[A-Za-z0-9_.-]{2,40}$/.test(newUsername.trim())) {
      return res.status(400).json({ error: 'Username must be 2–40 letters, numbers, dots, dashes, or underscores.' });
    }
    const usernameNormalized = newUsername.trim().toLowerCase();
    if (await User.exists({ usernameNormalized })) {
      return res.status(409).json({ error: 'That username already exists.' });
    }
    const user = {
      username: newUsername.trim(),
      usernameNormalized,
      role: 'auditor',
      ...hashPassword(newPassword),
      createdAt: new Date(),
    };
    await User.create(user);
    return res.status(201).json({ username: user.username });
  } catch (error) {
    if (error.code === 11000) return res.status(409).json({ error: 'That username already exists.' });
    return next(error);
  }
});

app.post('/api/auth/reset', async (req, res, next) => {
  if (!masterPasswordMatches(masterPasswordFromRequest(req))) {
    return res.status(403).json({ error: 'Invalid Master Authorization Password.' });
  }
  try {
    const defaultAdmin = await User.findOne({ usernameNormalized: DEFAULT_USERNAME.toLowerCase() }).lean();
    if (!defaultAdmin || !passwordMatches(DEFAULT_PASSWORD, defaultAdmin)) {
      throw new Error('Protected default administrator account is missing or invalid.');
    }
    authSecret = crypto.randomBytes(48);
    await User.deleteMany({ usernameNormalized: { $ne: DEFAULT_USERNAME.toLowerCase() } });
    await AppMetadata.updateOne(
      { _id: 'auth-secret' },
      { $set: { value: authSecret } },
      { upsert: true },
    );
    return res.json({ message: 'User accounts reset to the default administrator.' });
  } catch (error) {
    return next(error);
  }
});

app.use('/api', requireAuthentication);

app.get('/api/auth/me', (req, res) => res.json({ user: req.user }));

app.get('/api/products', (req, res) => res.json(SUPPORTED_PRODUCTS));

app.get('/api/backup/export', async (req, res, next) => {
  try {
    const zip = new AdmZip();
    zip.addFile('data/tickets.json', Buffer.from(`${JSON.stringify(await getTickets(), null, 2)}\n`));
    const notes = (await getNotes()).map(toApiNote);
    zip.addFile('data/notes.json', Buffer.from(`${JSON.stringify(notes, null, 2)}\n`));
    const tickets = await Ticket.find({}).select('attachments');
    for (const ticket of tickets) {
      for (const attachment of ticket.attachments || []) {
        zip.addFile(`public/uploads/${attachment.fileName}`, Buffer.from(attachment.data));
      }
    }
    const filename = `sentinel-backup-${new Date().toISOString().slice(0, 10)}.zip`;
    res.attachment(filename);
    res.type('application/zip');
    return res.send(zip.toBuffer());
  } catch (error) {
    return next(error);
  }
});

app.post('/api/backup/import', backupUpload.single('backupFile'), async (req, res, next) => {
  try {
    if (!req.file) {
      const error = new Error('Select a ZIP backup file to import.');
      error.status = 400;
      throw error;
    }
    if (!masterPasswordMatches(req.body?.masterPassword)) {
      return res.status(401).json({ error: 'Incorrect Master Password. Access Denied.' });
    }

    const { tickets, notes, uploadFiles } = parseBackupArchive(req.file.buffer);
    const uploadsByName = new Map(uploadFiles.map((file) => [file.fileName, file.data]));
    const ticketAttachments = new Map();
    for (const note of notes) {
      if (!ticketAttachments.has(note.ticketId)) ticketAttachments.set(note.ticketId, []);
      for (const attachment of note.attachments || []) {
        const data = uploadsByName.get(attachment.fileName);
        if (!data) continue;
        ticketAttachments.get(note.ticketId).push({
          fileName: attachment.fileName,
          name: attachment.name || attachment.fileName,
          contentType: attachment.mimeType,
          data,
          size: data.length,
        });
      }
    }
    const ticketsWithAttachments = tickets.map((ticket) => ({
      ...ticket,
      attachments: ticketAttachments.get(ticket.id) || [],
    }));
    const session = await mongoose.startSession();
    try {
      await session.withTransaction(async () => {
        await Ticket.deleteMany({}, { session });
        if (ticketsWithAttachments.length) {
          await Ticket.insertMany(ticketsWithAttachments.map(toMongoTicket), { session });
        }
        await Note.deleteMany({}, { session });
        if (notes.length) {
          await Note.insertMany(notes.map((note) => ({
            ...note,
            _id: note.id,
            createdAt: new Date(note.createdAt),
            updatedAt: new Date(note.updatedAt || note.createdAt),
          })), { session });
        }
      });
    } catch (error) {
      throw error;
    } finally {
      await session.endSession();
    }
    return res.json({ message: 'Backup imported successfully.' });
  } catch (error) {
    return next(error);
  } finally {
    req.file = undefined;
  }
});

app.get('/api/tickets', async (req, res, next) => {
  try {
    return res.json(filterTickets(await getTickets(), req.query));
  } catch (error) {
    return next(error);
  }
});

app.get('/api/reports/summary', async (req, res, next) => {
  try {
    const tickets = filterTickets(await getTickets(), req.query);
    const ticketIds = new Set(tickets.map((ticket) => ticket.id));
    const notes = (await getNotes())
      .filter((note) => ticketIds.has(note.ticketId))
      .map(toApiNote);
    const notesByTicket = new Map();
    for (const note of notes) {
      if (!notesByTicket.has(note.ticketId)) notesByTicket.set(note.ticketId, []);
      notesByTicket.get(note.ticketId).push(note);
    }

    const statusCounts = { open: 0, inProgress: 0, resolved: 0, closed: 0 };
    const severityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const ticket of tickets) {
      const status = normalizedTicketStatus(ticket.status || 'Open');
      if (status === 'open') statusCounts.open += 1;
      else if (status === 'in progress') statusCounts.inProgress += 1;
      else if (status === 'resolved') statusCounts.resolved += 1;
      else if (status === 'closed') statusCounts.closed += 1;

      const severity = String(ticket.severity || ticket.riskRating || '').toLocaleLowerCase();
      if (Object.hasOwn(severityCounts, severity)) severityCounts[severity] += 1;
    }

    return res.json({
      generatedAt: new Date().toISOString(),
      summary: {
        totalConcerns: tickets.length,
        ...statusCounts,
        ...severityCounts,
        evidenceNotes: notes.length,
      },
      tickets: tickets.map((ticket) => ({
        ...ticket,
        notes: notesByTicket.get(ticket.id) || [],
      })),
    });
  } catch (error) {
    return next(error);
  }
});

app.post('/api/tickets', async (req, res, next) => {
  try {
    const {
      title,
      description,
      product = DEFAULT_PRODUCT,
      severity,
      tags = [],
    } = req.body || {};
    if (typeof title !== 'string' || !title.trim() || title.length > 200) {
      return res.status(400).json({ error: 'Title of Issue is required and must be at most 200 characters.' });
    }
    if (typeof description !== 'string' || !description.trim() || description.length > 10000) {
      return res.status(400).json({ error: 'Description is required and must be at most 10,000 characters.' });
    }
    if (typeof product !== 'string' || !SUPPORTED_PRODUCTS.includes(product)) {
      return res.status(400).json({ error: 'Select a supported product category.' });
    }
    const normalizedSeverity = severity === undefined || severity === null || severity === ''
      ? null
      : canonicalTicketSeverity(severity);
    if (severity !== undefined && severity !== null && severity !== '' && !normalizedSeverity) {
      return res.status(400).json({ error: 'Select a supported ticket severity.' });
    }
    if (!Array.isArray(tags) || tags.length > 12 || tags.some((tag) => (
      typeof tag !== 'string'
      || !tag.trim().replace(/^#/, '').trim()
      || tag.trim().replace(/^#/, '').trim().length > 30
    ))) {
      return res.status(400).json({ error: 'Tags must be a list of at most 12 names, each at most 30 characters.' });
    }
    const seenTags = new Set();
    const normalizedTags = tags.reduce((normalized, tag) => {
      const value = tag.trim().replace(/^#/, '').trim();
      const key = value.toLocaleLowerCase();
      if (!seenTags.has(key)) {
        seenTags.add(key);
        normalized.push(value);
      }
      return normalized;
    }, []);
    const tickets = await getTickets();
    const createdAt = new Date().toISOString();
    const ticket = {
      id: createTicketId(tickets),
      product,
      title: title.trim(),
      description: description.trim(),
      tags: normalizedTags,
      status: 'Open',
      ...(normalizedSeverity ? { severity: normalizedSeverity, riskRating: normalizedSeverity } : {}),
      createdAt,
      author: req.user.username,
      activityLog: [],
    };
    appendTicketActivity(ticket, 'status_changed', null, ticket.status, req.user.username, createdAt);
    appendTicketActivity(ticket, 'product_changed', null, ticket.product, req.user.username, createdAt);
    if (normalizedSeverity) {
      appendTicketActivity(ticket, 'severity_changed', null, normalizedSeverity, req.user.username, createdAt);
    }
    const createdTicket = await Ticket.create(toMongoTicket(ticket));
    return res.status(201).json(toApiTicket(createdTicket));
  } catch (error) {
    return next(error);
  }
});

async function updateTicket(req, res, next) {
  try {
    const updates = req.body;
    if (!updates || typeof updates !== 'object' || Array.isArray(updates)) {
      return res.status(400).json({ error: 'Provide ticket fields to update.' });
    }
    const allowedFields = new Set(['title', 'status', 'severity', 'product']);
    const fields = Object.keys(updates);
    if (!fields.length || fields.some((field) => !allowedFields.has(field))) {
      return res.status(400).json({ error: 'Only title, status, severity, and product category can be updated.' });
    }
    const document = await Ticket.findById(req.params.id).lean();
    if (!document) return res.status(404).json({ error: 'Ticket not found.' });
    const ticket = toApiTicket(document);

    const timestamp = new Date().toISOString();
    const updatesToSet = {};
    const activityEvents = [];
    const recordActivity = (action, statusFrom, statusTo) => {
      activityEvents.push({
        action,
        statusFrom,
        statusTo,
        performedBy: req.user.username,
        timestamp: new Date(timestamp),
      });
    };
    if (Object.hasOwn(updates, 'title')) {
      if (typeof updates.title !== 'string' || !updates.title.trim() || updates.title.trim().length > 200) {
        return res.status(400).json({ error: 'Ticket title must be between 1 and 200 characters.' });
      }
      const nextTitle = updates.title.trim();
      if (ticket.title !== nextTitle) {
        activityEvents.push({
          action: 'title_changed',
          titleFrom: ticket.title,
          titleTo: nextTitle,
          performedBy: req.user.username,
          timestamp: new Date(timestamp),
        });
        updatesToSet.title = nextTitle;
      }
    }
    if (Object.hasOwn(updates, 'status')) {
      const nextStatus = canonicalTicketStatus(updates.status);
      if (!nextStatus) {
        return res.status(400).json({ error: `Status must be one of: ${TICKET_STATUSES.join(', ')}.` });
      }
      const currentStatus = ticket.status || 'Open';
      if (normalizedTicketStatus(currentStatus) !== normalizedTicketStatus(nextStatus)) {
        recordActivity('status_changed', currentStatus, nextStatus);
        updatesToSet.status = nextStatus;
      }
    }
    if (Object.hasOwn(updates, 'severity')) {
      const nextSeverity = updates.severity === null || updates.severity === ''
        ? null
        : canonicalTicketSeverity(updates.severity);
      if (updates.severity !== null && updates.severity !== '' && !nextSeverity) {
        return res.status(400).json({ error: `Severity must be one of: ${TICKET_SEVERITIES.join(', ')}.` });
      }
      const currentSeverity = ticket.severity || ticket.riskRating || null;
      if (currentSeverity !== nextSeverity) {
        recordActivity('severity_changed', currentSeverity, nextSeverity);
        if (nextSeverity) {
          updatesToSet.severity = nextSeverity;
          updatesToSet.riskRating = nextSeverity;
        } else {
          updatesToSet.severity = null;
          updatesToSet.riskRating = null;
        }
      }
    }
    if (Object.hasOwn(updates, 'product')) {
      if (typeof updates.product !== 'string' || !SUPPORTED_PRODUCTS.includes(updates.product)) {
        return res.status(400).json({ error: 'Select a supported product category.' });
      }
      if (ticket.product !== updates.product) {
        recordActivity('product_changed', ticket.product || null, updates.product);
        updatesToSet.product = updates.product;
      }
    }
    if (!activityEvents.length && !Object.keys(updatesToSet).length) return res.json(ticket);
    const mongoUpdate = {};
    if (Object.keys(updatesToSet).length) mongoUpdate.$set = updatesToSet;
    if (activityEvents.length) mongoUpdate.$push = { activityLog: { $each: activityEvents } };
    const updatedDocument = await Ticket.findByIdAndUpdate(req.params.id, mongoUpdate, {
      new: true,
      runValidators: true,
    }).lean();
    if (!updatedDocument) return res.status(404).json({ error: 'Ticket not found.' });
    return res.json(toApiTicket(updatedDocument));
  } catch (error) {
    return next(error);
  }
}

app.patch('/api/tickets/:id', updateTicket);
app.put('/api/tickets/:id', updateTicket);

app.get('/api/tickets/:id/comments', async (req, res, next) => {
  try {
    const ticket = await Ticket.findById(req.params.id).select('comments').lean();
    if (!ticket) return res.status(404).json({ error: 'Ticket not found.' });
    return res.json((ticket.comments || []).map(toApiComment));
  } catch (error) {
    return next(error);
  }
});

app.post('/api/tickets/:id/comments', async (req, res, next) => {
  try {
    const { role, text } = req.body || {};
    if (!['Developer', 'SiyanoAV Team', 'Auditor'].includes(role)) {
      return res.status(400).json({ error: 'Select Developer, SiyanoAV Team, or Auditor as the comment role.' });
    }
    if (typeof text !== 'string' || !text.trim() || text.length > 10000) {
      return res.status(400).json({ error: 'Comment text must be between 1 and 10,000 characters.' });
    }
    const createdAt = new Date();
    const comment = {
      _id: new mongoose.Types.ObjectId(),
      author: req.user.username,
      role,
      text: text.trim(),
      createdAt,
    };
    const activity = {
      action: 'comment_added',
      statusFrom: null,
      statusTo: null,
      message: `${role} comment added by ${req.user.username}`,
      commentRole: role,
      performedBy: req.user.username,
      timestamp: createdAt,
    };
    const updatedTicket = await Ticket.findByIdAndUpdate(req.params.id, {
      $push: {
        comments: comment,
        activityLog: activity,
      },
    }, {
      new: true,
      runValidators: true,
    }).select('comments').lean();
    if (!updatedTicket) return res.status(404).json({ error: 'Ticket not found.' });
    const savedComment = updatedTicket.comments.find((entry) => String(entry._id) === String(comment._id));
    return res.status(201).json(toApiComment(savedComment));
  } catch (error) {
    return next(error);
  }
});

function getBulkTicketIds(value) {
  if (!Array.isArray(value) || !value.length || value.length > 500
    || value.some((id) => typeof id !== 'string' || !id.trim())) {
    const error = new Error('Provide between 1 and 500 valid ticket IDs.');
    error.status = 400;
    throw error;
  }
  return [...new Set(value.map((id) => id.trim()))];
}

app.post('/api/tickets/bulk-update', async (req, res, next) => {
  try {
    const { ids, status, severity } = req.body || {};
    const hasStatus = Object.hasOwn(req.body || {}, 'status');
    const hasSeverity = Object.hasOwn(req.body || {}, 'severity');
    if (hasStatus === hasSeverity || Object.keys(req.body || {}).some((key) => !['ids', 'status', 'severity'].includes(key))) {
      return res.status(400).json({ error: 'Provide ticket IDs and exactly one of status or severity.' });
    }
    const ticketIds = getBulkTicketIds(ids);
    const nextValue = hasStatus ? canonicalTicketStatus(status) : canonicalTicketSeverity(severity);
    if (!nextValue) {
      const field = hasStatus ? 'Status' : 'Severity';
      const values = hasStatus ? TICKET_STATUSES : TICKET_SEVERITIES;
      return res.status(400).json({ error: `${field} must be one of: ${values.join(', ')}.` });
    }

    const documents = await Ticket.find({ _id: { $in: ticketIds } }).lean();
    if (documents.length !== ticketIds.length) {
      return res.status(404).json({ error: 'One or more selected tickets were not found.' });
    }
    const timestamp = new Date();
    const action = hasStatus ? 'bulk_status_changed' : 'bulk_severity_changed';
    const operations = documents.flatMap((document) => {
      const currentValue = hasStatus
        ? (document.status || 'Open')
        : (document.severity || document.riskRating || null);
      const changed = hasStatus
        ? normalizedTicketStatus(currentValue) !== normalizedTicketStatus(nextValue)
        : currentValue !== nextValue;
      if (!changed) return [];

      const set = hasStatus
        ? { status: nextValue }
        : { severity: nextValue, riskRating: nextValue };
      return [{
        updateOne: {
          filter: { _id: document._id },
          update: {
            $set: set,
            $push: {
              activityLog: {
                action,
                statusFrom: currentValue,
                statusTo: nextValue,
                performedBy: req.user.username,
                timestamp,
              },
            },
          },
        },
      }];
    });
    if (operations.length) await Ticket.bulkWrite(operations);
    const updatedDocuments = await Ticket.find({ _id: { $in: ticketIds } }).lean();
    return res.json({
      updatedCount: operations.length,
      tickets: updatedDocuments.map(toApiTicket),
    });
  } catch (error) {
    return next(error);
  }
});

app.post('/api/tickets/bulk-delete', async (req, res, next) => {
  if (!masterPasswordMatches(masterPasswordFromRequest(req))) {
    return res.status(403).json({ error: 'Incorrect Master Password. Access Denied.' });
  }
  try {
    const ticketIds = getBulkTicketIds(req.body?.ids);
    const documents = await Ticket.find({ _id: { $in: ticketIds } }).lean();
    if (documents.length !== ticketIds.length) {
      return res.status(404).json({ error: 'One or more selected tickets were not found.' });
    }

    const session = await mongoose.startSession();
    try {
      await session.withTransaction(async () => {
        await Ticket.deleteMany({ _id: { $in: ticketIds } }, { session });
        await Note.deleteMany({ ticketId: { $in: ticketIds } }, { session });
      });
    } finally {
      await session.endSession();
    }
    return res.json({ deletedCount: documents.length });
  } catch (error) {
    return next(error);
  }
});

app.delete('/api/tickets/:id', async (req, res, next) => {
  if (!masterPasswordMatches(masterPasswordFromRequest(req))) {
    return res.status(403).json({ error: 'Incorrect Master Password. Access Denied.' });
  }
  try {
    const ticketDocument = await Ticket.findById(req.params.id).lean();
    if (!ticketDocument) return res.status(404).json({ error: 'Ticket not found.' });
    const ticket = toApiTicket(ticketDocument);
    const session = await mongoose.startSession();
    try {
      await session.withTransaction(async () => {
        await Ticket.findByIdAndDelete(ticket.id, { session });
        await Note.deleteMany({ ticketId: ticket.id }, { session });
      });
    } finally {
      await session.endSession();
    }
    return res.status(204).end();
  } catch (error) {
    return next(error);
  }
});

app.get('/api/notes/counts', async (req, res, next) => {
  try {
    const counts = {};
    for (const note of await getNotes()) {
      counts[note.ticketId] = (counts[note.ticketId] || 0) + 1;
    }
    return res.json(counts);
  } catch (error) {
    return next(error);
  }
});

app.get('/api/notes/:ticketId', async (req, res, next) => {
  try {
    if (!(await Ticket.exists({ _id: req.params.ticketId }))) {
      return res.status(404).json({ error: 'Ticket not found.' });
    }
    return res.json((await getNotes())
      .filter((note) => note.ticketId === req.params.ticketId)
      .map(toApiNote));
  } catch (error) {
    return next(error);
  }
});

app.post('/api/notes', receiveNoteUploads, async (req, res, next) => {
  try {
    const { ticketId } = req.body || {};
    const { text = '' } = req.body || {};
    if (typeof ticketId !== 'string' || !ticketId.trim() || !(await Ticket.exists({ _id: ticketId }))) {
      return res.status(400).json({ error: 'Select a valid ticket before adding a note.' });
    }
    if (typeof text !== 'string' || text.length > 10000) {
      return res.status(400).json({ error: 'Note text must be at most 10,000 characters.' });
    }
    if (!text.trim() && !(req.files || []).length) {
      const error = req.noteUploadError;
      if (error) return res.status(error.status || 400).json({ error: error.message });
      return res.status(400).json({ error: 'Add note text or at least one attachment.' });
    }
    const note = {
      id: crypto.randomUUID(),
      ticketId,
      text: text.trim(),
      attachments: [],
      createdAt: new Date(),
      updatedAt: new Date(),
      author: req.user.username,
    };
    await Note.create({ ...note, _id: note.id });
    let attachmentError = req.noteUploadError;
    if (!attachmentError && (req.files || []).length) {
      try {
        note.attachments = await persistUploadedFiles(req.files, ticketId);
        await Note.updateOne({ _id: note.id }, { $set: { attachments: note.attachments } });
      } catch (error) {
        attachmentError = error;
        if (note.attachments.length) {
          try {
            await removeAttachmentFiles([note]);
          } catch (cleanupError) {
            console.error(`Unable to remove attachments from a note after attachment persistence failed: ${cleanupError.message}`);
          }
          note.attachments = [];
        }
      }
    }
    return res.status(201).json({
      ...toApiNote(note),
      ...(attachmentError ? { attachmentError: attachmentError.message } : {}),
    });
  } catch (error) {
    return next(error);
  }
});

app.put('/api/notes/:id', async (req, res, next) => {
  try {
    const { text } = req.body || {};
    if (typeof text !== 'string' || text.length > 10000) {
      return res.status(400).json({ error: 'Note text must be a string of at most 10,000 characters.' });
    }
    const note = await Note.findById(req.params.id).lean();
    if (!note) return res.status(404).json({ error: 'Note not found.' });
    const updatedNote = await Note.findByIdAndUpdate(req.params.id, {
      $set: { text: text.trim(), updatedAt: new Date(), updatedBy: req.user.username },
    }, { new: true }).lean();
    return res.json(toApiNote(updatedNote));
  } catch (error) {
    return next(error);
  }
});

app.delete('/api/notes/:id', async (req, res, next) => {
  if (!masterPasswordMatches(masterPasswordFromRequest(req))) {
    return res.status(403).json({ error: 'Incorrect Master Password. Access Denied.' });
  }
  try {
    const note = await Note.findById(req.params.id).lean();
    if (!note) return res.status(404).json({ error: 'Note not found.' });
    await Note.deleteOne({ _id: note._id });
    await removeAttachmentFiles([note]);
    return res.status(204).end();
  } catch (error) {
    return next(error);
  }
});

async function getStoredFile(req, res, next) {
  try {
    const fileName = req.params.fileId || req.params.fileName;
    if (!/^[\da-f-]{36}\.[a-z0-9]+$/i.test(fileName)) {
      return res.status(404).json({ error: 'Attachment not found.' });
    }
    const extension = path.extname(fileName).toLowerCase();
    if (!EXTENSION_MIMES.has(extension)) {
      return res.status(404).json({ error: 'Attachment not found.' });
    }
    const ticket = await Ticket.findOne({ 'attachments.fileName': fileName })
      .select({ 'attachments.$': 1 });
    const attachment = ticket?.attachments?.[0];
    if (!attachment) return res.status(404).json({ error: 'Attachment not found.' });
    if (!attachment || !attachment.data) return res.status(404).json({ error: 'Attachment not found.' });
    const contentType = EXTENSION_MIMES.get(extension);
    let data;
    if (Buffer.isBuffer(attachment.data)) {
      data = attachment.data;
    } else if (attachment.data instanceof Uint8Array) {
      data = Buffer.from(attachment.data);
    } else if (attachment.data?.buffer instanceof Uint8Array) {
      data = Buffer.from(attachment.data.buffer).subarray(0, attachment.data.position || attachment.data.buffer.length);
    } else {
      return res.status(404).json({ error: 'Attachment not found.' });
    }
    return res.type(contentType).set({
      'Content-Disposition': 'inline',
      'X-Content-Type-Options': 'nosniff',
      'Cache-Control': 'private, no-store',
    }).send(data);
  } catch (error) {
    return next(error);
  }
}

app.get('/api/files/:fileId', getStoredFile);
app.get('/api/uploads/:fileName', getStoredFile);

app.get('/api/gallery', async (req, res, next) => {
  try {
    const gallery = (await getNotes()).flatMap((note) =>
      (note.attachments || [])
        .filter((attachment) => attachment.mimeType.startsWith('image/'))
        .map((attachment) => ({
          ...attachment,
          apiPath: `/api/files/${encodeURIComponent(attachment.fileName)}`,
          ticketId: note.ticketId,
          createdAt: note.createdAt,
          text: note.text,
        })),
    );
    return res.json(gallery);
  } catch (error) {
    return next(error);
  }
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'dashboard.html')));

app.use((error, req, res, next) => {
  if (res.headersSent) return next(error);
  if (error instanceof multer.MulterError) {
    const status = error.code === 'LIMIT_FILE_SIZE' ? 413 : 400;
    if (req.path.startsWith('/api/backup/')) {
      return res.status(status).json({
        error: error.code === 'LIMIT_FILE_SIZE'
          ? 'The backup ZIP must be 250 MB or smaller.'
          : 'Backup upload limit exceeded.',
      });
    }
    return res.status(status).json({
      error: error.code === 'LIMIT_FILE_SIZE'
        ? 'Each attachment must be 10 MB or smaller.'
        : 'Attachment upload limit exceeded.',
    });
  }
  const status = Number.isInteger(error.status) ? error.status : 500;
  if (status >= 500) console.error(error);
  return res.status(status).json({ error: status >= 500 ? 'An internal server error occurred.' : error.message });
});

async function startServer() {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`SiyanoAV audit dashboard listening on 0.0.0.0:${PORT}`);
  });

  if (!MONGODB_URI) {
    console.error('MongoDB configuration error: MONGODB_URI is missing. Set it to a MongoDB connection string.');
    return;
  }
  if (!/^mongodb(?:\+srv)?:\/\/(?:[^@/?#]+@)?[^/?#]+(?:[/?#].*)?$/i.test(MONGODB_URI)) {
    console.error('MongoDB configuration error: MONGODB_URI must be a valid mongodb:// or mongodb+srv:// connection string.');
    return;
  }

  let attempt = 1;
  let retryDelay = 5000;
  while (!databaseReady) {
    try {
      await initializeMongo();
      return;
    } catch (error) {
      console.error(`Unable to connect to MongoDB at startup (attempt ${attempt}): ${error.message}`);
      console.error('The HTTP server remains available; MongoDB-backed API requests will return HTTP 503 while the database is unavailable.');
      if (/querySrv.*ECONNREFUSED/i.test(error.message) && /^mongodb\+srv:\/\//i.test(MONGODB_URI)) {
        console.error('This runtime cannot resolve the MongoDB SRV record. Configure MONGODB_URI with the standard mongodb:// seed-list URI from Atlas instead.');
      }
      await new Promise((resolve) => setTimeout(resolve, retryDelay));
      retryDelay = Math.min(retryDelay * 2, 60000);
      attempt += 1;
    }
  }
}

startServer();
