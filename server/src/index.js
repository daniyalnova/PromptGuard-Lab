import mongoose from 'mongoose'; import { createApp } from './app.js'; import { mongoStore } from './store.js'; import { startQueue } from './queue.js';
if (process.env.NODE_ENV === 'production' && (process.env.JWT_SECRET || '').length < 32) { console.error('JWT_SECRET (min 32 chars) is required in production'); process.exit(1); }
await mongoose.connect(process.env.MONGO_URL || 'mongodb://localhost:27017/promptguard');
startQueue(); createApp({ store: await mongoStore() }).listen(3000, () => console.log('API :3000'));
