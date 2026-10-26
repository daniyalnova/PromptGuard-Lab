export const outbox = [];   // dev/test visibility only
export async function sendMail({ to, subject, text }) {
  outbox.push({ to, subject, text }); if (outbox.length > 50) outbox.shift();
  if (process.env.SMTP_URL) { const nm = (await import('nodemailer')).default; await nm.createTransport(process.env.SMTP_URL).sendMail({ from: process.env.MAIL_FROM || 'PromptGuard Lab <no-reply@localhost>', to, subject, text }); }
  else console.log(`[mail:dev] to=${to} subject="${subject}"\n${text}`);
}
