export default async function handler(req, res) {
    // Only accept POST requests from Supabase
    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method Not Allowed' });
    }

    try {
        // Supabase sends the newly inserted row inside req.body.record
        const newRecord = req.body.record;
        if (!newRecord) return res.status(400).json({ error: 'No record data found' });

        const botToken = process.env.TELEGRAM_BOT_TOKEN;
        const chatId = process.env.TELEGRAM_ADMIN_CHAT_ID;

        if (!botToken || !chatId) {
            console.error("Missing Telegram environment variables.");
            return res.status(500).json({ error: 'Server configuration error' });
        }

        // Check if this is a Chat Room or a standard Payload (handles both tables!)
        const isRoom = newRecord.room_name !== undefined;
        const title = isRoom ? "👥 New Chat Room Created" : "📦 New Secret Payload Created";
        const linkId = newRecord.custom_alias || newRecord.id;
        const linkBase = isRoom ? "https://zerokey.vercel.app/chat#" : "https://zerokey.vercel.app/#";

        // Format a beautiful Markdown message for Telegram
        const message = `
🚨 *${title}* 🚨

*ID:* \`${newRecord.id}\`
*Protected:* ${newRecord.is_protected ? 'Yes 🔒' : 'No 🔓'}
*Created At:* ${new Date(newRecord.created_at).toUTCString()}

🔗 *Direct Link:*
${linkBase}${linkId}
`;

        // Blast it to the Telegram API
        const response = await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                chat_id: chatId,
                text: message,
                parse_mode: 'Markdown'
            })
        });

        if (!response.ok) {
            throw new Error(`Telegram API responded with ${response.status}`);
        }

        return res.status(200).json({ success: true, message: "Alert sent to admin." });

    } catch (error) {
        console.error("Telegram Alert Error:", error);
        return res.status(500).json({ error: 'Internal Server Error' });
    }
}
