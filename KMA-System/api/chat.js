export default async function handler(req, res) {
    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    const { message } = req.body;

    try {
        const response = await fetch('https://openai.com', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${process.env.OPENAI_API_KEY}`
            },
            body: JSON.stringify({
                model: 'gpt-4o-mini',
                messages: [
                    { role: 'system', content: 'أنت مساعد ذكي مدمج داخل نظام KMA الإداري، أجب باختصار واحترافية.' },
                    { role: 'user', content: message }
                ]
            })
        });

        const data = await response.json();
        const reply = data.choices.message.content;
        return res.status(200).json({ reply });
    } catch (error) {
        return res.status(500).json({ error: 'فشل الاتصال بخادم الذكاء الاصطناعي' });
    }
}
