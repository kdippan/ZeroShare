export default async function handler(req, res) {
    if (req.method !== "GET") {
        return res.status(405).json({
            error: "Method not allowed"
        });
    }

    const meteredDomain = process.env.METERED_DOMAIN;
    const meteredApiKey = process.env.METERED_API_KEY;

    if (!meteredDomain || !meteredApiKey) {
        console.error("Missing Metered environment variables.");

        return res.status(500).json({
            error: "TURN service is not configured."
        });
    }

    try {
        const domain = meteredDomain
            .replace(/^https?:\/\//, "")
            .replace(/\/+$/, "");

        const url =
            `https://${domain}/api/v1/turn/credentials` +
            `?apiKey=${encodeURIComponent(meteredApiKey)}`;

        const response = await fetch(url, {
            method: "GET",
            headers: {
                "Accept": "application/json"
            }
        });

        if (!response.ok) {
            const errorText = await response.text();

            console.error(
                "Metered API error:",
                response.status,
                errorText
            );

            return res.status(502).json({
                error: "Unable to obtain TURN configuration."
            });
        }

        const iceServers = await response.json();

        if (!Array.isArray(iceServers) || iceServers.length === 0) {
            console.error("Metered returned invalid ICE configuration.");

            return res.status(502).json({
                error: "Invalid TURN configuration."
            });
        }

        return res.status(200).json({
            iceServers
        });

    } catch (error) {
        console.error("TURN endpoint error:", error);

        return res.status(500).json({
            error: "TURN service unavailable."
        });
    }
}
