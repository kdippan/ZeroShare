export default async function handler(req, res) {
  if (req.method !== "GET") {
    return res.status(405).json({
      error: "Method not allowed",
    });
  }

  try {
    const {
      METERED_DOMAIN,
      METERED_API_KEY,
      EXPRESSTURN_USERNAME,
      EXPRESSTURN_PASSWORD,
    } = process.env;

    if (
      !METERED_DOMAIN ||
      !METERED_API_KEY ||
      !EXPRESSTURN_USERNAME ||
      !EXPRESSTURN_PASSWORD
    ) {
      return res.status(500).json({
        error: "TURN server configuration is incomplete",
      });
    }
    const meteredUrl =
      `https://${METERED_DOMAIN}/api/v1/turn/credentials` +
      `?apiKey=${encodeURIComponent(METERED_API_KEY)}`;

    const meteredResponse = await fetch(meteredUrl, {
      method: "GET",
      headers: {
        Accept: "application/json",
      },
      cache: "no-store",
    });

    if (!meteredResponse.ok) {
      throw new Error(
        `Metered request failed: HTTP ${meteredResponse.status}`
      );
    }

    const meteredServers = await meteredResponse.json();

    if (!Array.isArray(meteredServers)) {
      throw new Error("Invalid response from Metered");
    }
    const expressTurnServer = {
      urls: [
        "turn:free.expressturn.com:3478?transport=udp",
        "turn:free.expressturn.com:3478?transport=tcp",
      ],
      username: EXPRESSTURN_USERNAME,
      credential: EXPRESSTURN_PASSWORD,
    };
    const iceServers = [
      ...meteredServers,
      expressTurnServer,
    ];

    return res.status(200).json({
      iceServers,
      providers: {
        metered: true,
        expressturn: true,
      },
    });
  } catch (error) {
    console.error("TURN credential error:", error);

    return res.status(500).json({
      error: "Unable to obtain TURN configuration",
    });
  }
}