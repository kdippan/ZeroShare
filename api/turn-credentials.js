export default async function handler(req, res) {
  if (req.method !== "GET") {
    return res.status(405).json({
      error: "Method not allowed"
    });
  }

  const meteredDomain = process.env.METERED_DOMAIN;
  const meteredApiKey = process.env.METERED_API_KEY;

  const meteredUsername = process.env.METERED_USERNAME;
  const meteredCredential = process.env.METERED_CREDENTIAL;

  const expressTurnUsername = process.env.EXPRESSTURN_USERNAME;
  const expressTurnPassword = process.env.EXPRESSTURN_PASSWORD;

  const iceServers = [];

  let meteredAvailable = false;
  let meteredError = null;

  /*
   * ---------------------------------------------------------
   * METERED PRIMARY
   * ---------------------------------------------------------
   */

  if (meteredDomain && meteredApiKey) {
    try {
      const url =
        `https://${meteredDomain}/api/v1/turn/credentials?apiKey=${encodeURIComponent(
          meteredApiKey
        )}`;

      const controller = new AbortController();

      const timeout = setTimeout(() => {
        controller.abort();
      }, 10000);

      let response;

      try {
        response = await fetch(url, {
          method: "GET",
          headers: {
            Accept: "application/json"
          },
          signal: controller.signal
        });
      } finally {
        clearTimeout(timeout);
      }

      const text = await response.text();

      if (!response.ok) {
        meteredError = {
          type: "http_error",
          status: response.status,
          statusText: response.statusText
        };
      } else {
        let data;

        try {
          data = JSON.parse(text);
        } catch {
          data = null;
          meteredError = {
            type: "invalid_json"
          };
        }

        if (Array.isArray(data) && data.length > 0) {
          for (const server of data) {
            if (
              server &&
              server.urls &&
              (
                typeof server.urls === "string" ||
                Array.isArray(server.urls)
              )
            ) {
              iceServers.push(server);
            }
          }

          if (iceServers.length > 0) {
            meteredAvailable = true;
          }
        }
      }
    } catch (error) {
      meteredError = {
        type: error?.name === "AbortError"
          ? "timeout"
          : "fetch_error",
        details: error instanceof Error
          ? error.message
          : String(error)
      };

      console.error("Metered API error:", error);
    }
  } else {
    meteredError = {
      type: "configuration_missing"
    };
  }

  /*
   * ---------------------------------------------------------
   * METERED STATIC FALLBACK
   * ---------------------------------------------------------
   *
   * Optional:
   * METERED_USERNAME
   * METERED_CREDENTIAL
   *
   * This is useful when the Metered REST API cannot be reached
   * from the Vercel serverless function.
   */

  if (
    !meteredAvailable &&
    meteredUsername &&
    meteredCredential
  ) {
    iceServers.push(
      {
        urls: "stun:stun.relay.metered.ca:80"
      },
      {
        urls: "turn:global.relay.metered.ca:80",
        username: meteredUsername,
        credential: meteredCredential
      },
      {
        urls: "turn:global.relay.metered.ca:80?transport=tcp",
        username: meteredUsername,
        credential: meteredCredential
      },
      {
        urls: "turn:global.relay.metered.ca:443",
        username: meteredUsername,
        credential: meteredCredential
      },
      {
        urls: "turns:global.relay.metered.ca:443?transport=tcp",
        username: meteredUsername,
        credential: meteredCredential
      }
    );

    meteredAvailable = true;
  }

  /*
   * ---------------------------------------------------------
   * GOOGLE STUN
   * ---------------------------------------------------------
   */

  iceServers.push(
    {
      urls: "stun:stun.l.google.com:19302"
    },
    {
      urls: "stun:stun1.l.google.com:19302"
    }
  );

  /*
   * ---------------------------------------------------------
   * EXPRESSTURN SECONDARY
   * ---------------------------------------------------------
   */

  const expressTurnAvailable =
    Boolean(
      expressTurnUsername &&
      expressTurnPassword
    );

  if (expressTurnAvailable) {
    iceServers.push({
      urls: [
        "turn:free.expressturn.com:3478?transport=udp",
        "turn:free.expressturn.com:3478?transport=tcp"
      ],
      username: expressTurnUsername,
      credential: expressTurnPassword
    });
  }

  /*
   * ---------------------------------------------------------
   * NO TURN PROVIDER
   * ---------------------------------------------------------
   */

  if (!meteredAvailable && !expressTurnAvailable) {
    return res.status(503).json({
      error: "No TURN provider is available",
      providers: {
        metered: false,
        expressturn: false
      },
      meteredError
    });
  }

  /*
   * ---------------------------------------------------------
   * RESPONSE HEADERS
   * ---------------------------------------------------------
   */

  res.setHeader(
    "Cache-Control",
    "no-store, no-cache, must-revalidate, proxy-revalidate"
  );

  res.setHeader(
    "X-Turn-Metered",
    meteredAvailable
      ? "available"
      : "unavailable"
  );

  res.setHeader(
    "X-Turn-Express",
    expressTurnAvailable
      ? "available"
      : "unavailable"
  );

  /*
   * ---------------------------------------------------------
   * RESPONSE
   * ---------------------------------------------------------
   */

  return res.status(200).json({
    iceServers,

    providers: {
      metered: meteredAvailable,
      expressturn: expressTurnAvailable
    },

    meteredError: meteredError
      ? {
          type: meteredError.type,
          status: meteredError.status || null,
          details: meteredError.details || null
        }
      : null
  });
}