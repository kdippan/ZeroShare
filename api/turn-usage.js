export default async function handler(req, res) {
    if (req.method !== "GET") {
        return res.status(405).json({
            error: "Method not allowed"
        });
    }

    const domain = (process.env.METERED_DOMAIN || "")
        .trim()
        .replace(/^https?:\/\//, "")
        .replace(/\/+$/, "");

    const secretKey = (process.env.METERED_SECRET_KEY || "").trim();

    if (!domain || !secretKey) {
        return res.status(500).json({
            error: "TURN usage service is not configured"
        });
    }

    const url =
        `https://${domain}/api/v1/turn/current_usage` +
        `?secretKey=${encodeURIComponent(secretKey)}`;

    try {
        const response = await fetch(url, {
            method: "GET",
            headers: {
                Accept: "application/json"
            }
        });

        const data = await response.json().catch(() => null);

        if (!response.ok || !data) {
            return res.status(502).json({
                error: "Unable to retrieve TURN usage"
            });
        }

        const usageInGB = Number(data.usageInGB);
        const quotaInGB = Number(data.quotaInGB);
        const overageInGB = Number(data.overageInGB || 0);

        if (
            !Number.isFinite(usageInGB) ||
            !Number.isFinite(quotaInGB) ||
            quotaInGB <= 0
        ) {
            return res.status(502).json({
                error: "Invalid TURN usage data"
            });
        }

        const usageMB = usageInGB * 1000;
        const quotaMB = quotaInGB * 1000;
        const remainingMB = Math.max(0, quotaMB - usageMB);
        const percentage = Math.min(
            100,
            Math.max(0, (usageMB / quotaMB) * 100)
        );
        const overageMB = Math.max(0, overageInGB * 1000);

        let status = "available";

        if (percentage >= 100) {
            status = "exhausted";
        } else if (percentage >= 90) {
            status = "critical";
        } else if (percentage >= 70) {
            status = "warning";
        }

        return res.status(200).json({
            usageMB: Number(usageMB.toFixed(2)),
            quotaMB: Number(quotaMB.toFixed(2)),
            remainingMB: Number(remainingMB.toFixed(2)),
            percentage: Number(percentage.toFixed(2)),
            overageMB: Number(overageMB.toFixed(2)),
            status
        });
    } catch {
        return res.status(502).json({
            error: "TURN usage service unavailable"
        });
    }
}
