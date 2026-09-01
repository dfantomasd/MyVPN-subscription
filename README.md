# MyVPN Community Subscription

Automatically refreshed, ranked, VLESS-only community subscription. Russian
endpoints and insecure configurations are excluded.

Every published endpoint passes a fresh sing-box tunnel and Telegram HTTPS
probe. LTE reachability still depends on the mobile operator and cannot be
proven by foreign CI, so the feed retains diverse fallback endpoints.

## Subscription links

- HAPP (VLESS + Russian split routing + hourly auto-update): `https://dfantomasd.github.io/MyVPN-subscription/public/happ.txt`
- Karing (Base64): `https://dfantomasd.github.io/MyVPN-subscription/public/karing.txt`
- HAPP CDN mirror: `https://cdn.jsdelivr.net/gh/dfantomasd/MyVPN-subscription@main/public/happ.txt`
- Karing CDN mirror: `https://cdn.jsdelivr.net/gh/dfantomasd/MyVPN-subscription@main/public/karing.txt`
- Transparent ranking report: `https://raw.githubusercontent.com/dfantomasd/MyVPN-subscription/main/public/report.json`

Node labels distinguish end-to-end proxy latency from TCP-only measurements.
`speed—` means throughput has not been measured and is never an estimate.

Community endpoints are operated by third parties. Do not treat them as trusted
or private infrastructure and do not send unencrypted sensitive traffic.
