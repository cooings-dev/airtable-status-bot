# Airtable Status Bot

Cloud monitor for Airtable status with this behavior:

- Airtable is UP: check once per hour, no Slack message
- Airtable is DOWN: send status sync to Slack every 10 minutes

## How it works

The GitHub Actions workflow runs every 10 minutes:

- at `:00` (top of hour), it runs `hourly-probe`
- at other times, it runs `down-probe`

`hourly-probe` updates `.state/airtable_status_state.json` with `down_active=true|false`.  
`down-probe` only sends Slack when `down_active=true`.

## Setup

1. Go to repo `Settings` -> `Secrets and variables` -> `Actions`
2. Add a repository secret:
   - Name: `SLACK_WEBHOOK_URL`
   - Value: your Slack Incoming Webhook URL (`https://hooks.slack.com/services/...`)
3. Go to `Actions` tab and enable workflows if prompted
4. Optionally run a manual test:
   - `Airtable Status Monitor` -> `Run workflow`
   - choose mode `hourly-probe` or `down-probe`

## Files

- `airtable_status_monitor.py`: monitor logic
- `.github/workflows/airtable-status-monitor.yml`: scheduler + execution
- `.state/airtable_status_state.json`: persisted state committed by workflow

## Notes

- Status source: `https://status.airtable.com/api/v2/status.json`
- Incidents source: `https://status.airtable.com/api/v2/incidents/unresolved.json`
