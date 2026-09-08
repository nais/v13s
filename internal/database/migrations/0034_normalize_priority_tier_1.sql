-- +goose Up
-- Tier 1 (formerly ACT_NOW) is no longer a value v13s produces or exposes.
-- Promote any rows still on tier 1 (KEV findings scored by the old rules) to
-- HIGH so the API never returns an unmapped priority. The updater's normal
-- recalculation keeps them there.
UPDATE cve
SET priority = 2
WHERE priority = 1;

UPDATE vulnerability_summary
SET top_risk_tier = 2
WHERE top_risk_tier = 1;

UPDATE vuln_daily_by_workload
SET top_risk_tier = 2
WHERE top_risk_tier = 1;

-- +goose Down
-- No-op: tier 1 carried no information that can be reconstructed.
SELECT 1;
