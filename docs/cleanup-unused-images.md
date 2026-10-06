# Cleaning up unused images

The updater job `clean up unused images` deletes images that have been `unused` for longer than the retention and that no workload references. Their vulnerabilities and summaries are deleted through `ON DELETE CASCADE`.

| Variable | Default | |
|---|---|---|
| `UPDATER_CLEANUP_UNUSED_IMAGES_ENABLED` | `false` | |
| `UPDATER_CLEANUP_UNUSED_IMAGES_CRON` | `0 3 * * *` | |
| `UPDATER_CLEANUP_UNUSED_IMAGES_RETENTION` | `1440h` | 60 days |
| `UPDATER_CLEANUP_UNUSED_IMAGES_BATCH_SIZE` | `1000` | Images per delete statement |
| `UPDATER_CLEANUP_UNUSED_IMAGES_MAX_PER_RUN` | `0` | Images per run, `0` is no limit |

## First run on a tenant with a backlog

1. Measure the backlog and the current cost:

   ```sql
   SELECT COUNT(*) FROM images i
   WHERE i.state = 'unused' AND i.updated_at < NOW() - INTERVAL '60 days'
     AND NOT EXISTS (SELECT 1 FROM workloads w WHERE w.image_name = i.name AND w.image_tag = i.tag);

   SELECT relname, pg_size_pretty(pg_total_relation_size(oid))
   FROM pg_class WHERE relname IN ('vulnerabilities', 'vulnerability_summary', 'images');
   ```

   Record `EXPLAIN (ANALYZE, BUFFERS)` of the `mv_cve_workload_counts` query (`internal/database/migrations`) as the baseline.

2. Enable the job with a limit, for example `BATCH_SIZE=500` and `MAX_PER_RUN=50000`, so the backlog is removed over several nights. Raise or remove the limit once the backlog is gone.

3. While it runs, watch locks, WAL volume and query latency. The job logs the deleted image and vulnerability counts per run.

4. When the backlog is gone, update statistics and the visibility map:

   ```sql
   VACUUM (ANALYZE) vulnerabilities;
   VACUUM (ANALYZE) vulnerability_summary;
   VACUUM (ANALYZE) images;
   ```

5. `VACUUM` does not return disk space. Rewrite the tables in a maintenance window:
   - `pg_repack --table=vulnerabilities` (preferred, short locks), or
   - `VACUUM FULL vulnerabilities;` (holds an `ACCESS EXCLUSIVE` lock for the whole run).

6. Repeat step 1 and compare sizes and timings with the baseline.
