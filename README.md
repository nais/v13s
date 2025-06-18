# v13s

## Description

v13s offers a streamlined, workload-focused API designed to retrieve vulnerability data for a workload from multiple
sources

## Versioning the client

Skip versioning in the package names and use [Semantic Versioning](https://semver.org/) and tags, i.e. v1 and so on, so
users can import the package with a specific version.

## Notes/TODOs

* Have a k8s informer to keep track of total workloads, can watch deployments, statefulsets, daemonsets, jobs, and how
  many have sboms etc.
* Remember pagination when fetching resources from the API. We should not fetch all resources at once. See iterator in
  nais/api/apiclient for an example.
* Consider adding a separate go.mod in the pkg directory to not expose all our dependencies to the users. This will also
  allow us to have a cleaner go.mod file in the root directory.
  Add a replace directive in the main go.mod file to point to the local path of the pkg directory so it doesn't fetch
  the package from the internet. See github.com/nais/api for an example.
* Should we create a new row for each workload or do a update? If we do create we have a history of all workloads and
  images tags. If we do a update we only have the latest image tag for each workload. We still have the history of all
  images tags in the image table.

## River

```bash
  river migrate-get --line main --all --up > river_schema.sql
```

