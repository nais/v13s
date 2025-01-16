# v13s

## Description

TODO

## Versioning
Skip versioning in the package names and use [Semantic Versioning](https://semver.org/) and tags, i.e. v1 and so on, so users can import the package with a specific version.

## Notes/TODOs

* Remember pagination when fetching resources from the API. We should not fetch all resources at once. See iterator in nais/api/apiclient for an example.
* Consider adding a separate go.mod in the pkg directory to not expose all our dependencies to the users. This will also allow us to have a cleaner go.mod file in the root directory.
  Add a replace directive in the main go.mod file to point to the local path of the pkg directory so it doesn't fetch the package from the internet. See github.com/nais/api for an example.