# Bootstrap local development rig

## Push a (vulnerable) image into the local docker registry

Example image with vulnerabilities: [vulhub/nginx:1.4.2](https://github.com/vulhub/vulhub/blob/master/nginx/CVE-2013-4547/docker-compose.yml)

Retag to local registry and push:

```shell
source_image=vulhub/nginx:1.4.2
image_name=localhost:4004/vulhub-nginx:1.4.2
docker pull $source_image
docker tag $source_image  $image_name
docker push $image_name
```

Create cyclonedx sbom, attest and upload to local registry:

```shell
image_name=localhost:4004/vulhub-nginx:1.4.2
trivy image --format cyclonedx --output vuln-nginx.json $image_name
cosign attest --predicate vuln-nginx.json --type cyclonedx $image_name 
```

## Extract registry data from local registry so you dont have to push the image again

```shell
docker cp $(docker ps -q -f name=registry):/var/lib/registry ./local/registry-data
```