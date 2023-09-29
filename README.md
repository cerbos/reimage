# Re-image

A tool for mass update of images for kubernetes manifests.

This is a Work In Progress, YMMV, configuration and settings may change.

- Works with helm post-renderer, or arbitrary k8s manifests
- Check images used by Deployments, StatefulSets, DaemonSets, Cronjobs and Job (or
  arbitrary objects using jsonpath queries):
  - Exist (prevents deploy of manifests with bad references)
  - Remap tags (e.g latest) to a tag for the explicit digest they currently map to
  - Optionally copy images from third party repositories to known repository
  - Check that image scanning:
    - has completed (with time limited check retry)
    - images have no CVEs above a certain score (with overridable ignore list)
- Can create GCP BinAuthz attestations for discovered image digests

This is intended to:
- Prevent deploying assets with un-pullable images
- Localise images for faster start times
- Potentially improve availability by reducing runtime third party service
  dependencies (e.g. rDdockerhub)
- Help with compliance by pulling all images from registries with image
  scanning
- Help with the use of in-cluster binary authorization

# Renaming / Copying

```shell
$ cat manifest.yml | reimage \
  -rename-ignore 'docker.example.com/registry/spitfire/.+$' \
  -rename-remote-path 'docker.example.com/registry/spitfire/imported' \
  > manifest-out.yaml
```
This will update all the `image` fields of standard resource types in `manifest.yml`.
All the images matching `rename-ignore` will be left alone, all other images will
be update to exist under the `-rename-remote-path` repository. The remote path
is templateable using `-rename-force-digest`.

If the images do not exist in the remote repository they will be copied to the new
location. If the images have been copied previously this can be disabled by using `-no-copy`
(repository actions can be slow, so this can be a significant speed up).

If `-rename-force-digest` enabled, the image will first be renamed and copied
as above, but will then be transferred into the full resolved digest form. The
final mapping (see below), will be from the original name to the full resolved
digest form of the renamed image. This ensure in-cluster images are guaranteed
stable, and is also required for cluster with an enforced Grafeas/Kritis/BinAuthz
image policy.

The following flags control renaming and copying
```
  -clobber
        allow overwriting remote images
  -no-copy
        disable copying of renamed images
  -rename-force-digest
        the final renamed image will be transformed to digest form before output
  -rename-ignore string
        ignore images matching this expression (default "^$")
  -rename-remote-path string
        template for remapping imported images
  -rename-template string
        template for remapping imported images (default "{{ .RemotePath }}/{{ .Registry }}/{{ .Repository }}:{{ .DigestHex }}")
```

## Supporting Unknown K8S types

If you need to find images in non-standard k8s you can provide rules
to reimage to help it find image fields. You can pass these rules using
the `-rules-config` CLI flag.

```yaml
- kind: ^Prometheus$                     # Regexp matching the k8s Kind of objects
  apiVersion: ^monitoring.coreos.com/v1$ # Regexp matching APIVersion of objects
  imageJSONP:
  - "$.spec.image"                       # JSONP queries that match image fields of a type
```

# Stored Mappings

The mappings that result from the renaming of images can be written to a file,
and/r directly to an OCI registry. You can then run reimage again, reading the
exact set of mapping generated previously. This ensures that mappings of image tags
to digests can be consistent between runs of reimage.

```shell
$ # write to a file
$ helm template -write-mappings-file mappings.json -remote-path example.com/registry/imported
$ # write to an image
$ helm template \
  -rename-remote-path 'docker.example.com/registry/spitfire/imported' \
  -write-mappings-img example.com/registry/imported/reimage-mapping:1234 \
  -remote-path example.com/registry/imported
```

The `-mappings-only` switches off the default yaml processing, and instead will apply
any requested copying, vulnerability checking, and attestation against every image
listed in the mappings file.

```shell
$ # read image from an image
$ helm template \
  -mappings-only
  -static-mappings-img example.com/registry/imported/reimage-mapping:1234 \
  -remote-path example.com/registry/imported
```

If vulnerability scanning (see below) is performed when the mappings are being
written, the CVEs that exist in an image (but are below the max CVSS score, or
explicitly ignored), are included in the image. This makes it easy to audit
CVEs for a specific image.

The following flags control mappings usage

```
  -static-json-mappings-file string
        take all mappings from a mappings file
  -static-json-mappings-img string
        take all mapping from a mappings registry image
  -write-json-mappings-file string
        write final image mappings to a json file
  -write-json-mappings-img string
        write final image mapping to a registry image
  -mappings-only
        skip yaml processing, and image copying,  and just run checks and attestations from images in mappings

```
# Grafeas Vulnerability Checking

NOTE: At present, Vulnerability scanning only works with google cloud container registry

reimage can check for Grafeas Discovery occurrences containing CVE checks for
the discovered images. If discovery checking is enabled, but no completed discovery
has occurred, reimage will wait for a configurable time. Vulnerability checking
is disabled by default, and can be enabled by setting `-vulncheck-max-cvss`. If you
want to scan, but ignore all CVEs, use `-vulncheck-max-cvss 11`

```
  -vulncheck-ignore-cve-list string
        comma separated list of vulnerabilities to ignore
  -vulncheck-ignore-images string
        regexp of images to skip for CVE checks
  -vulncheck-max-cvss float
        maximum CVSS vulnerabitility score
  -vulncheck-timeout duration
        how long to wait for vulnerability scanning to complete (default 5m0s)
```

# Grafeas Attestation

NOTE: At present, attestation support only works with Google Cloud BinAuthz attestors

reimage can add attestations for the images it has processed. For example, you can
create an attestation that shows that images were required for our helm deploys

```shell
$  helmfile template --environment=staging | reimage \
     -grafeas-parent projects/my-registry \
     -binauthz-attestor projects/my-registry/attestors/helm-requires
```

Similarly you can attest that all images have gone to staging (and perhaps have passed
integration testing).

```shell
$ reimage \
     -mappings-only
     -static-mappings-img example.com/registry/imported/reimage-mapping:1234 \
     -grafeas-parent projects/my-registry \
     -binauthz-attestor projects/my-registry/attestors/cleared-staging
```

`

