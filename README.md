#Re-image

A tool for mass update of images for kubernetes manifests. This is a Work In
Progress, YMMV, configuration and settings may change.

- Works with helm post-renderer, or arbitrary k8s manifests
- Check images used by Deployments, StatefulSets, DaemonSets, Cronjobs and Job (or
  arbitrary objects using jsonpath queries):
  - Exists (prevents deploy of manifests with bad references)
  - Remap tags (e.g latest) to a tag for the explicit digest they currently map to
  - Optionally syncs images from third party repositories to known repository

This is intended to:
- Prevent deploying assets with un-pullable images
- Localise images for faster start times
- Potentially improve availability by reducing runtime third party service
  dependencies (e.g. dockerhub)
- Help with compliance by pulling all images from registries with image
  scanning
- Help with the use of in-cluster binary authorization
