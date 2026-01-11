Publish Image Tag action

Writes the provided image tag to `image-tag.txt` and uploads it as an artifact named `image-tag`.

Inputs:
- `image-tag` (required): the image tag string to publish.

Usage in workflows:

```yaml
- uses: ./.github/actions/publish-image-tag
  with:
    image-tag: ${{ steps.tag.outputs.image-tag }}
```
