#!/bin/bash

# Install the project itself into the environment prepared by the image (the
# dependencies are already there; --frozen keeps uv from re-resolving).
uv sync --frozen --group l10n
tail -f /dev/null
