FROM python:3.10-bookworm

# install zbar dependency
RUN apt-get -qq update
RUN apt-get -y -qq install zbar-tools

# uv manages the Python environment; see the project README
COPY --from=ghcr.io/astral-sh/uv:0.12.5 /uv /uvx /bin/

# The compose file bind-mounts the repo over /seedsigner, which would shadow a
# venv created there at build time. Keep the environment outside the mount so
# the dependency layer below survives, and so uv reuses it at container start.
ENV UV_PROJECT_ENVIRONMENT=/opt/venv
ENV PATH="/opt/venv/bin:${PATH}"

# Warm the dependency layer: this is invalidated only when the lockfile or the
# project metadata changes, not on every source edit.
WORKDIR /build
# README.md is copied because pyproject.toml declares it as the readme.
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --group l10n --no-install-project
RUN rm -rf /build

# set working dir
WORKDIR /seedsigner
