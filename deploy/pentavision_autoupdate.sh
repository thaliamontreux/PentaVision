#!/usr/bin/env bash
set -euo pipefail

APP_USER="pentavision"
APP_DIR="/opt/pentavision"
REPO_DIR="${APP_DIR}/app"
VENV_DIR="${APP_DIR}/venv"
BRANCH="main"

if [[ ! -d "${REPO_DIR}/.git" ]]; then
  echo "Repo not found at ${REPO_DIR}" >&2
  exit 1
fi

cd "${REPO_DIR}"

git remote update -p

LOCAL_SHA="$(git rev-parse HEAD)"
REMOTE_SHA="$(git rev-parse "origin/${BRANCH}")"
BASE_SHA="$(git merge-base HEAD "origin/${BRANCH}")"

if [[ "${LOCAL_SHA}" == "${REMOTE_SHA}" ]]; then
  echo "Up to date (${LOCAL_SHA})"
  exit 0
fi

if [[ "${BASE_SHA}" != "${LOCAL_SHA}" ]]; then
  echo "Local branch has diverged from origin/${BRANCH}; refusing to auto-update" >&2
  echo "local=${LOCAL_SHA} remote=${REMOTE_SHA} base=${BASE_SHA}" >&2
  exit 2
fi

echo "Updating ${LOCAL_SHA} -> ${REMOTE_SHA}"

systemctl stop pentavision-web.service pentavision-video.service pentavision-logserver.service || true

sudo -u "${APP_USER}" git pull --ff-only origin "${BRANCH}"

if [[ -x "${VENV_DIR}/bin/pip" && -f "${REPO_DIR}/requirements.txt" ]]; then
  sudo -u "${APP_USER}" "${VENV_DIR}/bin/pip" install -r "${REPO_DIR}/requirements.txt" --break-system-packages
fi

if [[ -x "${REPO_DIR}/deploy/update_databases.sh" ]]; then
  "${REPO_DIR}/deploy/update_databases.sh" || true
fi

systemctl start pentavision-web.service pentavision-video.service pentavision-logserver.service

echo "Update complete"
