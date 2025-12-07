# Facial Recognition Module

This document describes the facial recognition approach used by PentaVision and
how it maps to the requirements in `TODO.md` under **Facial recognition module**.

## Stack choice

PentaVision uses the following Python libraries for facial detection and
recognition:

- **`face-recognition`** – high-level library built on top of dlib's
  deep-learning face embeddings. Provides convenient `face_encodings` and
  comparison helpers.
- **OpenCV (`opencv-python`)** – used for image loading/processing and, where
  needed, additional detectors or video frame handling.

These are already listed in `requirements.txt` and are installed into the app's
virtualenv.

## FaceDB schema

Facial embeddings are stored in the **FaceDB** database using the
`FaceEmbedding` model in `app/models.py`:

- `id` – primary key.
- `user_id` – integer linking the embedding to a user in `UserDB`.
- `embedding` – binary blob containing the serialized face embedding.
- `created_at` – timestamp when the embedding was created.

The `create_face_schema(engine)` helper in `app/models.py` creates the
underlying `face_embeddings` table, and the installer (`/install`) calls this
helper during initial setup.

## Enrollment flow

Enrollment is implemented via the Faces demo page and `/api/face/enroll`:

1. A logged-in operator opens the **Faces demo** page and selects *Enroll*.
2. The browser uses `getUserMedia` to capture one or more images from the
   webcam.
3. The images are POSTed to `/api/face/enroll` along with the target email or
   account identifier.
4. The backend locates faces, computes embeddings, and inserts `FaceEmbedding`
   rows into FaceDB.

If no faces are detected or the email does not map to a user, the API responds
with a clear error and does not create embeddings.

## Runtime recognition

The app exposes two main recognition paths:

1. **Snapshot recognition** – the Faces demo posts still images to
   `/api/face/recognize`, which returns bounding boxes, match distances, and
   (when present) matched user IDs/emails.
2. **Live camera recognition** – the dashboard and per-camera session view call
   `/api/cameras/<device_id>/face-recognize`, which uses the shared
   `CameraStreamManager` to grab the latest frame for a camera and run
   recognition on it.

In both cases, the flow is:

1. Load the frame into memory.
2. Detect faces and compute embeddings with `face_recognition`.
3. Compare embeddings to stored `FaceEmbedding` vectors.
4. Return matches, distances, and image dimensions so the frontend can draw
   overlays.

Thresholds use Euclidean distance and are controlled by:

- `FACE_MATCH_THRESHOLD` – environment variable loaded via `app.config`.
- Default value: `0.6` if the variable is unset or invalid.

## Privacy, retention, and deletion

- Only embeddings (numeric vectors) are stored in FaceDB; raw enrollment images
  do not need to be kept once embeddings are created.
- FaceDB runs on its own MariaDB instance (see
  `docs/database-architecture.md`), with:
  - Dedicated DB user credentials.
  - No direct cross-DB joins.
  - Network and TLS protections consistent with the other databases.
  - Encryption at rest enabled (for example, full-disk encryption via LUKS on
    self-managed servers, or built-in storage encryption on managed cloud
    databases).
  - Network ACLs/firewall rules that allow connections only from the
    recognition service host(s); other application components should not be
    able to reach FaceDB directly.
- Opt-out settings are stored in the `FacePrivacySetting` table. The APIs
  `/api/face/privacy/opt-out` and `/api/face/privacy/opt-in` let operators
  toggle whether a user's embeddings are considered during recognition.
- When a user is marked as opted out, their existing embeddings remain in the
  database but are excluded from matching.
- To fully delete a subject's facial data, an administrator can remove all
  `FaceEmbedding` rows for the relevant `user_id` from FaceDB (for example via
  a maintenance script or admin-only management tool).
- Retention policies should be defined per deployment (for example, keeping
  embeddings only while a user has an active account and valid consent).
