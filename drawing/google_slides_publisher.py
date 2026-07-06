"""Publish topology diagrams via Google Slides API (Drawings has no shape API)."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

from layout_topology import TopologyLayout
from topology_model import Topology

# Slides + create files in Drive (presentation link can be opened/exported).
SCOPES = [
    "https://www.googleapis.com/auth/presentations",
    "https://www.googleapis.com/auth/drive.file",
]

DEFAULT_TOKEN_PATH = Path(__file__).resolve().parent / ".google_topology_token.json"
DEFAULT_CREDENTIALS_PATH = Path(__file__).resolve().parent / "credentials.json"

OAUTH_SETUP_HELP = """
Google Slides upload needs OAuth (one-time setup):

1. Open https://console.cloud.google.com/ (pick or create a project).
2. APIs & Services → Library → enable **Google Slides API** and **Google Drive API**.
3. APIs & Services → OAuth consent screen → configure (add your Google account as
   Test user if the app is in Testing mode).
4. APIs & Services → Credentials → Create credentials → **OAuth client ID**.
   Application type: **Desktop app** → Create → **Download JSON**.
5. Save the downloaded file as:
     drawing/credentials.json
   Or anywhere, then:
     export GOOGLE_TOPOLOGY_CREDENTIALS=/path/to/client_secret....json
6. Re-run:
     python drawing/publish_topology.py --yaml drawing/topology.yaml --google-slides

A browser window opens for sign-in; token is cached in drawing/.google_topology_token.json

Alternative (gcloud): if you use Application Default Credentials with Slides/Drive
scopes, the script will try those before asking for credentials.json.
"""


def _try_application_default_credentials() -> Credentials | None:
    try:
        import google.auth

        creds, _ = google.auth.default(scopes=SCOPES)
        if hasattr(creds, "refresh"):
            if not creds.valid:
                creds.refresh(Request())
        return creds  # type: ignore[return-value]
    except Exception:
        return None


def _load_credentials(
    credentials_path: Path | None = None,
    token_path: Path | None = None,
) -> Credentials:
    credentials_path = credentials_path or Path(
        os.environ.get("GOOGLE_TOPOLOGY_CREDENTIALS", str(DEFAULT_CREDENTIALS_PATH))
    )
    token_path = token_path or Path(
        os.environ.get("GOOGLE_TOPOLOGY_TOKEN", str(DEFAULT_TOKEN_PATH))
    )

    creds: Credentials | None = None
    if token_path.is_file():
        creds = Credentials.from_authorized_user_file(str(token_path), SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            creds = _try_application_default_credentials()
            if creds is None or not creds.valid:
                if not credentials_path.is_file():
                    raise FileNotFoundError(
                        f"OAuth client secrets not found at {credentials_path}.\n"
                        f"{OAUTH_SETUP_HELP}"
                    )
                flow = InstalledAppFlow.from_client_secrets_file(str(credentials_path), SCOPES)
                creds = flow.run_local_server(port=0)
        token_path.write_text(creds.to_json(), encoding="utf-8")

    return creds


def _pt(value: float) -> dict[str, Any]:
    return {"magnitude": value, "unit": "PT"}


def _object_id(prefix: str, index: int) -> str:
    safe = "".join(c if c.isalnum() else "_" for c in prefix)[:40]
    return f"{safe}_{index}"


def build_slides_requests(
    topology: Topology,
    layout: TopologyLayout,
    slide_id: str,
) -> list[dict[str, Any]]:
    requests: list[dict[str, Any]] = []

    for i, device in enumerate(topology.devices):
        node = layout.nodes[device]
        box_id = _object_id(device, i)
        requests.append(
            {
                "createShape": {
                    "objectId": box_id,
                    "shapeType": "ROUND_RECTANGLE",
                    "elementProperties": {
                        "pageObjectId": slide_id,
                        "size": {"width": _pt(node.width), "height": _pt(node.height)},
                        "transform": {
                            "scaleX": 1,
                            "scaleY": 1,
                            "translateX": node.x,
                            "translateY": node.y,
                            "unit": "PT",
                        },
                    },
                }
            }
        )
        requests.append(
            {
                "insertText": {
                    "objectId": box_id,
                    "insertionIndex": 0,
                    "text": device,
                }
            }
        )

    for i, link in enumerate(topology.links):
        a = layout.nodes[link.device_a]
        b = layout.nodes[link.device_b]
        line_id = _object_id("link", i)
        x1, y1 = a.center_x, a.center_y
        x2, y2 = b.center_x, b.center_y
        width = max(abs(x2 - x1), 1.0)
        height = max(abs(y2 - y1), 1.0)
        requests.append(
            {
                "createLine": {
                    "objectId": line_id,
                    "lineCategory": "STRAIGHT",
                    "elementProperties": {
                        "pageObjectId": slide_id,
                        "size": {"width": _pt(width), "height": _pt(height)},
                        "transform": {
                            "scaleX": 1 if x2 >= x1 else -1,
                            "scaleY": 1 if y2 >= y1 else -1,
                            "translateX": min(x1, x2),
                            "translateY": min(y1, y2),
                            "unit": "PT",
                        },
                    },
                }
            }
        )
        if link.port_a or link.port_b:
            label = f"{link.port_a} ↔ {link.port_b}".strip(" ↔")
            label_id = _object_id("lbl", i)
            mx = (x1 + x2) / 2 - 40
            my = (y1 + y2) / 2 - 24
            requests.append(
                {
                    "createShape": {
                        "objectId": label_id,
                        "shapeType": "TEXT_BOX",
                        "elementProperties": {
                            "pageObjectId": slide_id,
                            "size": {"width": _pt(120), "height": _pt(20)},
                            "transform": {
                                "scaleX": 1,
                                "scaleY": 1,
                                "translateX": mx,
                                "translateY": my,
                                "unit": "PT",
                            },
                        },
                    }
                }
            )
            requests.append(
                {
                    "insertText": {
                        "objectId": label_id,
                        "insertionIndex": 0,
                        "text": label,
                    }
                }
            )

    return requests


def publish_topology_to_google_slides(
    topology: Topology,
    layout: TopologyLayout,
    *,
    title: str = "Network topology",
    credentials_path: Path | None = None,
    token_path: Path | None = None,
) -> dict[str, str]:
    """Create a new Google Slides deck with the topology diagram. Returns ids/urls."""
    creds = _load_credentials(credentials_path, token_path)
    service = build("slides", "v1", credentials=creds, cache_discovery=False)

    presentation = (
        service.presentations()
        .create(body={"title": title})
        .execute()
    )
    presentation_id = presentation["presentationId"]
    slide_id = presentation["slides"][0]["objectId"]

    requests = build_slides_requests(topology, layout, slide_id)
    if requests:
        service.presentations().batchUpdate(
            presentationId=presentation_id,
            body={"requests": requests},
        ).execute()

    url = f"https://docs.google.com/presentation/d/{presentation_id}/edit"
    return {
        "presentation_id": presentation_id,
        "url": url,
        "note": (
            "Google Drawings has no shape API and no File→Import. Use this Slides URL and "
            "copy/paste shapes into a Drawing, or export PNG and use Insert→Image in Drawings."
        ),
    }
