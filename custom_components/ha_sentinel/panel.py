"""Sidebar panel (dashboard) registration."""

from __future__ import annotations

from pathlib import Path

from homeassistant.components import frontend, panel_custom
from homeassistant.components.http import StaticPathConfig
from homeassistant.core import HomeAssistant

from .const import DOMAIN, PANEL_COMPONENT, PANEL_ICON, PANEL_TITLE, PANEL_URL_PATH, STATIC_URL, VERSION

_FRONTEND_DIR = Path(__file__).parent / "frontend"
_STATIC_REGISTERED = f"{DOMAIN}_static_registered"


async def async_register_static(hass: HomeAssistant) -> None:
    """Serve the panel's JS (once per HA run: static routes cannot be removed)."""
    if hass.data.get(_STATIC_REGISTERED):
        return
    await hass.http.async_register_static_paths(
        [StaticPathConfig(STATIC_URL, str(_FRONTEND_DIR), cache_headers=False)]
    )
    hass.data[_STATIC_REGISTERED] = True


async def async_register_panel(hass: HomeAssistant) -> None:
    """Add the Sentinel dashboard to the sidebar (admins only)."""
    if PANEL_URL_PATH in hass.data.get(frontend.DATA_PANELS, {}):
        return
    await panel_custom.async_register_panel(
        hass,
        frontend_url_path=PANEL_URL_PATH,
        webcomponent_name=PANEL_COMPONENT,
        sidebar_title=PANEL_TITLE,
        sidebar_icon=PANEL_ICON,
        module_url=f"{STATIC_URL}/ha-sentinel-panel.js?v={VERSION}",
        require_admin=True,
        config={"version": VERSION},
    )


def async_unregister_panel(hass: HomeAssistant) -> None:
    """Remove the panel from the sidebar."""
    frontend.async_remove_panel(hass, PANEL_URL_PATH, warn_if_unknown=False)
