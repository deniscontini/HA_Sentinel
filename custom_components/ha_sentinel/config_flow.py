"""Config and options flow for HA Sentinel."""

from __future__ import annotations

import os
from typing import Any

from homeassistant.config_entries import ConfigEntry, ConfigFlow, ConfigFlowResult, OptionsFlowWithReload
from homeassistant.core import HomeAssistant, callback
from homeassistant.data_entry_flow import section
from homeassistant.helpers.selector import (
    BooleanSelector,
    NumberSelector,
    NumberSelectorConfig,
    NumberSelectorMode,
    SelectSelector,
    SelectSelectorConfig,
    SelectSelectorMode,
    TextSelector,
    TextSelectorConfig,
)
import voluptuous as vol

from .const import (
    CONF_BRUTE_FORCE_THRESHOLD,
    CONF_BRUTE_FORCE_WINDOW,
    CONF_BUS_EVENT_MIN_SEVERITY,
    CONF_IGNORED_NETWORKS,
    CONF_LOG_PATHS,
    CONF_MONITOR_HA_AUTH,
    CONF_POLL_INTERVAL,
    CONF_PORT_SCAN_THRESHOLD,
    CONF_PORT_SCAN_WINDOW,
    CONF_RETENTION_DAYS,
    CONF_SYSLOG_ALLOWED,
    CONF_SYSLOG_ENABLED,
    CONF_SYSLOG_HOST,
    CONF_SYSLOG_PORT,
    CONF_UNDER_ATTACK_THRESHOLD,
    DEFAULT_OPTIONS,
    DOMAIN,
    NAME,
    SEVERITY_OPTIONS,
    split_lines,
)
from .manager import parse_networks

SECTION_SOURCES = "sources"
SECTION_SYSLOG = "syslog"
SECTION_DETECTION = "detection"
SECTION_GENERAL = "general"

_SECTIONS: dict[str, tuple[str, ...]] = {
    SECTION_SOURCES: (CONF_MONITOR_HA_AUTH, CONF_LOG_PATHS, CONF_POLL_INTERVAL),
    SECTION_SYSLOG: (CONF_SYSLOG_ENABLED, CONF_SYSLOG_HOST, CONF_SYSLOG_PORT, CONF_SYSLOG_ALLOWED),
    SECTION_DETECTION: (
        CONF_BRUTE_FORCE_THRESHOLD,
        CONF_BRUTE_FORCE_WINDOW,
        CONF_PORT_SCAN_THRESHOLD,
        CONF_PORT_SCAN_WINDOW,
        CONF_UNDER_ATTACK_THRESHOLD,
        CONF_IGNORED_NETWORKS,
    ),
    SECTION_GENERAL: (CONF_RETENTION_DAYS, CONF_BUS_EVENT_MIN_SEVERITY),
}


def _num(minimum: int, maximum: int, unit: str | None = None) -> NumberSelector:
    config = NumberSelectorConfig(min=minimum, max=maximum, step=1, mode=NumberSelectorMode.BOX)
    if unit:
        config["unit_of_measurement"] = unit
    return NumberSelector(config)


_MULTILINE = TextSelector(TextSelectorConfig(multiline=True))


def _options_schema(o: dict[str, Any]) -> vol.Schema:
    return vol.Schema(
        {
            vol.Required(SECTION_SOURCES): section(
                vol.Schema(
                    {
                        vol.Required(
                            CONF_MONITOR_HA_AUTH, default=o[CONF_MONITOR_HA_AUTH]
                        ): BooleanSelector(),
                        vol.Optional(CONF_LOG_PATHS, default=o[CONF_LOG_PATHS]): _MULTILINE,
                        vol.Required(CONF_POLL_INTERVAL, default=o[CONF_POLL_INTERVAL]): _num(1, 300, "s"),
                    }
                ),
                {"collapsed": False},
            ),
            vol.Required(SECTION_SYSLOG): section(
                vol.Schema(
                    {
                        vol.Required(CONF_SYSLOG_ENABLED, default=o[CONF_SYSLOG_ENABLED]): BooleanSelector(),
                        vol.Required(CONF_SYSLOG_HOST, default=o[CONF_SYSLOG_HOST]): TextSelector(),
                        vol.Required(CONF_SYSLOG_PORT, default=o[CONF_SYSLOG_PORT]): _num(1, 65535),
                        vol.Optional(CONF_SYSLOG_ALLOWED, default=o[CONF_SYSLOG_ALLOWED]): _MULTILINE,
                    }
                ),
                {"collapsed": not o[CONF_SYSLOG_ENABLED]},
            ),
            vol.Required(SECTION_DETECTION): section(
                vol.Schema(
                    {
                        vol.Required(CONF_BRUTE_FORCE_THRESHOLD, default=o[CONF_BRUTE_FORCE_THRESHOLD]): _num(
                            2, 1000
                        ),
                        vol.Required(CONF_BRUTE_FORCE_WINDOW, default=o[CONF_BRUTE_FORCE_WINDOW]): _num(
                            10, 86400, "s"
                        ),
                        vol.Required(CONF_PORT_SCAN_THRESHOLD, default=o[CONF_PORT_SCAN_THRESHOLD]): _num(
                            2, 1000
                        ),
                        vol.Required(CONF_PORT_SCAN_WINDOW, default=o[CONF_PORT_SCAN_WINDOW]): _num(
                            5, 3600, "s"
                        ),
                        vol.Required(
                            CONF_UNDER_ATTACK_THRESHOLD, default=o[CONF_UNDER_ATTACK_THRESHOLD]
                        ): _num(1, 100000),
                        vol.Optional(CONF_IGNORED_NETWORKS, default=o[CONF_IGNORED_NETWORKS]): _MULTILINE,
                    }
                ),
                {"collapsed": True},
            ),
            vol.Required(SECTION_GENERAL): section(
                vol.Schema(
                    {
                        vol.Required(CONF_RETENTION_DAYS, default=o[CONF_RETENTION_DAYS]): _num(1, 3650, "d"),
                        vol.Required(
                            CONF_BUS_EVENT_MIN_SEVERITY, default=o[CONF_BUS_EVENT_MIN_SEVERITY]
                        ): SelectSelector(
                            SelectSelectorConfig(
                                options=SEVERITY_OPTIONS,
                                mode=SelectSelectorMode.DROPDOWN,
                                translation_key="severity",
                            )
                        ),
                    }
                ),
                {"collapsed": True},
            ),
        }
    )


def _flatten(user_input: dict[str, Any]) -> dict[str, Any]:
    flat: dict[str, Any] = {}
    for name in _SECTIONS:
        flat.update(user_input.get(name, {}))
    for key in (
        CONF_POLL_INTERVAL,
        CONF_SYSLOG_PORT,
        CONF_BRUTE_FORCE_THRESHOLD,
        CONF_BRUTE_FORCE_WINDOW,
        CONF_PORT_SCAN_THRESHOLD,
        CONF_PORT_SCAN_WINDOW,
        CONF_UNDER_ATTACK_THRESHOLD,
        CONF_RETENTION_DAYS,
    ):
        if key in flat:
            flat[key] = int(flat[key])
    return flat


def _validate(hass: HomeAssistant, options: dict[str, Any]) -> dict[str, str]:
    """Blocking validation (runs in the executor). Returns ``{section: error}``."""
    errors: dict[str, str] = {}
    for path in split_lines(options.get(CONF_LOG_PATHS)):
        if not os.path.isabs(path):
            errors[SECTION_SOURCES] = "path_not_absolute"
        elif not hass.config.is_allowed_path(path):
            errors[SECTION_SOURCES] = "path_not_allowed"
        elif not os.path.isfile(path) or not os.access(path, os.R_OK):
            errors[SECTION_SOURCES] = "path_not_readable"
        if SECTION_SOURCES in errors:
            break
    try:
        parse_networks(options.get(CONF_SYSLOG_ALLOWED))
    except ValueError:
        errors[SECTION_SYSLOG] = "invalid_network"
    try:
        parse_networks(options.get(CONF_IGNORED_NETWORKS))
    except ValueError:
        errors[SECTION_DETECTION] = "invalid_network"
    return errors


class SentinelConfigFlow(ConfigFlow, domain=DOMAIN):
    """Initial setup: one instance, sensible defaults."""

    VERSION = 1

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        if user_input is not None:
            options = {**DEFAULT_OPTIONS, **user_input}
            options[CONF_RETENTION_DAYS] = int(options[CONF_RETENTION_DAYS])
            return self.async_create_entry(title=NAME, data={}, options=options)

        schema = vol.Schema(
            {
                vol.Required(CONF_MONITOR_HA_AUTH, default=True): BooleanSelector(),
                vol.Required(CONF_RETENTION_DAYS, default=DEFAULT_OPTIONS[CONF_RETENTION_DAYS]): _num(
                    1, 3650, "d"
                ),
            }
        )
        return self.async_show_form(step_id="user", data_schema=schema)

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> SentinelOptionsFlow:
        return SentinelOptionsFlow()


class SentinelOptionsFlow(OptionsFlowWithReload):
    """All tunables; saving reloads the integration."""

    async def async_step_init(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        current = {**DEFAULT_OPTIONS, **self.config_entry.options}
        errors: dict[str, str] = {}
        if user_input is not None:
            candidate = {**current, **_flatten(user_input)}
            errors = await self.hass.async_add_executor_job(_validate, self.hass, candidate)
            if not errors:
                return self.async_create_entry(data=candidate)
            current = candidate

        return self.async_show_form(step_id="init", data_schema=_options_schema(current), errors=errors)
