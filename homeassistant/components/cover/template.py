"""
Support for covers which integrates with other components.

For more details about this platform, please refer to the documentation at
https://home-assistant.io/components/switch.template/
"""
import asyncio
import logging

import voluptuous as vol

from homeassistant.core import callback
from homeassistant.components.cover import (
    ENTITY_ID_FORMAT, CoverDevice, PLATFORM_SCHEMA)
from homeassistant.const import (
    ATTR_FRIENDLY_NAME, CONF_VALUE_TEMPLATE, STATE_OPEN, STATE_CLOSED,
    STATE_UNKNOWN, ATTR_ENTITY_ID, CONF_COVERS, EVENT_HOMEASSISTANT_START)
from homeassistant.exceptions import TemplateError
import homeassistant.helpers.config_validation as cv
from homeassistant.helpers.entity import async_generate_entity_id
from homeassistant.helpers.event import async_track_state_change
from homeassistant.helpers.restore_state import async_get_last_state
from homeassistant.helpers.script import Script

_LOGGER = logging.getLogger(__name__)
_VALID_STATES = [STATE_OPEN, STATE_CLOSED, STATE_UNKNOWN, 'true', 'false']

OPEN_ACTION = 'open_cover'
CLOSE_ACTION = 'close_cover'
STOP_ACTION = 'stop_cover'

COVER_SCHEMA = vol.Schema({
    vol.Required(CONF_VALUE_TEMPLATE): cv.template,
    vol.Optional(OPEN_ACTION): cv.SCRIPT_SCHEMA,
    vol.Optional(CLOSE_ACTION): cv.SCRIPT_SCHEMA,
    vol.Optional(STOP_ACTION): cv.SCRIPT_SCHEMA,
    vol.Optional(ATTR_FRIENDLY_NAME): cv.string,
    vol.Optional(ATTR_ENTITY_ID): cv.entity_ids
})

PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend({
    vol.Required(CONF_COVERS): vol.Schema({cv.slug: COVER_SCHEMA}),
})


@asyncio.coroutine
# pylint: disable=unused-argument
def async_setup_platform(hass, config, async_add_devices, discovery_info=None):
    """Setup the Template cover."""
    covers = []

    for device, device_config in config[CONF_COVERS].items():
        friendly_name = device_config.get(ATTR_FRIENDLY_NAME, device)
        state_template = device_config[CONF_VALUE_TEMPLATE]
        close_action = device_config[CLOSE_ACTION]
        open_action = device_config[OPEN_ACTION]
        stop_action = device_config[STOP_ACTION]
        entity_ids = (device_config.get(ATTR_ENTITY_ID) or
                      state_template.extract_entities())

        state_template.hass = hass
        covers.append(
            CoverTemplate(
                hass,
                device,
                friendly_name,
                state_template,
                close_action,
                open_action,
                stop_action,
                entity_ids)
            )
    if not covers:
        return False

    async_add_devices(covers, True)
    return True


class CoverTemplate(CoverDevice):
    """Representation of a Template Cover."""

    def __init__(self, hass, device_id, friendly_name, state_template,
                 close_action, open_action, stop_action, entity_ids):
        """Initialize the Template cover."""
        _LOGGER.info("CoverTemplate called")

        self.hass = hass
        self.entity_id = async_generate_entity_id(ENTITY_ID_FORMAT, device_id,
                                                  hass=hass)
        self._name = friendly_name
        self._template = state_template
        self._close_script = Script(hass, close_action)
        self._open_script = Script(hass, open_action)
        self._stop_script = Script(hass, stop_action)
        self._state = False
        self._position = None
        self._tilt_position = None
        self._entities = entity_ids

    @asyncio.coroutine
    def async_added_to_hass(self):
        """Register callbacks."""
        state = yield from async_get_last_state(self.hass, self.entity_id)
        if state:
            self._state = state.state == STATE_UNKNOWN

        @callback
        def template_cover_state_listener(entity, old_state, new_state):
            """Called when the target device changes state."""
            self.hass.async_add_job(self.async_update_ha_state(True))

        @callback
        def template_cover_startup(event):
            """Update template on startup."""
            async_track_state_change(
                self.hass, self._entities, template_cover_state_listener)

            self.hass.async_add_job(self.async_update_ha_state(True))

        self.hass.bus.async_listen_once(
            EVENT_HOMEASSISTANT_START, template_cover_startup)

    @property
    def name(self):
        """Return the name of the cover."""
        return self._name

    @property
    def should_poll(self):
        """No polling needed."""
        return False

    @property
    def available(self):
        """If cover is available."""
        return self._state is not None

    def open_cover(self, **kwargs):
        """Fire the on action."""
        self._open_script.run()

    def close_cover(self, **kwargs):
        """Fire the off action."""
        self._close_script.run()

    def stop_cover(self, **kwargs):
        """Fire the stop action."""
        self._stop_script.run()


    @asyncio.coroutine
    def async_update(self):
        """Update the state from the template."""
        try:
            state = self._template.async_render().lower()
            if state in _VALID_STATES:
                self._state = state in ('true', STATE_CLOSED)
            else:
                _LOGGER.error(
                    'Received invalid cover state: %s. Expected: %s',
                    state, ', '.join(_VALID_STATES))
                self._state = None

        except TemplateError as ex:
            _LOGGER.error(ex)
            self._state = None
