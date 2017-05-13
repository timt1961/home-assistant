"""The tests for the  Template cover platform."""
import asyncio
import unittest
from homeassistant.core import State, CoreState
from homeassistant import setup
from homeassistant.const import STATE_OPEN, STATE_CLOSED, STATE_UNKNOWN
from homeassistant.helpers.restore_state import DATA_RESTORE_CACHE
from homeassistant.setup import setup_component
import homeassistant.components.cover as cover

from tests.common import (
    get_test_home_assistant, assert_setup_component, mock_component)


class TestTemplateCover(unittest.TestCase):
    """Test the Template cover."""

    def setup_method(self, method):  # pylint: disable=invalid-name
        """Setup things to be run when tests are started."""
        self.hass = get_test_home_assistant()
        self.assertTrue(setup_component(self.hass, cover.DOMAIN, {'cover': {
            'platform': 'template',
        }}))

    def teardown_method(self, method):  # pylint: disable=invalid-name
        """Stop everything that was started."""
        self.hass.stop()

    def should_poll(self):
        """Test the polling setting."""
        templ_cover = templ.CoverTemplate(self.hass, 'foo',
                                          'open_cover', 'close_cover',
                                          'stop_cover', 'cover.test_state')

        self.assertFalse(templ_cover.should_poll)
                            
    def test_template_state_text(self):
        """"Test the state text of a template."""
        with assert_setup_component(1):
            assert setup.setup_component(self.hass, 'cover', {
                'cover': {
                    'platform': 'template',
                    'covers': {
                        'test_template_cover': {
                            'value_template':
                                "{{ states.cover.test_state.state }}",
                            'open_cover': {
                                'service': 'cover.open_cover',
                                'entity_id': 'cover.test_state'
                            },
                            'close_cover': {
                                'service': 'cover.close_cover',
                                'entity_id': 'cover.test_state'
                            },
                            'stop_cover': {
                                'service': 'cover.stop_cover',
                                'entity_id': 'cover.test_state'
                            },
                        }
                    }
                }
            })

        self.hass.start()
        self.hass.block_till_done()

        state = self.hass.states.set('cover.test_state', STATE_OPEN)
        self.hass.block_till_done()

        state = self.hass.states.get('cover.test_template_cover')
        assert state.state == STATE_OPEN

        state = self.hass.states.set('cover.test_state', STATE_CLOSED)
        self.hass.block_till_done()

        state = self.hass.states.get('cover.test_template_cover')
        assert state.state == STATE_CLOSE

        state = self.hass.states.set('cover.test_state', STATE_UNKNOWN)
        self.hass.block_till_done()

        state = self.hass.states.get('cover.test_template_cover')
        assert state.state == STATE_UNKNOWN

    def test_template_syntax_error(self):
        """Test templating syntax error."""
        with assert_setup_component(0):
            assert setup.setup_component(self.hass, 'cover', {
                'cover': {
                    'platform': 'template',
                    'covers': {
                        'test_template_cover': {
                            'value_template':
                                "{% if rubbish %}",
                            'open_cover': {
                                'service': 'cover.open_cover',
                                'entity_id': 'cover.test_state'
                            },
                            'turn_off': {
                                'service': 'cover.close_cover',
                                'entity_id': 'cover.test_state'
                            },
                        }
                    }
                }
            })

        self.hass.start()
        self.hass.block_till_done()

        assert self.hass.states.all() == []

    def test_invalid_name_does_not_create(self):
        """Test invalid name."""
        with assert_setup_component(0):
            assert setup.setup_component(self.hass, 'cover', {
                'cover': {
                    'platform': 'template',
                    'covers': {
                        'test INVALID cover': {
                            'value_template':
                                "{{ rubbish }",
                            'close_cover': {
                                'service': 'cover.close_cover',
                                'entity_id': 'cover.test_state'
                            },
                            'open_cover': {
                                'service': 'cover.open_cover',
                                'entity_id': 'cover.test_state'
                            },
                        }
                    }
                }
            })

        self.hass.start()
        self.hass.block_till_done()

        assert self.hass.states.all() == []

    def test_invalid_cover_does_not_create(self):
        """Test invalid cover."""
        with assert_setup_component(0):
            assert setup.setup_component(self.hass, 'cover', {
                'cover': {
                    'platform': 'template',
                    'covers': {
                        'test_template_cover': 'Invalid'
                    }
                }
            })

        self.hass.start()
        self.hass.block_till_done()

        assert self.hass.states.all() == []

    def test_no_covers_does_not_create(self):
        """Test if there are no covers no creation."""
        with assert_setup_component(0):
            assert setup.setup_component(self.hass, 'cover', {
                'cover': {
                    'platform': 'template'
                }
            })

        self.hass.start()
        self.hass.block_till_done()

        assert self.hass.states.all() == []

    def test_missing_template_does_not_create(self):
        """Test missing template."""
        with assert_setup_component(0):
            assert setup.setup_component(self.hass, 'cover', {
                'cover': {
                    'platform': 'template',
                    'covers': {
                        'test_template_cover': {
                            'not_value_template':
                                "{{ states.cover.test_state.state }}",
                            'close_cover': {
                                'service': 'cover.close_cover',
                                'entity_id': 'cover.test_state'
                            },
                            'open_cover': {
                                'service': 'cover.open_cover',
                                'entity_id': 'cover.test_state'
                            },
                        }
                    }
                }
            })

        self.hass.start()
        self.hass.block_till_done()

        assert self.hass.states.all() == []

@asyncio.coroutine
def test_restore_state(hass):
    """Ensure states are restored on startup."""
    hass.data[DATA_RESTORE_CACHE] = {
        'cover.test_template_cover':
            State('cover.test_template_cover', 'on'),
    }

    hass.state = CoreState.starting
    mock_component(hass, 'recorder')

    yield from setup.async_setup_component(hass, 'cover', {
        'cover': {
            'platform': 'template',
            'covers': {
                'test_template_cover': {
                    'value_template':
                        "{{ states.cover.test_state.state }}",
                    'close_cover': {
                        'service': 'cover.close_cover',
                        'entity_id': 'cover.test_state'
                    },
                    'open_cover': {
                        'service': 'cover.open_cover',
                        'entity_id': 'cover.test_state'
                    },
                }
            }
        }
    })

    state = hass.states.get('cover.test_template_cover')
    assert state.state == 'on'

    yield from hass.async_start()
    yield from hass.async_block_till_done()

    state = hass.states.get('cover.test_template_cover')
    assert state.state == 'unavailable'
