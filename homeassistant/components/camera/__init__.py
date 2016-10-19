# pylint: disable=too-many-lines
"""
Component to interface with cameras.

For more details about this component, please refer to the documentation at
https://home-assistant.io/components/camera/
"""
import asyncio
import logging
import time

from aiohttp import web

from homeassistant.helpers.entity import Entity
from homeassistant.helpers.entity_component import EntityComponent
from homeassistant.helpers.config_validation import PLATFORM_SCHEMA  # noqa
from homeassistant.components.http import HomeAssistantView
from homeassistant.util.asyncio import run_coroutine_threadsafe

DOMAIN = 'camera'
DEPENDENCIES = ['http']
SCAN_INTERVAL = 30
ENTITY_ID_FORMAT = DOMAIN + '.{}'

STATE_RECORDING = 'recording'
STATE_STREAMING = 'streaming'
STATE_IDLE = 'idle'

ENTITY_IMAGE_URL = '/api/camera_proxy/{0}?token={1}'


# pylint: disable=too-many-branches
def setup(hass, config):
    """Setup the camera component."""
    component = EntityComponent(
        logging.getLogger(__name__), DOMAIN, hass, SCAN_INTERVAL)

    hass.wsgi.register_view(CameraImageView(hass, component.entities))
    hass.wsgi.register_view(CameraMjpegStream(hass, component.entities))

    component.setup(config)

    return True


class Camera(Entity):
    """The base class for camera entities."""

    def __init__(self):
        """Initialize a camera."""
        self.is_streaming = False

    @property
    def access_token(self):
        """Access token for this camera."""
        return str(id(self))

    @property
    def should_poll(self):
        """No need to poll cameras."""
        return False

    @property
    def entity_picture(self):
        """Return a link to the camera feed as entity picture."""
        return ENTITY_IMAGE_URL.format(self.entity_id, self.access_token)

    @property
    def is_recording(self):
        """Return true if the device is recording."""
        return False

    @property
    def brand(self):
        """Camera brand."""
        return None

    @property
    def model(self):
        """Camera model."""
        return None

    def camera_image(self):
        """Return bytes of camera image."""
        return run_coroutine_threadsafe(
            self.async_camera_image(), self.hass.loop).result()

    @asyncio.coroutine
    def async_camera_image(self):
        """Return bytes of camera image."""
        raise NotImplementedError()

    def mjpeg_stream(self):
        """Generate an HTTP MJPEG stream from camera images."""
        return run_coroutine_threadsafe(
            self.async_mjpeg_stream(), self.hass.loop).result()

    @asyncio.coroutine
    def async_mjpeg_stream(self):
        """Generate an HTTP MJPEG stream from camera images."""
        return (
            FakeMjpegStream(self),
            'multipart/x-mixed-replace; boundary=--jpegboundary'
        )

    @property
    def state(self):
        """Camera state."""
        if self.is_recording:
            return STATE_RECORDING
        elif self.is_streaming:
            return STATE_STREAMING
        else:
            return STATE_IDLE

    @property
    def state_attributes(self):
        """Camera state attributes."""
        attr = {
            'access_token': self.access_token,
        }

        if self.model:
            attr['model_name'] = self.model

        if self.brand:
            attr['brand'] = self.brand

        return attr


class FakeMjpegStream(object):
    """Fake a file read object for mjpeg streams."""

    def __init__(self, entity):
        """Init fake mjpeg stream object."""
        self.entity = entity
        self.last_image = None

    @asyncio.coroutine
    def read(self, ignore):
        """Stream images as mjpeg stream."""
        img_bytes = yield from self.entity.async_camera_image()

        if img_bytes is not None and img_bytes != last_image:
            img_bytes =  bytes(
                '--jpegboundary\r\n'
                'Content-Type: image/jpeg\r\n'
                'Content-Length: {}\r\n\r\n'.format(
                        len(img_bytes)), 'utf-8') + img_bytes + b'\r\n'

            last_image = img_bytes
        return last_image

    @asyncio.coroutine
    def close(self):
        """Close fake stream."""
        return


class CameraView(HomeAssistantView):
    """Base CameraView."""

    requires_auth = False

    def __init__(self, hass, entities):
        """Initialize a basic camera view."""
        super().__init__(hass)
        self.entities = entities

    @asyncio.coroutine
    def get(self, request, entity_id):
        """Start a get request."""
        camera = self.entities.get(entity_id)

        if camera is None:
            return web.Response(status=404)

        authenticated = (request.authenticated or
                         request.GET.get('token') == camera.access_token)

        if not authenticated:
            return web.Response(status=401)

        response = yield from self.handle(request, camera)
        return response

    @asyncio.coroutine
    def handle(self, camera):
        """Hanlde the camera request."""
        raise NotImplementedError()


class CameraImageView(CameraView):
    """Camera view to serve an image."""

    url = "/api/camera_proxy/{entity_id}"
    name = "api:camera:image"

    @asyncio.coroutine
    def handle(self, request, camera):
        """Serve camera image."""
        image = yield from camera.async_camera_image()

        if image is None:
            return web.Response(status=500)

        return web.Response(body=image)


class CameraMjpegStream(CameraView):
    """Camera View to serve an MJPEG stream."""

    url = "/api/camera_proxy_stream/{entity_id}"
    name = "api:camera:stream"

    @asyncio.coroutine
    def handle(self, request, camera):
        """Serve camera image."""
        response = web.StreamResponse()

        (stream, content) = yield from camera.async_mjpeg_stream()
        if stream is None:
            return web.Response(status=500)

        # init header
        response.content_type = content
        response.enable_chunked_encoding()

        response.prepare(request)
        while True:
            try:
                data = yield from stream.read(512)
                if not data:
                    break
                response.write(data)
            # pylint: disable=broad-except
            except Exception as err:
                _LOGGER.debug("Exception on stream sending.", exc_info=True)
                break

        yield from asyncio.gather(
            [stream.close(), response.write_eof()], loop=self.hass.loop)
        return response
