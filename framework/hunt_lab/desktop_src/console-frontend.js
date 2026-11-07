/* Authored QEMU console UI. Bundled with unmodified noVNC 1.6.0 at release time. */
'use strict';

const status = document.getElementById('console-status');
const screen = document.getElementById('console-screen');
const focus = document.getElementById('console-focus');
const endpoint = document.body.dataset.consoleWebsocket;
const match = /^ws:\/\/127\.0\.0\.1:([1-9]\d{0,4})\/$/.exec(endpoint || '');
let rfb = null;

function fail(message) {
  status.textContent = message;
  focus.disabled = true;
}

if (!match || Number(match[1]) > 65535) {
  fail('Console refused: invalid loopback WebSocket endpoint.');
} else {
  try {
    rfb = new RFB(screen, endpoint, { shared: true });
    rfb.viewOnly = false;
    rfb.scaleViewport = true;
    rfb.resizeSession = false;
    rfb.focusOnClick = true;
    rfb.showDotCursor = true;
    rfb.addEventListener('connect', () => {
      status.textContent = 'Connected to the real QEMU display. Click the display or Focus console to send keyboard and pointer input to this guest.';
      focus.disabled = false;
    });
    rfb.addEventListener('disconnect', event => {
      fail(event.detail.clean
        ? 'QEMU console disconnected. Refresh the owning profile status explicitly to open a new console connection.'
        : 'QEMU console connection failed or closed unexpectedly. Refresh the owning profile status explicitly; no alternate viewer or automatic retry was used.');
    });
    rfb.addEventListener('credentialsrequired', () => {
      rfb.disconnect();
      fail('Console refused: this local QEMU console unexpectedly requested credentials. No credentials were read or supplied.');
    });
    rfb.addEventListener('securityfailure', () => {
      fail('QEMU console security negotiation failed. No alternate endpoint was used.');
    });
    focus.addEventListener('click', () => rfb.focus());
    window.addEventListener('pagehide', () => rfb.disconnect(), { once: true });
  } catch {
    if (rfb) rfb.disconnect();
    fail('The embedded QEMU console could not initialize. No external viewer, service, or Bot Screen fallback was opened.');
  }
}
