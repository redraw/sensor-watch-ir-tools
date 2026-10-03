#!/usr/bin/env python3
"""Set the watch's shared latitude/longitude through Sunrise/Sunset IR mode.

On the watch, open Sunrise/Sunset and long-press Light. Short-press Alarm to
leave IR mode. Coordinates use signed hundredths of a degree, so the sender
rounds decimal degrees to the watch's precision before transmission.
"""

import argparse
import atexit
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
import json
import secrets
import signal
import struct
import sys
import time
from urllib.request import Request, urlopen

from ir_modem import (Modem, handshake, HANDSHAKE_BAUD, RESET_DELAY_S,
                      CMD_TX, CMD_STOP, TX_FLAG_AUTO_RX, MSG_RX, MSG_TX_DONE,
                      MSG_ERR, RX_DIGITAL, RX_ANALOG)
from serial_frame import build_frame

try:
    import serial
except ImportError:
    sys.exit("error: pyserial not installed; install it in the tools' .venv")

LOCATION_FLAG = 0x20
DATA_BAUD = 3600
ACK_BAUD = 300
ser = None
modem = None


def coordinate(value: str, limit: int, name: str) -> int:
    try:
        degrees = Decimal(value)
    except InvalidOperation:
        raise argparse.ArgumentTypeError(f"{name} must be a decimal degree value")
    if not degrees.is_finite() or abs(degrees) > limit:
        raise argparse.ArgumentTypeError(f"{name} must be between -{limit} and {limit}")
    return int((degrees * 100).quantize(Decimal(1), rounding=ROUND_HALF_UP))


def ip_location():
    """Approximate location of this computer's public IP, or None on failure."""
    try:
        request = Request('https://ipapi.co/json/',
                          headers={'User-Agent': 'sensor-watch-ir-tools/location_sender'})
        with urlopen(request, timeout=5) as response:
            data = json.load(response)
        latitude = coordinate(str(data['latitude']), 90, 'latitude')
        longitude = coordinate(str(data['longitude']), 180, 'longitude')
        if latitude == 0 and longitude == 0:
            return None
        place = ', '.join(part for part in
                          (data.get('city'), data.get('region'), data.get('country_name'))
                          if part)
        return latitude, longitude, place
    except (OSError, ValueError, KeyError, TypeError, argparse.ArgumentTypeError):
        return None


def choose_coordinates(args, parser):
    if (args.latitude is None) != (args.longitude is None):
        parser.error('provide both latitude and longitude, or neither for IP lookup')
    if args.latitude is not None:
        try:
            latitude = coordinate(args.latitude, 90, 'latitude')
            longitude = coordinate(args.longitude, 180, 'longitude')
        except argparse.ArgumentTypeError as exc:
            parser.error(str(exc))
    else:
        suggestion = ip_location()
        if suggestion:
            latitude, longitude, place = suggestion
            print(f"IP suggests {place or 'an unknown place'}: "
                  f"{latitude / 100:.2f}, {longitude / 100:.2f}")
            print('IP geolocation is approximate; VPNs may place it elsewhere.')
            try:
                choice = input('Use these coordinates? [y]es / [m]anual: ').strip().lower()
            except EOFError:
                sys.exit('error: confirmation required; supply coordinates explicitly')
            if choice in ('y', 'yes'):
                return latitude, longitude
            if choice not in ('m', 'manual', ''):
                sys.exit('location update cancelled')
        else:
            print('IP location unavailable; enter coordinates manually.')
        try:
            raw_latitude = input('Latitude (-90 to 90, north positive): ').strip()
            raw_longitude = input('Longitude (-180 to 180, east positive): ').strip()
            latitude = coordinate(raw_latitude, 90, 'latitude')
            longitude = coordinate(raw_longitude, 180, 'longitude')
        except EOFError:
            sys.exit('error: coordinates required')
        except argparse.ArgumentTypeError as exc:
            parser.error(str(exc))

    if latitude == 0 and longitude == 0:
        parser.error('0.00, 0.00 is reserved as an unset location by the watch')
    print(f"Location to save: {latitude / 100:.2f}, {longitude / 100:.2f}")
    try:
        confirmed = input('Send this location to the watch? [y/N]: ').strip().lower()
    except EOFError:
        sys.exit('error: confirmation required')
    if confirmed not in ('y', 'yes'):
        sys.exit('location update cancelled')
    return latitude, longitude


def _shutdown():
    global ser, modem
    if ser is None:
        return
    try:
        if ser.is_open:
            if modem is not None:
                modem.send(CMD_STOP)
                time.sleep(0.05)
            ser.close()
    except Exception:
        pass
    ser = None


def _signal_handler(_signum, _frame):
    _shutdown()
    sys.exit(130)


def invert_data_bytes(data: bytes) -> bytes:
    return bytes(byte ^ 0xFF for byte in data)


def send_location(modem: Modem, latitude: int, longitude: int,
                  frame_id: int, timeout: float, retries: int,
                  data_baud: int, rx_invert: bool, tx_invert: bool) -> bool:
    frame = build_frame(b"LOC1" + struct.pack('<hh', latitude, longitude),
                        frame_id, LOCATION_FLAG)
    expected = struct.pack('<H', frame_id)
    if rx_invert:
        frame = invert_data_bytes(frame)
    if tx_invert:
        expected = invert_data_bytes(expected)
    for attempt in range(retries + 1):
        if attempt:
            print(f"no ACK, retransmit {attempt}/{retries}")
        modem.send(CMD_TX, bytes((TX_FLAG_AUTO_RX,)) + frame)
        deadline = time.time() + len(frame) * 10 / data_baud + timeout + 1.0
        window = bytearray()
        while time.time() < deadline:
            msg = modem.read_message(deadline)
            if msg is None:
                break
            mtype, data = msg
            if mtype == MSG_TX_DONE:
                deadline = time.time() + timeout
            elif mtype == MSG_RX:
                window += data
                if expected in window:
                    return True
                del window[:-8]
            elif mtype == MSG_ERR:
                code = data[0] if data else 0
                sys.exit(f"error: modem reported error code {code}")
    return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('latitude', nargs='?', help='Decimal degrees, -90 to 90 (north positive)')
    parser.add_argument('longitude', nargs='?', help='Decimal degrees, -180 to 180 (east positive)')
    parser.add_argument('--device', default='/dev/ttyACM0', help='Modem serial device')
    parser.add_argument('--baud', type=int, default=DATA_BAUD,
                        help=f'Host-to-watch baud; match flasher RX baud (default {DATA_BAUD})')
    parser.add_argument('--ack-baud', type=int, default=ACK_BAUD,
                        help=f'Watch-to-host baud; match flasher TX baud (default {ACK_BAUD})')
    parser.add_argument('--encoding', choices=('nrz', 'irda'), default='nrz',
                        help='Match flasher encoding (default nrz)')
    parser.add_argument('--rx-invert', action='store_true',
                        help='Match the watch flasher RX invert setting (NRZ only)')
    parser.add_argument('--tx-invert', action='store_true',
                        help='Match the watch flasher TX invert setting (NRZ only)')
    parser.add_argument('--digital-rx', action='store_true',
                        help='Use the modem digital receiver instead of analog')
    parser.add_argument('--timeout', type=float, default=1.0,
                        help='ACK wait in seconds (default 1.0)')
    parser.add_argument('--retries', type=int, default=10,
                        help='Retransmissions after first attempt (default 10)')
    args = parser.parse_args()
    if args.timeout <= 0 or args.retries < 0 or args.baud <= 0 or args.ack_baud <= 0:
        parser.error('baud rates and --timeout must be positive; --retries must be nonnegative')
    if args.encoding == 'irda' and (args.rx_invert or args.tx_invert):
        parser.error('data-bit inversion has no effect in IrDA; omit the invert options')
    latitude, longitude = choose_coordinates(args, parser)

    global ser, modem
    atexit.register(_shutdown)
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)
    try:
        ser = serial.Serial(args.device, baudrate=HANDSHAKE_BAUD, timeout=0.1)
    except serial.SerialException as exc:
        sys.exit(f"error: cannot open {args.device}: {exc}")
    print(f"opened {args.device}; waiting {RESET_DELAY_S:.1f}s for modem reset...")
    time.sleep(RESET_DELAY_S)
    ser.reset_input_buffer()
    modem = Modem(ser)
    handshake(modem, args.baud, args.ack_baud, args.encoding,
              RX_DIGITAL if args.digital_rx else RX_ANALOG)
    frame_id = secrets.randbits(16)
    if send_location(modem, latitude, longitude, frame_id,
                     args.timeout, args.retries, args.baud,
                     args.rx_invert, args.tx_invert):
        print(f"location saved: {latitude / 100:.2f}, {longitude / 100:.2f}")
    else:
        sys.exit('error: no ACK; check Sunrise/Sunset IR mode and probe alignment')


if __name__ == '__main__':
    main()
