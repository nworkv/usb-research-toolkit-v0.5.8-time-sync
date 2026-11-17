#!/usr/bin/env python3
"""Unit tests for maximal USBPcap descriptor inventory reconstruction."""
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("usb_report_reconstruction", ROOT / "scripts/report-usb-campaign.py")
REPORTER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPORTER)


def main():
    # Device descriptor, a complete 9-byte configuration header and one HID report descriptor.
    device = bytes.fromhex("12 01 00 02 00 00 00 40 34 12 78 56 00 01 01 02 03 01")
    config = bytes.fromhex("09 02 09 00 00 01 00 80 32")
    hid_report = bytes.fromhex("05 01 09 06 A1 01 C0")
    catalogue = [
        {"type": 1, "index": 0, "language_id": 0, "interface": None,
         "name": "Device", "expected_hex": device.hex()},
        {"type": 2, "index": 0, "language_id": 0, "interface": None,
         "name": "Configuration", "expected_hex": config.hex()},
        {"type": 34, "index": 0, "language_id": 0, "interface": 0,
         "name": "HID Report", "expected_hex": hid_report.hex()},
        {"type": 3, "index": 2, "language_id": 0x0409, "interface": None,
         "name": "Product String", "expected_hex": "".encode().hex()},
    ]
    def tx(dtype, index, payload, interface=None, lang=0, frames=None, req_len=None):
        return {"descriptor_type": dtype, "descriptor_index": index, "language_id": lang,
                "interface": interface, "actual_hex": payload.hex(), "frames": frames or [1],
                "host_transfer_status": "COMPLETED", "request": {"wLength": req_len or len(payload)},
                "result": "MATCH"}
    transactions = [tx(1, 0, device), tx(2, 0, config), tx(34, 0, hid_report, interface=0)]
    result = REPORTER.reconstruct_host_configuration(transactions, catalogue)
    assert result["host_ids"] == {"vid": "0x1234", "pid": "0x5678"}
    by_type = {tuple(x["key"]): x for x in result["entries"]}
    assert by_type[(1, 0, 0, None)]["result"] == "IDENTICAL"
    assert by_type[(2, 0, 0, None)]["result"] == "IDENTICAL"
    assert by_type[(34, 0, 0, 0)]["result"] == "IDENTICAL"
    assert by_type[(3, 2, 0x0409, None)]["state"] == "NOT_REQUESTED"
    html = REPORTER.configuration_comparison_html(result)
    assert "EXPECTED VID/PID" in html and "HOST RECEIVED VID/PID" in html
    assert "NOT_REQUESTED" in html

    # Full-PCAP inventory is deliberately independent of per-case time windows.
    # These six early enumeration transactions must remain visible even when they
    # precede the first fuzz case.
    early_groups = []
    for frame, payload in enumerate((device, config, hid_report, device, config, hid_report), 1):
        dtype = payload[1] if len(payload) > 1 else 1
        early_groups.append({
            "request": {"bmRequestType": 0x80, "bRequest": 6, "wValue": dtype << 8,
                        "wIndex": 0, "wLength": len(payload)},
            "payload": payload, "frame_numbers": [frame], "time_epoch": 100.0 + frame,
            "bus_id": 1, "device_address": 4, "urb_id": str(frame),
            "status": "COMPLETED", "complete_seen": True,
        })
    inventory = REPORTER.build_host_capture_inventory(early_groups)
    assert inventory["get_descriptor_count"] == 6
    assert inventory["devices"][0]["vid_pid"] == {"vid": "0x1234", "pid": "0x5678"}
    assert inventory["devices"][0]["transactions"][0]["frames"] == [1]
    inventory_html = REPORTER.host_inventory_html(inventory)
    assert "Frame" in inventory_html and "12010002" in inventory_html
    assert "Request HEX" in inventory_html and "8006000100001200" in inventory_html

    # USBPcap setup requests with no completion must never be reported as a response.
    missing = REPORTER.build_transfer_groups([{
        "frame_number": 99, "time_epoch": 101.0, "bus_id": 1, "device_address": 1,
        "irp_id": "0xabc", "urb_function": "URB_FUNCTION_GET_DESCRIPTOR_FROM_DEVICE",
        "control_stage": "0", "request": {"bmRequestType": 128, "bRequest": 6,
        "wValue": 0x0100, "wIndex": 0, "wLength": 18}, "urb_status": None,
        "get_descriptor_response": None, "control_response": None,
        "data_fragment": None, "capdata": None
    }])
    assert len(missing) == 1 and missing[0]["status"] == "NO_COMPLETION"
    assert missing[0]["payload"] is None
    # A changed endpoint/config byte must be reported as a difference.
    changed = bytearray(config)
    changed[8] = 0x40
    changed_result = REPORTER.reconstruct_host_configuration([tx(2, 0, bytes(changed))], catalogue[1:2])
    assert changed_result["different_count"] == 1
    malformed_iface = bytes.fromhex("09 02 22 00 01 01 00 80 19 09 04 99 00 01 03 00 00 00 09 21 11 01 00 01 22 3e 00 07 05 81 03 04 00 0a")
    decoded = REPORTER.describe_descriptor(2, malformed_iface)
    assert any("bInterfaceNumber=153" in line and "INVALID" in line for line in decoded), decoded
    short_iface = bytes.fromhex("09 02 11 00 01 01 00 80 19 08 04 00 00 01 03 00 00")
    decoded_short = REPORTER.describe_descriptor(2, short_iface)
    assert any("Interface descriptor" in line and "requires 9 bytes" in line for line in decoded_short), decoded_short
    print("test_usb_configuration_reconstruction: PASS")


if __name__ == "__main__":
    main()
