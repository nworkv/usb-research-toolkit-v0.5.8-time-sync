#!/usr/bin/env python3
"""Unit/integration tests for report-usb-campaign.py using a fake tshark."""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path(__file__).resolve().parents[1] / "scripts/report-usb-campaign.py"
ROOT = SCRIPT.resolve().parents[1]
spec = importlib.util.spec_from_file_location("campaign_byte_report", SCRIPT)
reporter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reporter)
verifier_spec = importlib.util.spec_from_file_location("verify_usb_case", ROOT / "scripts/verify-usb-case.py")
verifier = importlib.util.module_from_spec(verifier_spec)
verifier_spec.loader.exec_module(verifier)

FIELDS = [
    "frame.number", "frame.time_epoch", "usb.bus_id", "usb.device_address", "usb.urb_id",
    "usb.irp_id", "usb.urb_function", "usb.control_stage", "usb.data_fragment", "usb.urb_type", "usb.usbd_status", "usb.endpoint_address", "usb.transfer_type", "usb.urb_status",
    "usb.bmRequestType", "usb.setup.bRequest", "usb.setup.wValue", "usb.setup.wIndex",
    "usb.setup.wLength", "usb.data_len", "usb.capdata", "usb.control.Response",
    "usb.getDescriptor.Response", "usb.idVendor", "usb.idProduct",
]


def rows_for_descriptor(payload_hex):
    def base(frame, timestamp, urb, typ):
        row = {f: "" for f in FIELDS}
        row.update({"frame.number": str(frame), "frame.time_epoch": str(timestamp), "usb.bus_id": "1",
                    "usb.device_address": "0", "usb.urb_id": str(urb), "usb.urb_type": typ,
                    "usb.endpoint_address": "0", "usb.urb_status": "", "usb.data_len": ""})
        return row
    out = []
    r = base(1, 1001.0, 123, "S")
    r.update({"usb.bmRequestType": "128", "usb.setup.bRequest": "6", "usb.setup.wValue": "256",
              "usb.setup.wIndex": "0", "usb.setup.wLength": "64"})
    out.append(r)
    r = base(2, 1001.01, 123, "C")
    r.update({"usb.urb_status": "0", "usb.getDescriptor.Response": payload_hex,
              "usb.data_len": str(len(payload_hex.split(":")))})
    out.append(r)
    r = base(3, 1002.0, 124, "S")
    r.update({"usb.bmRequestType": "0", "usb.setup.bRequest": "9", "usb.setup.wValue": "1",
              "usb.setup.wIndex": "0", "usb.setup.wLength": "0"})
    out.append(r)
    r = base(4, 1002.01, 124, "C")
    r.update({"usb.urb_status": "0"})
    out.append(r)
    return out


def main():
    with tempfile.TemporaryDirectory(prefix="usb-byte-report-test-") as td:
        temp = Path(td)
        campaign = temp / "campaign"
        traces = campaign / "traces"
        traces.mkdir(parents=True)
        profile_source = ROOT / "profiles/valid/minimal-device.json"
        profile_path = campaign / "case-00001.json"
        shutil.copyfile(profile_source, profile_path)
        profile = json.loads(profile_path.read_text())
        expected = verifier.build_expected_descriptors(profile)[(1, 0, 0)]
        trace_path = traces / "case-00001.device.jsonl"
        trace_events = [
            {"sequence": 1, "event": "CONTROL_REQUEST", "timestamp_wall_ns": 1001000000000, "request": {"bmRequestType": 128, "bRequest": 6, "wValue": 256, "wIndex": 0, "wLength": 64}},
            {"sequence": 2, "event": "CONTROL_RESPONSE_COMPLETE", "timestamp_wall_ns": 1001010000000, "request": {"bmRequestType": 128, "bRequest": 6, "wValue": 256, "wIndex": 0, "wLength": 64}, "payload_hex": expected.hex(), "actual_length": len(expected), "status": "completed"},
            {"sequence": 3, "event": "SET_CONFIGURATION", "timestamp_wall_ns": 1002000000000, "configuration_value": 1},
        ]
        trace_path.write_text("\n".join(json.dumps(x) for x in trace_events) + "\n")
        (campaign / "campaign.jsonl").write_text(json.dumps({
            "case": 1, "status": "COMPLETED", "started_epoch": 1000.0, "ended_epoch": 1010.0,
            "duration_seconds": 10.0, "profile": str(profile_path), "trace": str(trace_path),
            "profile_sha256": "test-sha", "changes": ["$.device.idProduct: 1 -> 2"]
        }) + "\n")

        fake_tshark = temp / "fake-tshark"
        fake_tshark.write_text("""#!/usr/bin/env python3
import csv, json, sys
from pathlib import Path
FIELDS = %r
if '-G' in sys.argv:
    for f in FIELDS:
        print('F\\t' + f + '\\t' + f + '\\tFT_STRING\\tusb\\t0x0')
    raise SystemExit(0)
pcap = Path(sys.argv[sys.argv.index('-r') + 1])
rows = json.loads(pcap.read_text())
chosen = [sys.argv[i+1] for i,x in enumerate(sys.argv[:-1]) if x == '-e']
w = csv.writer(sys.stdout, delimiter='\\t', lineterminator='\\n', quoting=csv.QUOTE_MINIMAL)
w.writerow(chosen)
for r in rows:
    w.writerow([r.get(f, '') for f in chosen])
""" % FIELDS, encoding="utf-8")
        fake_tshark.chmod(0o755)
        good_pcap = temp / "good.pcapng"
        good_pcap.write_text(json.dumps(rows_for_descriptor(":".join(f"{x:02x}" for x in expected))))
        run = subprocess.run([sys.executable, str(SCRIPT), "--campaign-dir", str(campaign),
                              "--host-pcap", str(good_pcap), "--tshark", str(fake_tshark)],
                             text=True, capture_output=True)
        assert run.returncode == 0, run.stdout + "\n" + run.stderr
        data = json.loads((campaign / "protocol-report.json").read_text())
        assert data["cases"][0]["verdict"] == "EXPECTED_DESCRIPTOR_BYTES_MATCH_CONFIGURED_OBSERVED", data["cases"][0]["verdict"]
        transaction = data["cases"][0]["descriptor_transactions"][0]
        assert transaction["result"] == "MATCH"
        assert transaction["three_way_status"] == "ALL_THREE_BYTE_STREAMS_MATCH", transaction
        assert transaction["device_trace_payload_hex"] == expected.hex()
        assert transaction["device_vs_host"]["status"] == "MATCH"
        assert (campaign / "protocol-report.txt").is_file()
        txt = (campaign / "protocol-report.txt").read_text()
        assert "DEVICE TRACE / Raw Gadget payload (HEX)" in txt
        assert "THREE-WAY STATUS: ALL_THREE_BYTE_STREAMS_MATCH" in txt
        html = (campaign / "protocol-report.html").read_text()
        assert "ОЖИДАЛОСЬ — JSON PROFILE" in html
        assert "ОТПРАВЛЕНО — RAW GADGET TRACE" in html
        assert "ПОЛУЧЕНО — WINDOWS USBPcap" in html

        # End-to-end fake tshark output in native Windows USBPcap form.
        setup_row = {f: "" for f in FIELDS}
        setup_row.update({"frame.number": "7", "frame.time_epoch": "1001.0", "usb.bus_id": "1",
            "usb.device_address": "1", "usb.irp_id": "0xffff8308136eba80",
            "usb.urb_function": "URB_FUNCTION_GET_DESCRIPTOR_FROM_DEVICE (0x000b)",
            "usb.control_stage": "0", "usb.bmRequestType": "128", "usb.setup.bRequest": "6",
            "usb.setup.wValue": "256", "usb.setup.wIndex": "0", "usb.setup.wLength": str(len(expected))})
        complete_row = {f: "" for f in FIELDS}
        complete_row.update({"frame.number": "8", "frame.time_epoch": "1001.001", "usb.bus_id": "1",
            "usb.device_address": "1", "usb.irp_id": "0xffff8308136eba80",
            "usb.urb_function": "URB_FUNCTION_CONTROL_TRANSFER (0x0008)",
            "usb.control_stage": "3", "usb.usbd_status": "USBD_STATUS_SUCCESS (0x00000000)",
            "usb.data_len": str(len(expected)),
            "usb.getDescriptor.Response": ":".join(f"{x:02x}" for x in expected)})
        usbpcap_pcap = temp / "usbpcap.pcapng"
        usbpcap_pcap.write_text(json.dumps([setup_row, complete_row]))
        run = subprocess.run([sys.executable, str(SCRIPT), "--campaign-dir", str(campaign),
                              "--host-pcap", str(usbpcap_pcap), "--tshark", str(fake_tshark),
                              "--out-prefix", str(campaign / "usbpcap-report")],
                             text=True, capture_output=True)
        assert run.returncode == 0, run.stdout + "\\n" + run.stderr
        usbpcap_report = json.loads((campaign / "usbpcap-report.json").read_text())
        inventory = usbpcap_report["host_capture_inventory"]
        assert inventory["get_descriptor_count"] == 1, inventory
        tx = inventory["devices"][0]["transactions"][0]
        assert tx["frames"] == [7, 8] and tx["actual_hex"] == expected.hex(), tx
        assert tx["setup_hex"] == "800600010000" + f"{len(expected):04x}"[-2:] + "00"

        bad_bytes = bytearray(expected)
        bad_bytes[8] ^= 0x01
        bad_pcap = temp / "bad.pcapng"
        bad_pcap.write_text(json.dumps(rows_for_descriptor(":".join(f"{x:02x}" for x in bad_bytes))))
        run = subprocess.run([sys.executable, str(SCRIPT), "--campaign-dir", str(campaign),
                              "--host-pcap", str(bad_pcap), "--tshark", str(fake_tshark),
                              "--out-prefix", str(campaign / "mismatch-report")],
                             text=True, capture_output=True)
        assert run.returncode == 0, run.stdout + "\n" + run.stderr
        bad = json.loads((campaign / "mismatch-report.json").read_text())
        assert bad["cases"][0]["verdict"] == "HOST_BYTES_MISMATCH_DEVICE_TRACE"
        assert bad["cases"][0]["descriptor_transactions"][0]["first_diff_offset"] == 8
        assert bad["cases"][0]["descriptor_transactions"][0]["three_way_status"] == "HOST_BYTES_MISMATCH_DEVICE_TRACE"

        # Endpoint IN payloads compare profile expectation -> device trace -> host capture.
        endpoint_profile = {"endpoint_io": {"in_payloads": {"129": "01020304"}}}
        endpoint_events = [{"event": "DEVICE_IN_TRANSFER_COMPLETE", "sequence": 7,
                            "timestamp_wall_ns": 1003000000000, "endpoint_address": 129,
                            "direction": "device_to_host", "payload_hex": "01020304",
                            "actual_length": 4, "status": "completed"}]
        endpoint_trace = reporter.device_trace_data_transfers(endpoint_events, endpoint_profile)
        assert endpoint_trace[0]["expected_payload_hex"] == "01020304"
        assert endpoint_trace[0]["expected_vs_trace_status"] == "MATCH"

        # A device-side descriptor payload mismatch is distinguished from a host-side mismatch.
        mutated_trace_events = list(trace_events)
        mutated = bytearray(expected)
        mutated[4] ^= 0x80
        mutated_trace_events[1] = dict(mutated_trace_events[1], payload_hex=mutated.hex())
        trace_path.write_text("\n".join(json.dumps(x) for x in mutated_trace_events) + "\n")
        run = subprocess.run([sys.executable, str(SCRIPT), "--campaign-dir", str(campaign),
                              "--host-pcap", str(good_pcap), "--tshark", str(fake_tshark),
                              "--out-prefix", str(campaign / "device-mismatch-report")],
                             text=True, capture_output=True)
        assert run.returncode == 0, run.stdout + "\n" + run.stderr
        device_bad = json.loads((campaign / "device-mismatch-report.json").read_text())
        assert device_bad["cases"][0]["verdict"] == "DEVICE_TRACE_BYTES_MISMATCH_PROFILE"
        assert device_bad["cases"][0]["descriptor_transactions"][0]["three_way_status"] == "DEVICE_TRACE_BYTES_MISMATCH_PROFILE"
    # USBPcap uses IRP ID + URB Function + Control transfer stage, not usb.urb_type.
    setup = {"bmRequestType": 128, "bRequest": 6, "wValue": 0x0100, "wIndex": 0, "wLength": 18}
    usbpcap_rows = [
        {"frame_number": 7, "time_epoch": 2000.0, "bus_id": 1, "device_address": 1,
         "irp_id": "0xffff8308136eba80", "urb_function": "URB_FUNCTION_GET_DESCRIPTOR_FROM_DEVICE (0x000b)",
         "control_stage": "0", "request": setup, "urb_status": "USBD_STATUS_SUCCESS (0x00000000)",
         "get_descriptor_response": None, "control_response": None, "data_fragment": None, "capdata": None},
        {"frame_number": 8, "time_epoch": 2000.001, "bus_id": 1, "device_address": 1,
         "irp_id": "0xffff8308136eba80", "urb_function": "URB_FUNCTION_CONTROL_TRANSFER (0x0008)",
         "control_stage": "3", "request": None, "urb_status": "USBD_STATUS_SUCCESS (0x00000000)",
         "get_descriptor_response": "12:01:00:02:00:00:00:40:09:12:00:12:00:01:01:02:03:01",
         "control_response": None, "data_fragment": None, "capdata": None},
    ]
    usbpcap_groups = reporter.build_transfer_groups(usbpcap_rows)
    assert len(usbpcap_groups) == 1, usbpcap_groups
    assert usbpcap_groups[0]["frame_numbers"] == [7, 8]
    assert usbpcap_groups[0]["complete_seen"] is True
    assert usbpcap_groups[0]["status"] == "COMPLETED"
    assert usbpcap_groups[0]["payload"].hex() == "120100020000004009120012000101020301"
    assert reporter.setup_packet_hex(setup) == "8006000100001200"

    print("test_campaign_byte_report: PASS")


if __name__ == "__main__":
    main()
