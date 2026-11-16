import importlib.util
from pathlib import Path
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "usb-time-sync.py"
spec = importlib.util.spec_from_file_location("usb_time_sync", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def test_linux_remote_clock_command():
    class Args:
        target_os = "linux"
    with patch.object(mod, "run_ssh", return_value="1760000000123") as call:
        assert mod.remote_now_ms(Args()) == 1760000000123
        assert call.call_args.args[1] == "date -u +%s%3N"


def test_linux_set_command_uses_sudo_noninteractive():
    class Args:
        target_os = "linux"
    with patch.object(mod, "run_ssh", return_value="ok") as call:
        mod.set_remote(Args(), 1760000000123)
        assert call.call_args.args[1].startswith("sudo -n date -u -s @")


def test_windows_set_command_uses_fixed_powershell_template():
    class Args:
        target_os = "windows"
    with patch.object(mod, "run_ssh", return_value="ok") as call:
        mod.set_remote(Args(), 1760000000123)
        command = call.call_args.args[1]
        assert "Set-Date" in command
        assert "1760000000123" in command
