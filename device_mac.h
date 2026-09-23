#pragma once
// device_mac.h — the hardware MAC address that identifies this machine to Apple.
//
// Every App Store request carries a GUID derived from this address, and the
// SAP / StoreAgent emulation is seeded with the same bytes. It must therefore be:
//   * the REAL address of a PHYSICAL network adapter — never a placeholder
//     (macOS 27 hands 02:00:00:00:00:00 to getifaddrs() callers launched from
//     pwsh, so every such user would share GUID 020000000000);
//   * chosen deterministically — adding a VPN / virtual adapter or toggling
//     Wi-Fi must not change which adapter is picked;
//   * detected fresh on every run (no on-disk cache), so a replaced network
//     card is picked up.
//
// Platform sources:
//   macOS   : IOKit — IOMACAddress of the controller behind the interface marked
//             IOPrimaryInterface (built-in en0), falling back to en0 by BSD name.
//             This is the factory address, unaffected by the getifaddrs()
//             placeholder and by per-network private Wi-Fi addresses.
//   Windows : GetIfTable2 — physical adapters only (HardwareInterface flag),
//             PermanentPhysicalAddress (factory MAC, unaffected by Windows
//             random hardware addresses). Ethernet before Wi-Fi, then lowest MAC.
//   Linux   : /sys/class/net/<if> with a backing device (physical only),
//             wired before wireless, then interface name.
//
// Strict mode: if no valid address is found, device_mac_address() throws
// IpaError and no request must be sent to Apple.

#include <cstdint>
#include <string>
#include <vector>

// 6-byte hardware address. Throws IpaError when no valid physical address exists.
// Detected once per process (the result is stable for the lifetime of the run).
std::vector<uint8_t> device_mac_address();

// Upper-case hex GUID used in App Store requests, e.g. "FCB214A1B2C3".
std::string device_guid();

// Human-readable description of the chosen adapter, for --debug output
// (e.g. "IOKit primary interface en0"). Empty until device_mac_address() ran.
std::string device_mac_source();

// True for addresses that must never be sent to Apple: all zeros,
// 02:00:00:00:00:00 (macOS placeholder), broadcast, multicast, and the
// AA:BB:CC:DD:EE:FF fallback older builds used.
bool is_placeholder_mac(const uint8_t* mac, size_t len);

// Print adapter selection details to stderr (enabled by --debug).
void device_mac_set_debug(bool on);
