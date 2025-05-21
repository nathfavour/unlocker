package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// unlockDevice attempts to unlock the device at the given IP, downloads info, and simulates firmware analysis.
func unlockDevice(targetIP string) error {
	fmt.Printf("\nAttempting to unlock device at %s...\n", targetIP)
	unlockerDir := filepath.Join(".unlocker")
	if err := os.MkdirAll(unlockerDir, 0755); err != nil {
		return fmt.Errorf("failed to create .unlocker directory: %v", err)
	}
	// Simulate downloading device info
	infoPath := filepath.Join(unlockerDir, "device_info.txt")
	infoContent := fmt.Sprintf("Device IP: %s\nUnlock attempt: %s\n", targetIP, time.Now().Format(time.RFC3339))
	os.WriteFile(infoPath, []byte(infoContent), 0644)
	// Simulate firmware access and analysis
	firmwarePath := filepath.Join(unlockerDir, "firmware.bin")
	os.WriteFile(firmwarePath, []byte("FAKE_FIRMWARE_DATA"), 0644)
	fmt.Println("Relevant info downloaded to .unlocker/. Attempting low-level analysis...")
	// ...insert real low-level networking/firmware logic here...
	fmt.Println("(Simulation) Firmware analysis complete. Device should now accept different SIM cards/vendors if unlock is successful.")
	return nil
}

// getLocalIP returns the first non-loopback IPv4 address found on the system.
func getLocalIP() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			ip = ip.To4()
			if ip == nil {
				continue
			}
			return ip.String(), nil
		}
	}
	return "", fmt.Errorf("no connected network interface found")
}

// extrapolateRouterIP guesses the router IP based on the local IP (assumes /24 subnet).
func extrapolateRouterIP(localIP string) (string, error) {
	parts := strings.Split(localIP, ".")
	if len(parts) != 4 {
		return "", fmt.Errorf("invalid local IP format")
	}
	return fmt.Sprintf("%s.%s.%s.1", parts[0], parts[1], parts[2]), nil
}

// profileEthernet prints detailed info about all Ethernet interfaces.
func profileEthernet() error {
	ifaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	found := false
	for _, iface := range ifaces {
		// Heuristic: Ethernet interfaces are usually not loopback, not point-to-point, and have a hardware address
		if iface.Flags&net.FlagLoopback != 0 || len(iface.HardwareAddr) == 0 {
			continue
		}
		fmt.Printf("\nEthernet Interface: %s\n", iface.Name)
		fmt.Printf("  HardwareAddr (MAC): %s\n", iface.HardwareAddr.String())
		fmt.Printf("  MTU: %d\n", iface.MTU)
		fmt.Printf("  Flags: %s\n", iface.Flags.String())
		addrs, err := iface.Addrs()
		if err == nil {
			for _, addr := range addrs {
				fmt.Printf("  Address: %s\n", addr.String())
			}
		}
		found = true
	}
	if !found {
		fmt.Println("No Ethernet interfaces found.")
	}
	return nil
}

func main() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("=== Ethernet Profiler CLI ===")
	fmt.Println("Profiling Ethernet interfaces...")
	_ = profileEthernet()
	localIP, err := getLocalIP()
	if err == nil {
		fmt.Printf("Detected local IP: %s\n", localIP)
		routerIP, rerr := extrapolateRouterIP(localIP)
		if rerr == nil {
			fmt.Printf("Guessed router IP: %s\n", routerIP)
			fmt.Println("\nThis tool will attempt to network unlock the WiFi device at the router IP, allowing different SIM cards and vendors to use it. It will deeply analyze the device via Ethernet, download relevant info into the .unlocker/ folder, and attempt firmware analysis.\n")
			fmt.Print("Press Enter to proceed...")
			reader.ReadString('\n')
			err = unlockDevice(routerIP)
			if err != nil {
				fmt.Printf("Failed to unlock device: %v\n", err)
			} else {
				fmt.Println("Unlock attempt complete.")
			}
			return
		}
	}
	fmt.Println("Could not determine router IP. Exiting.")
}
