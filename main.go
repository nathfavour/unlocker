package main

import (
	"bufio"
	"fmt"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// unlockDevice attempts to unlock the device at the given IP, downloads info, and simulates firmware analysis.
func unlockDevice(targetIP string) error {
	fmt.Printf("\nAttempting to unlock device at %s...\n", targetIP)
	unlockerDir := filepath.Join(".unlocker")
	if err := os.MkdirAll(unlockerDir, 0755); err != nil {
		return fmt.Errorf("failed to create .unlocker directory: %v", err)
	}

	ports := []int{80, 443, 23, 22, 8080}
	var results []string
	for _, port := range ports {
		address := fmt.Sprintf("%s:%d", targetIP, port)
		conn, err := net.DialTimeout("tcp", address, 3*time.Second)
		if err != nil {
			results = append(results, fmt.Sprintf("Port %d: closed or unreachable", port))
			continue
		}
		defer conn.Close()
		results = append(results, fmt.Sprintf("Port %d: OPEN", port))
		if port == 80 || port == 8080 || port == 443 {
			// Try HTTP(S) GET
			fmt.Fprintf(conn, "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", targetIP)
			buf := make([]byte, 4096)
			n, _ := conn.Read(buf)
			banner := string(buf[:n])
			results = append(results, fmt.Sprintf("Port %d banner:\n%s", port, banner))
		} else {
			// Try to read banner for Telnet/SSH
			buf := make([]byte, 512)
			n, _ := conn.Read(buf)
			if n > 0 {
				results = append(results, fmt.Sprintf("Port %d banner:\n%s", port, string(buf[:n])))
			}
		}
	}

	infoPath := filepath.Join(unlockerDir, "router_analysis.txt")
	os.WriteFile(infoPath, []byte(strings.Join(results, "\n\n")), 0644)
	fmt.Printf("Router analysis complete. Results saved to %s\n", infoPath)

	// --- Raw Go: Send low-level TCP SYN to port 80 ---
	err := sendRawTCPSYN(targetIP, 80)
	if err != nil {
		fmt.Printf("[Raw] Failed to send TCP SYN: %v\n", err)
	} else {
		fmt.Println("[Raw] Low-level TCP SYN sent to router (simulated unlock trigger).")
	}

	// Simulate downloading device info
	infoPath = filepath.Join(unlockerDir, "device_info.txt")
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

// sendRawTCPSYN sends a raw TCP SYN packet to the target IP on the given port (Linux/Unix only, requires root).
func sendRawTCPSYN(targetIP string, port int) error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return fmt.Errorf("raw socket error: %v (are you root?)", err)
	}
	defer syscall.Close(fd)

	// Build IP and TCP headers manually (minimal, not production-ready)
	ip := net.ParseIP(targetIP).To4()
	if ip == nil {
		return fmt.Errorf("invalid IPv4 address")
	}
	// Random source port
	srcPort := uint16(10000 + rand.Intn(50000))
	// TCP header (20 bytes)
	tcpHeader := make([]byte, 20)
	tcpHeader[0] = byte(srcPort >> 8)
	tcpHeader[1] = byte(srcPort)
	tcpHeader[2] = byte(port >> 8)
	tcpHeader[3] = byte(port)
	tcpHeader[13] = 0x02 // SYN flag
	// IP header (20 bytes, not filled here for brevity)
	packet := append(make([]byte, 20), tcpHeader...)

	dst := syscall.SockaddrInet4{Port: port}
	copy(dst.Addr[:], ip)
	if err := syscall.Sendto(fd, packet, 0, &dst); err != nil {
		return fmt.Errorf("sendto failed: %v", err)
	}
	fmt.Printf("[Raw] Sent TCP SYN to %s:%d\n", targetIP, port)
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
