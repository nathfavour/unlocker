package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

// unlockDevice is a placeholder for the core logic to unlock a network-locked WiFi device.
func unlockDevice(targetIP string) error {
	// TODO: Implement smart networking logic to interact with the device.
	// Use net.Dial, net.Conn, or other low-level networking as needed.
	fmt.Printf("Attempting to unlock device at %s...\n", targetIP)
	// ...networking and unlocking logic here...
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

func main() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("=== WiFi Device Unlocker CLI ===")
	localIP, err := getLocalIP()
	if err == nil {
		fmt.Printf("Detected local IP: %s\n", localIP)
		routerIP, rerr := extrapolateRouterIP(localIP)
		if rerr == nil {
			fmt.Printf("Guessed router IP: %s\n", routerIP)
		}
	}
	for {
		fmt.Print("Enter the IP address of the device to unlock (or 'exit' to quit): ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)
		if input == "exit" {
			fmt.Println("Exiting.")
			break
		}
		if net.ParseIP(input) == nil {
			fmt.Println("Invalid IP address. Please try again.")
			continue
		}
		err := unlockDevice(input)
		if err != nil {
			fmt.Printf("Failed to unlock device: %v\n", err)
		} else {
			fmt.Println("Unlock attempt complete.")
		}
	}
}
