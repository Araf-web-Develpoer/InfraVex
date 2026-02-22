package pivot

import (
	"fmt"

	"InfraVex/pkg/logger"
)

// AttemptASN handles the workflow of prompting user for out-of-scope ASN block expansion
func AttemptASN(targetOrg string, discoveredOrg string, asn string, blocks []string) ([]string, error) {
	if targetOrg == "" || discoveredOrg == "" {
		return nil, fmt.Errorf("missing org names")
	}

	fmt.Printf("\n[PIVOT ALERT] Potential organizational match found.\n")
	fmt.Printf("Target Org:     %s\n", targetOrg)
	fmt.Printf("Discovered Org: %s\n", discoveredOrg)
	fmt.Printf("ASN:            %s\n", asn)

	fmt.Printf("The ASN %s advertises %d network blocks.\n", asn, len(blocks))
	fmt.Print("Do you want to add these CIDRs to the active scope? (YES/no): ")

	var response string
	fmt.Scanln(&response)

	if response == "YES" {
		logger.Info("ASN Pivot accepted by user", map[string]interface{}{"asn": asn})
		return blocks, nil
	}

	logger.Info("ASN Pivot rejected by user", map[string]interface{}{"asn": asn})
	return nil, nil // return empty, no error
}
