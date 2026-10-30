// Package offboarding provides the OFF-001 checklist template and helpers.
package offboarding

import "encoding/json"

// Item is one checklist row.
type Item struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Done        bool   `json:"done"`
	EvidenceRef string `json:"evidence_ref,omitempty"`
	Note        string `json:"note,omitempty"`
}

// DefaultItems returns the OFF-001 checklist (accounts, SSO, VPN, keys, destruction, holds, notice, fourth parties, inventory).
func DefaultItems() []Item {
	return []Item{
		{ID: "revoke_accounts", Label: "Revoke accounts"},
		{ID: "revoke_sso", Label: "Revoke SSO apps"},
		{ID: "revoke_vpn", Label: "Revoke VPN access"},
		{ID: "revoke_api_keys", Label: "Revoke API keys"},
		{ID: "destruction_cert", Label: "Data return/destruction certificate"},
		{ID: "legal_hold_check", Label: "Legal-hold check before destruction"},
		{ID: "termination_notice", Label: "Termination notice"},
		{ID: "fourth_party_impact", Label: "Fourth-party impacts reviewed"},
		{ID: "inventory_status", Label: "Inventory status updated to offboarding/terminated"},
	}
}

// ItemsJSON marshals default or provided items.
func ItemsJSON(items []Item) (string, error) {
	if items == nil {
		items = DefaultItems()
	}
	b, err := json.Marshal(items)
	return string(b), err
}

// ParseItems unmarshals checklist JSON.
func ParseItems(raw string) ([]Item, error) {
	if raw == "" {
		return DefaultItems(), nil
	}
	var items []Item
	if err := json.Unmarshal([]byte(raw), &items); err != nil {
		return nil, err
	}
	return items, nil
}

// MarkDone sets Done on the matching item id.
func MarkDone(items []Item, id string, done bool, evidenceRef string) ([]Item, bool) {
	out := make([]Item, len(items))
	copy(out, items)
	for i := range out {
		if out[i].ID == id {
			out[i].Done = done
			if evidenceRef != "" {
				out[i].EvidenceRef = evidenceRef
			}
			return out, true
		}
	}
	return out, false
}

// AllDone reports whether every item is complete.
func AllDone(items []Item) bool {
	if len(items) == 0 {
		return false
	}
	for _, it := range items {
		if !it.Done {
			return false
		}
	}
	return true
}
