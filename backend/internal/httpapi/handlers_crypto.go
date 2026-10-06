package httpapi

import (
	"encoding/json"
	"net/http"

	"ciphervault/internal/crypto"
)

type RegistryResponse struct {
	Default  string   `json:"default"`
	Variants []string `json:"variants"`
}

func (s *Server) handleGetVariants(w http.ResponseWriter, r *http.Request) {
	resp := RegistryResponse{
		Default:  crypto.DefaultVariant,
		Variants: crypto.AllVariantIDs,
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(resp)
}

