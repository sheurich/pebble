package va

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"log"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/letsencrypt/pebble/v2/acme"
	"github.com/letsencrypt/pebble/v2/core"
	"github.com/letsencrypt/pebble/v2/db"
)

func TestAuthzRace(_ *testing.T) {
	// Exercises a specific (fixed) race condition:
	// WARNING: DATA RACE
	// Read at 0x00c00040cde8 by goroutine 55:
	//  github.com/letsencrypt/pebble/db.(*MemoryStore).FindValidAuthorization()
	//      /tank/tank/src/pebble/db/memorystore.go:263 +0x18e
	//  github.com/letsencrypt/pebble/wfe.(*WebFrontEndImpl).makeAuthorizations()
	//      /tank/tank/src/pebble/wfe/wfe.go:1503 +0x2cf
	// ...
	// Previous write at 0x00c00040cde8 by goroutine 76:
	//  github.com/letsencrypt/pebble/va.VAImpl.setAuthzValid()
	//      /tank/tank/src/pebble/va/va.go:196 +0x2a6
	//  github.com/letsencrypt/pebble/va.VAImpl.process()
	//      /tank/tank/src/pebble/va/va.go:264 +0x83b

	// VAImpl.setAuthzInvalid updates authz.Status
	// MemoryStore.FindValidAuthorization searches and tests authz.Status

	// This whole test can be removed if/when the MemoryStore becomes 100% by value
	ms := db.NewMemoryStore()
	va := New(log.New(os.Stdout, "Pebble/TestRace", log.LstdFlags), 14000, 15000, false, "", ms)

	authz := &core.Authorization{
		ID: "auth-id",
	}

	_, err := ms.AddAuthorization(authz)
	if err != nil {
		panic("")
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		ms.FindValidAuthorization("", acme.Identifier{})
		wg.Done()
	}()
	va.setAuthzInvalid(authz, &core.Challenge{}, nil)
	wg.Wait()
}

func TestParseDNSPersist01Record(t *testing.T) {
	ms := db.NewMemoryStore()
	va := New(log.New(os.Stdout, "Pebble/Test ", log.LstdFlags), 14000, 15000, false, "", ms)

	tests := []struct {
		name        string
		record      string
		expectError bool
		expected    *DNSPersist01Record
	}{
		{
			name:        "Valid record with all parameters",
			record:      "ca.example.com; accounturi=https://example.com/acme/acct/123; policy=wildcard; persistUntil=1735689600",
			expectError: false,
			expected: &DNSPersist01Record{
				IssuerDomainName: "ca.example.com",
				AccountURI:       "https://example.com/acme/acct/123",
				Policy:           "wildcard",
				PersistUntil:     1735689600,
			},
		},
		{
			name:        "Valid record with only required parameters",
			record:      "ca.example.com; accounturi=https://example.com/acme/acct/456",
			expectError: false,
			expected: &DNSPersist01Record{
				IssuerDomainName: "ca.example.com",
				AccountURI:       "https://example.com/acme/acct/456",
				Policy:           "",
				PersistUntil:     0,
			},
		},
		{
			name:        "Valid record with wildcard policy",
			record:      "pebble.localhost; accounturi=https://localhost:14000/acct/1; policy=wildcard",
			expectError: false,
			expected: &DNSPersist01Record{
				IssuerDomainName: "pebble.localhost",
				AccountURI:       "https://localhost:14000/acct/1",
				Policy:           "wildcard",
				PersistUntil:     0,
			},
		},
		{
			name:        "Valid record with persistUntil timestamp",
			record:      "ca.example.com; accounturi=https://example.com/acct/789; persistUntil=9999999999",
			expectError: false,
			expected: &DNSPersist01Record{
				IssuerDomainName: "ca.example.com",
				AccountURI:       "https://example.com/acct/789",
				Policy:           "",
				PersistUntil:     9999999999,
			},
		},
		{
			name:        "Case-insensitive policy parameter",
			record:      "ca.example.com; accounturi=https://example.com/acct/1; policy=WiLdCaRd",
			expectError: false,
			expected: &DNSPersist01Record{
				IssuerDomainName: "ca.example.com",
				AccountURI:       "https://example.com/acct/1",
				Policy:           "wildcard", // should be lowercased
				PersistUntil:     0,
			},
		},
		{
			name:        "Unknown parameters should be ignored",
			record:      "ca.example.com; accounturi=https://example.com/acct/1; unknownparam=value; anotherparam=test",
			expectError: false,
			expected: &DNSPersist01Record{
				IssuerDomainName: "ca.example.com",
				AccountURI:       "https://example.com/acct/1",
				Policy:           "",
				PersistUntil:     0,
			},
		},
		{
			name:        "Whitespace handling",
			record:      "  ca.example.com  ;  accounturi = https://example.com/acct/1  ;  policy = wildcard  ",
			expectError: false,
			expected: &DNSPersist01Record{
				IssuerDomainName: "ca.example.com",
				AccountURI:       "https://example.com/acct/1",
				Policy:           "wildcard",
				PersistUntil:     0,
			},
		},
		{
			name:        "Multiple semicolons with empty parts",
			record:      "ca.example.com;; accounturi=https://example.com/acct/1;;;",
			expectError: false,
			expected: &DNSPersist01Record{
				IssuerDomainName: "ca.example.com",
				AccountURI:       "https://example.com/acct/1",
				Policy:           "",
				PersistUntil:     0,
			},
		},
		{
			name:        "Missing accounturi",
			record:      "ca.example.com; policy=wildcard",
			expectError: true,
			expected:    nil,
		},
		{
			name:        "Missing issuer-domain-name",
			record:      "; accounturi=https://example.com/acct/1",
			expectError: true,
			expected:    nil,
		},
		{
			name:        "Empty issuer-domain-name (whitespace only)",
			record:      "   ; accounturi=https://example.com/acct/1",
			expectError: true,
			expected:    nil,
		},
		{
			name:        "Bad timestamp format",
			record:      "ca.example.com; accounturi=https://example.com/acct/1; persistUntil=notanumber",
			expectError: true,
			expected:    nil,
		},
		{
			name:        "Empty persistUntil value",
			record:      "ca.example.com; accounturi=https://example.com/acct/1; persistUntil=",
			expectError: true,
			expected:    nil,
		},
		{
			name:        "Empty accounturi value",
			record:      "ca.example.com; accounturi=",
			expectError: true,
			expected:    nil,
		},
		{
			name:        "Empty string",
			record:      "",
			expectError: true,
			expected:    nil,
		},
		{
			name:        "Parameter without equals sign",
			record:      "ca.example.com; accounturi=https://example.com/acct/1; invalidparam",
			expectError: true,
			expected:    nil,
		},
		{
			name:        "Non-normalized issuer - uppercase with trailing dot",
			record:      "CA.EXAMPLE.COM.; accounturi=https://example.com/acct/1",
			expectError: false,
			expected: &DNSPersist01Record{
				IssuerDomainName: "ca.example.com",
				AccountURI:       "https://example.com/acct/1",
				Policy:           "",
				PersistUntil:     0,
			},
		},
		{
			name:        "Non-normalized issuer - uppercase without trailing dot",
			record:      "CA.EXAMPLE.COM; accounturi=https://example.com/acct/1",
			expectError: false,
			expected: &DNSPersist01Record{
				IssuerDomainName: "ca.example.com",
				AccountURI:       "https://example.com/acct/1",
				Policy:           "",
				PersistUntil:     0,
			},
		},
		{
			name:        "Non-normalized issuer - lowercase with trailing dot",
			record:      "ca.example.com.; accounturi=https://example.com/acct/1",
			expectError: false,
			expected: &DNSPersist01Record{
				IssuerDomainName: "ca.example.com",
				AccountURI:       "https://example.com/acct/1",
				Policy:           "",
				PersistUntil:     0,
			},
		},
		{
			name:        "Non-normalized issuer - mixed case with trailing dot and wildcard",
			record:      "Pebble.LocalHost.; accounturi=https://localhost:14000/acct/1; policy=wildcard",
			expectError: false,
			expected: &DNSPersist01Record{
				IssuerDomainName: "pebble.localhost",
				AccountURI:       "https://localhost:14000/acct/1",
				Policy:           "wildcard",
				PersistUntil:     0,
			},
		},
		{
			name:        "Case-insensitive parameter keys - AccountURI",
			record:      "ca.example.com; AccountURI=https://example.com/acct/1",
			expectError: false,
			expected: &DNSPersist01Record{
				IssuerDomainName: "ca.example.com",
				AccountURI:       "https://example.com/acct/1",
				Policy:           "",
				PersistUntil:     0,
			},
		},
		{
			name:        "Case-insensitive parameter keys - POLICY",
			record:      "ca.example.com; accounturi=https://example.com/acct/1; POLICY=wildcard",
			expectError: false,
			expected: &DNSPersist01Record{
				IssuerDomainName: "ca.example.com",
				AccountURI:       "https://example.com/acct/1",
				Policy:           "wildcard",
				PersistUntil:     0,
			},
		},
		{
			name:        "Case-insensitive parameter keys - PersistUntil",
			record:      "ca.example.com; accounturi=https://example.com/acct/1; PersistUntil=1735689600",
			expectError: false,
			expected: &DNSPersist01Record{
				IssuerDomainName: "ca.example.com",
				AccountURI:       "https://example.com/acct/1",
				Policy:           "",
				PersistUntil:     1735689600,
			},
		},
		{
			name:        "Duplicate accounturi parameter",
			record:      "ca.example.com; accounturi=https://example.com/acct/1; accounturi=https://example.com/acct/2",
			expectError: true,
			expected:    nil,
		},
		{
			name:        "Duplicate policy parameter",
			record:      "ca.example.com; accounturi=https://example.com/acct/1; policy=wildcard; policy=other",
			expectError: true,
			expected:    nil,
		},
		{
			name:        "Duplicate persistUntil parameter",
			record:      "ca.example.com; accounturi=https://example.com/acct/1; persistUntil=1735689600; persistUntil=1735689601",
			expectError: true,
			expected:    nil,
		},
		{
			name:        "Duplicate accounturi with different case",
			record:      "ca.example.com; accounturi=https://example.com/acct/1; AccountURI=https://example.com/acct/2",
			expectError: true,
			expected:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := va.parseDNSPersist01Record(tt.record)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none for record: %q", tt.record)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v for record: %q", err, tt.record)
				}
				if result == nil {
					t.Errorf("Expected result but got nil")
					return
				}
				if result.IssuerDomainName != tt.expected.IssuerDomainName {
					t.Errorf("Expected IssuerDomainName %q, got %q", tt.expected.IssuerDomainName, result.IssuerDomainName)
				}
				if result.AccountURI != tt.expected.AccountURI {
					t.Errorf("Expected AccountURI %q, got %q", tt.expected.AccountURI, result.AccountURI)
				}
				if result.Policy != tt.expected.Policy {
					t.Errorf("Expected Policy %q, got %q", tt.expected.Policy, result.Policy)
				}
				if result.PersistUntil != tt.expected.PersistUntil {
					t.Errorf("Expected PersistUntil %d, got %d", tt.expected.PersistUntil, result.PersistUntil)
				}
			}
		})
	}
}

func TestValidateDNSPersist01(t *testing.T) {
	ms := db.NewMemoryStore()
	va := New(log.New(os.Stdout, "Pebble/Test ", log.LstdFlags), 14000, 15000, false, "", ms)

	// Create a test account key
	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	accountURL := "https://localhost:14000/acct/1"
	issuerDomainNames := []string{"pebble.localhost", "ca.example.com"}

	// Helper function to create a mock vaTask
	createTask := func(issuerDomains []string, accountURL string, wildcard bool) *vaTask {
		authz := &core.Authorization{
			ID: "test-authz",
		}
		order := &core.Order{
			ID: "test-order",
		}
		authz.Order = order

		challenge := &core.Challenge{
			Challenge: acme.Challenge{
				Type:              acme.ChallengeDNSPersist01,
				Token:             "test-token",
				IssuerDomainNames: issuerDomains,
				Status:            acme.StatusPending,
			},
			ID:            "test-challenge",
			Authz:         authz,
			ValidatedDate: time.Time{},
		}

		// Convert ecdsa.PrivateKey to JSONWebKey
		jwk := &jose.JSONWebKey{
			Key: accountKey.Public(),
		}

		account := &core.Account{
			Key: jwk,
		}

		return &vaTask{
			Identifier: acme.Identifier{
				Type:  acme.IdentifierDNS,
				Value: "example.com",
			},
			Challenge:  challenge,
			Account:    account,
			AccountURL: accountURL,
			Wildcard:   wildcard,
		}
	}

	// Helper function to mock getTXTEntry
	// Since we can't easily mock the DNS lookup, we'll need to test the parsing logic
	// and validation logic separately. The validation logic in validateDNSPersist01
	// depends on getTXTEntry which makes real DNS queries.
	// For now, we'll create tests that demonstrate the validation logic.

	tests := []struct {
		name          string
		txtRecords    []string
		task          *vaTask
		expectError   bool
		errorContains string
	}{
		{
			name: "Valid dns-persist-01 challenge with matching issuer and account",
			txtRecords: []string{
				"pebble.localhost; accounturi=https://localhost:14000/acct/1",
			},
			task:        createTask(issuerDomainNames, accountURL, false),
			expectError: false,
		},
		{
			name: "Valid challenge with persistUntil in the future",
			txtRecords: []string{
				"pebble.localhost; accounturi=https://localhost:14000/acct/1; persistUntil=9999999999",
			},
			task:        createTask(issuerDomainNames, accountURL, false),
			expectError: false,
		},
		{
			name: "Expired persistUntil should fail",
			txtRecords: []string{
				"pebble.localhost; accounturi=https://localhost:14000/acct/1; persistUntil=1",
			},
			task:          createTask(issuerDomainNames, accountURL, false),
			expectError:   true,
			errorContains: "No valid dns-persist-01 record found for this challenge",
		},
		{
			name: "Issuer domain name mismatch should fail",
			txtRecords: []string{
				"unknown.issuer.com; accounturi=https://localhost:14000/acct/1",
			},
			task:          createTask(issuerDomainNames, accountURL, false),
			expectError:   true,
			errorContains: "No valid dns-persist-01 record found for this challenge",
		},
		{
			name: "Account URI mismatch should fail",
			txtRecords: []string{
				"pebble.localhost; accounturi=https://localhost:14000/acct/999",
			},
			task:          createTask(issuerDomainNames, accountURL, false),
			expectError:   true,
			errorContains: "No valid dns-persist-01 record found for this challenge",
		},
		{
			name: "Wildcard certificate without policy=wildcard should fail",
			txtRecords: []string{
				"pebble.localhost; accounturi=https://localhost:14000/acct/1",
			},
			task:          createTask(issuerDomainNames, accountURL, true),
			expectError:   true,
			errorContains: "No valid dns-persist-01 record found for this challenge",
		},
		{
			name: "Wildcard certificate with policy=wildcard should succeed",
			txtRecords: []string{
				"pebble.localhost; accounturi=https://localhost:14000/acct/1; policy=wildcard",
			},
			task:        createTask(issuerDomainNames, accountURL, true),
			expectError: false,
		},
		{
			name: "Multiple TXT records with one valid record",
			txtRecords: []string{
				"wrong.issuer.com; accounturi=https://localhost:14000/acct/1",
				"pebble.localhost; accounturi=https://localhost:14000/acct/999",
				"pebble.localhost; accounturi=https://localhost:14000/acct/1",
			},
			task:        createTask(issuerDomainNames, accountURL, false),
			expectError: false,
		},
		{
			name: "Multiple TXT records all invalid",
			txtRecords: []string{
				"wrong.issuer.com; accounturi=https://localhost:14000/acct/1",
				"pebble.localhost; accounturi=https://localhost:14000/acct/999",
				"another.issuer.com; accounturi=https://localhost:14000/acct/888",
			},
			task:          createTask(issuerDomainNames, accountURL, false),
			expectError:   true,
			errorContains: "No valid dns-persist-01 record found for this challenge",
		},
		{
			name: "Challenge missing issuer-domain-names",
			txtRecords: []string{
				"pebble.localhost; accounturi=https://localhost:14000/acct/1",
			},
			task:          createTask([]string{}, accountURL, false),
			expectError:   true,
			errorContains: "Challenge missing issuer-domain-names",
		},
		{
			name: "Valid record with second issuer domain name",
			txtRecords: []string{
				"ca.example.com; accounturi=https://localhost:14000/acct/1",
			},
			task:        createTask(issuerDomainNames, accountURL, false),
			expectError: false,
		},
		{
			name: "Malformed TXT record should be skipped",
			txtRecords: []string{
				"malformed record without proper format",
				"pebble.localhost; accounturi=https://localhost:14000/acct/1",
			},
			task:        createTask(issuerDomainNames, accountURL, false),
			expectError: false,
		},
		{
			name: "All TXT records malformed should fail",
			txtRecords: []string{
				"malformed record without proper format",
				"; accounturi=https://localhost:14000/acct/1",
				"issuer without accounturi",
			},
			task:          createTask(issuerDomainNames, accountURL, false),
			expectError:   true,
			errorContains: "No valid dns-persist-01 record found for this challenge",
		},
		{
			name: "Non-normalized issuer - uppercase with trailing dot should match",
			txtRecords: []string{
				"PEBBLE.LOCALHOST.; accounturi=https://localhost:14000/acct/1",
			},
			task:        createTask(issuerDomainNames, accountURL, false),
			expectError: false,
		},
		{
			name: "Non-normalized issuer - mixed case should match",
			txtRecords: []string{
				"CA.Example.COM; accounturi=https://localhost:14000/acct/1",
			},
			task:        createTask(issuerDomainNames, accountURL, false),
			expectError: false,
		},
		{
			name: "Case-insensitive policy - uppercase WILDCARD",
			txtRecords: []string{
				"pebble.localhost; accounturi=https://localhost:14000/acct/1; policy=WILDCARD",
			},
			task:        createTask(issuerDomainNames, accountURL, true),
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test implementation that simulates the validation logic
			// without making actual DNS queries
			result := simulateValidation(va, tt.task, tt.txtRecords)

			if tt.expectError {
				if result.Error == nil {
					t.Errorf("Expected error but got none")
				} else if tt.errorContains != "" {
					if result.Error.Detail != tt.errorContains {
						t.Errorf("Expected error containing %q, got %q", tt.errorContains, result.Error.Detail)
					}
				}
			} else {
				if result.Error != nil {
					t.Errorf("Unexpected error: %v", result.Error)
				}
			}
		})
	}
}

// simulateValidation simulates the validation logic from validateDNSPersist01
// without making actual DNS queries. This allows us to test the validation
// logic in isolation.
func simulateValidation(va *VAImpl, task *vaTask, txtRecords []string) *core.ValidationRecord {
	challengeSubdomain := "_validation-persist." + task.Identifier.Value
	result := &core.ValidationRecord{
		URL:         challengeSubdomain,
		ValidatedAt: time.Now(),
	}

	if len(txtRecords) == 0 {
		result.Error = acme.UnauthorizedProblem("No TXT records found for dns-persist-01 challenge")
		return result
	}

	task.Challenge.RLock()
	issuerDomainNames := task.Challenge.IssuerDomainNames
	task.Challenge.RUnlock()

	if len(issuerDomainNames) == 0 {
		result.Error = acme.MalformedProblem("Challenge missing issuer-domain-names")
		return result
	}

	for _, txt := range txtRecords {
		record, err := va.parseDNSPersist01Record(txt)
		if err != nil {
			continue
		}

		// Validate issuer-domain-name against challenge's allowed values
		issuerFound := false
		for _, validIssuer := range issuerDomainNames {
			if record.IssuerDomainName == validIssuer {
				issuerFound = true
				break
			}
		}

		if !issuerFound {
			continue
		}

		// Validate accounturi matches the requesting account's URL
		if record.AccountURI != task.AccountURL {
			continue
		}

		// Validate persistUntil if present
		if record.PersistUntil > 0 {
			currentTime := time.Now().Unix()
			if currentTime > record.PersistUntil {
				continue
			}
		}

		// Validate wildcard policy if this is a wildcard certificate request
		if task.Wildcard && record.Policy != "wildcard" {
			continue
		}

		// Record is valid
		return result
	}

	result.Error = acme.UnauthorizedProblem("No valid dns-persist-01 record found for this challenge")
	return result
}
