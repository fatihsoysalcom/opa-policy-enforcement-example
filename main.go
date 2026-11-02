package main

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/open-policy-agent/opa/rego"
)

// Represents a user's request to access a resource.
type Request struct {
	User    string `json:"user"`
	Action  string `json:"action"`
	Resource string `json:"resource"`
}

func main() {
	// Define the Rego policy as a string.
	// This policy allows 'admin' to perform any action on any resource,
	// and 'user' to read any resource.
	policy := `
package example

default allow = false

allow {
	input.user == "admin"
}

allow {
	input.user == "user"
	input.action == "read"
}
`

	// Initialize OPA with the policy.
	// This is a simplified initialization for demonstration purposes.
	// In a real-world scenario, you might load policies from files or external services.
	r, err := rego.New(rego.Query("data.example.allow"), rego.Policy(policy)).PrepareForEval(nil)
	if err != nil {
		log.Fatalf("Error preparing OPA: %v", err)
	}

	// Define some example requests.
	requests := []Request{
		{User: "admin", Action: "write", Resource: "data"},
		{User: "user", Action: "read", Resource: "config"},
		{User: "user", Action: "write", Resource: "data"},
		{User: "guest", Action: "read", Resource: "logs"},
	}

	// Evaluate each request against the policy.
	fmt.Println("Evaluating requests against OPA policy:")
	for _, req := range requests {
		inputJSON, _ := json.Marshal(req)
		var input interface{}
		json.Unmarshal(inputJSON, &input)

		results, err := r.Eval(nil, rego.EvalInput(input))
		if err != nil {
			log.Printf("Error evaluating request %+v: %v", req, err)
			continue
		}

		// The result is a slice of `rego.Result` objects.
		// We expect a single boolean result for 'data.example.allow'.
		var allowed bool
		if len(results) > 0 && len(results[0].Expressions) > 0 {
			allowed = results[0].Expressions[0].Value.(bool)
		}

		fmt.Printf("Request: %+v, Allowed: %t\n", req, allowed)
	}
}
