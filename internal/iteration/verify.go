// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package iteration

import (
	"fmt"

	"github.com/steflokos/assess/internal/model"
)

// State of one signature after it was checked.
const (
	Valid     = "valid"
	Invalid   = "invalid"
	Unchecked = "not checked" // no public key was given for it
)

// SigStatus is the result for one signature.
type SigStatus struct {
	By    string `json:"by"`
	Key   string `json:"key"`
	State string `json:"state"`
}

// Status is the result for one iteration.
type Status struct {
	Number     int         `json:"number"`
	Date       string      `json:"date"`
	Hash       string      `json:"hash"`
	OK         bool        `json:"ok"` // its number, its link and its hash are right, and no signature is wrong
	Signatures []SigStatus `json:"signatures,omitempty"`
}

// Result is what Verify found.
type Result struct {
	Iterations []Status  `json:"iterations"`
	Head       string    `json:"head,omitempty"`
	Problems   []Problem `json:"problems,omitempty"`
	// Unchecked counts the signatures that no public key was given for.
	Unchecked int `json:"unchecked,omitempty"`
}

// Verify checks the chain and every signature that one of the keys can check. head is the last hash that you kept
// somewhere else, or empty. It is the only way to find out that someone removed the newest iterations.
func Verify(its []model.Iteration, keys []Key, head string) Result {
	res := Result{Head: Head(its), Problems: Chain(its)}
	byKey := map[string]Key{}
	for _, k := range keys {
		byKey[k.Fingerprint] = k
	}
	bad := map[int]bool{}
	for _, p := range res.Problems {
		bad[p.Number] = true
	}
	for _, it := range its {
		st := Status{Number: it.Number, Date: it.Date, Hash: it.Hash}
		used := map[string]bool{}
		for _, s := range it.Signatures {
			ss := SigStatus{By: s.By, Key: s.Key, State: Unchecked}
			if used[s.Key] {
				// the name is a label that anyone who can edit the file can change, so a signature copied under another name
				// would otherwise show as a second person who signed
				ss.State = Invalid
				bad[it.Number] = true
				res.Problems = append(res.Problems, Problem{it.Number, CodeSignature, fmt.Sprintf("the signature of %s uses a key that signed this iteration already. One key is one person", s.By)})
				st.Signatures = append(st.Signatures, ss)
				continue
			}
			used[s.Key] = true
			if k, ok := byKey[s.Key]; ok {
				ss.State = Valid
				if !Check(k.Pub, it.Hash, s.Sig) {
					ss.State = Invalid
					bad[it.Number] = true
					res.Problems = append(res.Problems, Problem{it.Number, CodeSignature, fmt.Sprintf("the signature of %s does not match the hash of the iteration", s.By)})
				}
			} else {
				res.Unchecked++
			}
			st.Signatures = append(st.Signatures, ss)
		}
		st.OK = !bad[it.Number]
		res.Iterations = append(res.Iterations, st)
	}
	if head != "" && head != res.Head {
		shown := res.Head
		if shown == "" {
			shown = "none"
		}
		res.Problems = append(res.Problems, Problem{0, CodeHead, fmt.Sprintf("the last hash in the file is %s, but you expected %s. Iterations are missing, or someone wrote the file again", shown, head)})
	}
	return res
}
