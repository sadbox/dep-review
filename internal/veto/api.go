// Package veto asks the model whether anything in an update's changed
// code is a reason to stop it (docs/v0.2-spec.md, section 7).
//
// This file is the package's API. The model gets one request per chunk,
// with no tools and no repository content: only the text the gate put in
// the request. Its answer is a closed structure and can only take a merge
// away. Nothing it writes is interpreted; allow.Decide treats any veto,
// of any category, as person.
package veto

import (
	"context"

	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/artifact"
)

// Answer is the model's decision for one update.
type Answer string

// The two answers. There is no "approve" and no "unsure".
const (
	// NoVeto: every chunk was answered and none raised an objection.
	NoVeto Answer = "no_veto"
	// Vetoed: at least one chunk raised an objection, or the model
	// refused.
	Vetoed Answer = "veto"
)

// Category is why the model stopped an update.
type Category string

// The fixed list the model chooses from.
const (
	// Exfiltration: reads credentials, environment or files and sends
	// them somewhere.
	Exfiltration Category = "exfiltration"
	// RemoteCode: downloads and runs code.
	RemoteCode Category = "remote_code"
	// InstallTimeExecution: runs at install, import or init with effects
	// unrelated to the package's purpose.
	InstallTimeExecution Category = "install_time_execution"
	// Obfuscation: an encoded, packed or eval'd payload.
	Obfuscation Category = "obfuscation"
	// Destructive: deletes or overwrites user data.
	Destructive Category = "destructive"
	// UnexplainedCapability: new process, network or filesystem use
	// unrelated to the package's purpose.
	UnexplainedCapability Category = "unexplained_capability"
	// InjectionText: text addressed to the reviewer, to an AI or to an
	// automated check. Such text is itself the reason to stop.
	InjectionText Category = "injection_text"
	// OtherMalicious: malicious in a way no other category names.
	OtherMalicious Category = "other_malicious"
)

// Refused is the category the gate sets when the model refused to answer
// (stop_reason "refusal"). It is not offered to the model.
const Refused Category = allow.VetoModelRefused

// Categories returns the fixed list offered to the model, in the order
// the prompt and the answer schema give it. Refused is not in it.
func Categories() []Category {
	return []Category{
		Exfiltration, RemoteCode, InstallTimeExecution, Obfuscation,
		Destructive, UnexplainedCapability, InjectionText, OtherMalicious,
	}
}

// Request is one update's prepared read, to be put before the model.
type Request struct {
	// Read holds the chunks, the unread files and the content key. The
	// update's ecosystem, name and versions in Read.Pair are the only
	// other thing the model is told.
	Read artifact.Prepared
}

// Verdict is the answer for one update, over all of its chunks.
type Verdict struct {
	// Answer is NoVeto only when every chunk was answered no_veto.
	Answer Answer `json:"answer"`
	// Category is set when Answer is Vetoed: one of Categories, or
	// Refused.
	Category Category `json:"category"`
	// Quotes are the lines the model pointed at. Untrusted text.
	Quotes []string `json:"quotes"`
	// Notes is the model's optional remark (a breaking change, a file it
	// could not judge). Shown, never acted on. Untrusted text.
	Notes string `json:"notes"`
	// Read is what the caller records as the update's Read fact: the
	// request's Read.State (full or partial) when every chunk was
	// answered. It is never allow.ReadNone here; see Reviewer.
	Read allow.ReadState `json:"read"`
	// Key is the request's content key (Read.Key), under which the
	// verdict may be stored and found again. A NoVeto is stored only
	// after every chunk answered.
	Key string `json:"key"`
}

// Reviewer gets a verdict for a prepared read.
type Reviewer interface {
	// Review sends each chunk of req to the model and combines the
	// answers: any veto is a veto.
	//
	// An error means there is no complete answer (the call failed, the
	// model was unavailable, an answer did not fit the closed structure).
	// The caller records allow.ReadNone and no veto for the update, which
	// allow.Decide answers with wait and retries at the next evaluation.
	// A refusal is not an error: it is a Verdict with Answer Vetoed and
	// Category Refused.
	//
	// The caller turns a Verdict into facts like this: UpdateFacts.Read
	// is Verdict.Read, and UpdateFacts.Veto is nil for NoVeto and
	// otherwise &allow.Veto{Category: string(v.Category), Quotes:
	// v.Quotes, Notes: v.Notes}.
	Review(ctx context.Context, req Request) (Verdict, error)
}
