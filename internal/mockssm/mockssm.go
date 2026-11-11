// Package mockssm is a stand-in for SSM Parameter Store in the local stack
// and tests: GetParameter and PutParameter over the AWS JSON protocol, with
// parameters kept in memory. It checks no signatures and encrypts nothing.
// It is never released.
package mockssm

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Server holds parameters by name.
type Server struct {
	mu     sync.Mutex
	params map[string]parameter
}

type parameter struct {
	value    string
	typ      string
	version  int64
	modified time.Time
}

// New returns a server holding seed, SecureStrings by name.
func New(seed map[string]string) *Server {
	s := &Server{params: map[string]parameter{}}
	for name, value := range seed {
		s.params[name] = parameter{value: value, typ: "SecureString", version: 1, modified: time.Now()}
	}
	return s
}

// Handler serves the SSM API at /.
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/healthz" {
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "UnknownOperationException", "SSM is POST only")
			return
		}
		switch r.Header.Get("X-Amz-Target") {
		case "AmazonSSM.GetParameter":
			s.getParameter(w, r)
		case "AmazonSSM.PutParameter":
			s.putParameter(w, r)
		default:
			writeError(w, http.StatusBadRequest, "UnknownOperationException", "the mock knows GetParameter and PutParameter")
		}
	})
}

// name returns the parameter name an ARN or a name gives: the ARN of a
// hierarchical name (/a/b) leaves out its leading slash.
func name(nameOrARN string) string {
	if _, rest, ok := strings.Cut(nameOrARN, ":parameter/"); ok {
		if strings.Contains(rest, "/") {
			return "/" + rest
		}
		return rest
	}
	return nameOrARN
}

func (s *Server) getParameter(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name           string
		WithDecryption bool
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		writeError(w, http.StatusBadRequest, "ValidationException", "invalid request")
		return
	}
	n := name(in.Name)
	s.mu.Lock()
	p, ok := s.params[n]
	s.mu.Unlock()
	if !ok {
		writeError(w, http.StatusBadRequest, "ParameterNotFound", "parameter "+n+" not found")
		return
	}
	value := p.value
	if p.typ == "SecureString" && !in.WithDecryption {
		value = "encrypted"
	}
	writeJSON(w, map[string]any{"Parameter": map[string]any{
		"Name": n, "Type": p.typ, "Value": value, "Version": p.version,
		"LastModifiedDate": float64(p.modified.UnixMilli()) / 1000, "DataType": "text",
	}})
}

func (s *Server) putParameter(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name      string
		Value     string
		Type      string
		Overwrite bool
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil || in.Name == "" || strings.HasPrefix(in.Name, "arn:") {
		writeError(w, http.StatusBadRequest, "ValidationException", "a parameter name is required, not an ARN")
		return
	}
	if len(in.Value) > 4096 {
		writeError(w, http.StatusBadRequest, "ValidationException", "a standard parameter's value is at most 4 KB")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p, exists := s.params[in.Name]
	if exists && !in.Overwrite {
		writeError(w, http.StatusBadRequest, "ParameterAlreadyExists", "the parameter already exists")
		return
	}
	typ := in.Type
	if typ == "" {
		typ = "String"
	}
	s.params[in.Name] = parameter{value: in.Value, typ: typ, version: p.version + 1, modified: time.Now()}
	writeJSON(w, map[string]any{"Version": p.version + 1, "Tier": "Standard"})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	_ = json.NewEncoder(w).Encode(v)
}

// writeError answers as SSM does: the error's type in __type, which the
// AWS SDK turns into its typed error.
func writeError(w http.ResponseWriter, status int, typ, msg string) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"__type": typ, "message": msg})
}
