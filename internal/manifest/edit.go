package manifest

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"
	"k8s.io/apimachinery/pkg/util/validation"
)

// ErrLayout is returned when a document is laid out in a way the editor does
// not change in place, such as YAML anchors in spec.encryptedData. Its
// wrapped message says what; it never echoes file content.
var ErrLayout = errors.New("the file cannot be edited in place")

// Edit sets one key of spec.encryptedData in one document.
type Edit struct {
	// Document is the document's index, as Document.Index reports it.
	Document int
	Key      string
	// Value is a base64 ciphertext.
	Value string
}

var (
	base64Value = regexp.MustCompile(`^[A-Za-z0-9+/=]+$`)
	// plainSafe matches what can be written unquoted and is read back as
	// the same string by YAML 1.1 and 1.2 parsers alike, once the words
	// below are excluded.
	plainSafe = regexp.MustCompile(`^[A-Za-z_][-._A-Za-z0-9+/=]*$`)
	// yaml11Words are read as booleans or null by YAML 1.1 parsers, which
	// Kubernetes tooling uses.
	yaml11Words = map[string]bool{
		"y": true, "Y": true, "yes": true, "Yes": true, "YES": true,
		"n": true, "N": true, "no": true, "No": true, "NO": true,
		"true": true, "True": true, "TRUE": true, "false": true, "False": true, "FALSE": true,
		"on": true, "On": true, "ON": true, "off": true, "Off": true, "OFF": true,
		"null": true, "Null": true, "NULL": true,
	}
)

// SetEncryptedData returns content with each edit made. Only the values of
// spec.encryptedData change, plus a line for each key that is new: comments,
// formatting, key order and every other document are kept byte for byte.
// Names, namespaces and annotations, which make up the decryption label,
// are never touched.
//
// The result is checked before it is returned: decoded, it must equal the
// original with exactly these values set. A file the editor cannot change
// that precisely is refused with ErrLayout rather than reformatted.
func SetEncryptedData(content []byte, edits []Edit) ([]byte, error) {
	docs, err := parse(content)
	if err != nil {
		return nil, err
	}
	byDoc := map[int]map[string]string{}
	for _, e := range edits {
		if e.Document < 0 || e.Document >= len(docs) {
			return nil, fmt.Errorf("failed to edit document %d: the file has %d", e.Document, len(docs))
		}
		if len(validation.IsConfigMapKey(e.Key)) > 0 {
			return nil, fmt.Errorf("failed to edit document %d: invalid key %q", e.Document, e.Key)
		}
		if !base64Value.MatchString(e.Value) {
			return nil, fmt.Errorf("failed to edit document %d: the value of %s is not base64", e.Document, e.Key)
		}
		if byDoc[e.Document] == nil {
			byDoc[e.Document] = map[string]string{}
		}
		if _, dup := byDoc[e.Document][e.Key]; dup {
			return nil, fmt.Errorf("failed to edit document %d: %s is set twice", e.Document, e.Key)
		}
		byDoc[e.Document][e.Key] = e.Value
	}

	t := newText(content)
	var ops []op
	for i, set := range byDoc {
		root := documentRoot(docs[i])
		if root == nil || docs[i].Content[0].Kind != yaml.MappingNode {
			return nil, layoutError(i, "it is not a mapping")
		}
		docOps, err := editDocument(t, docs[i].Content[0], set)
		if err != nil {
			return nil, layoutError(i, err.Error())
		}
		ops = append(ops, docOps...)
	}
	out, err := apply(content, ops)
	if err != nil {
		return nil, err
	}
	if err := verify(content, out, edits); err != nil {
		return nil, err
	}
	return out, nil
}

func layoutError(doc int, why string) error {
	return fmt.Errorf("%w: document %d: %s", ErrLayout, doc, why)
}

// op replaces content[start:end] with text; an insertion has start == end.
type op struct {
	start, end int
	text       string
}

func apply(content []byte, ops []op) ([]byte, error) {
	sort.Slice(ops, func(i, j int) bool {
		if ops[i].start != ops[j].start {
			return ops[i].start < ops[j].start
		}
		return ops[i].end < ops[j].end
	})
	var b bytes.Buffer
	b.Grow(len(content))
	at := 0
	for _, o := range ops {
		if o.start < at || o.end < o.start || o.end > len(content) {
			return nil, fmt.Errorf("%w: overlapping edits", ErrLayout)
		}
		b.Write(content[at:o.start])
		b.WriteString(o.text)
		at = o.end
	}
	b.Write(content[at:])
	return b.Bytes(), nil
}

// editDocument returns the operations that set the keys in one document.
func editDocument(t *text, root *yaml.Node, set map[string]string) ([]op, error) {
	specKey, spec := entry(root, "spec")
	switch {
	case spec == nil:
		return nil, errors.New("it has no spec")
	case spec.Kind == yaml.AliasNode || spec.Anchor != "":
		return nil, errors.New("spec uses a YAML anchor or alias")
	case spec.Kind != yaml.MappingNode:
		return nil, errors.New("spec is not a mapping")
	}
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	flowSpec := spec.Style&yaml.FlowStyle != 0
	edKey, ed := entry(spec, "encryptedData")
	switch {
	case ed == nil:
		if flowSpec || len(spec.Content) == 0 {
			return nil, errors.New("spec has no encryptedData")
		}
		indent := spec.Content[0].Column - 1
		var b strings.Builder
		b.WriteString(spaces(indent) + "encryptedData:" + t.nl)
		writeBlockEntries(&b, keys, set, indent+step(specKey, spec.Content[0]), t.nl)
		at, prefix, err := t.after(specKey.Line)
		if err != nil {
			return nil, err
		}
		return []op{{start: at, end: at, text: prefix + b.String()}}, nil

	case ed.Kind == yaml.AliasNode || ed.Anchor != "" || edKey.Kind != yaml.ScalarNode:
		return nil, errors.New("spec.encryptedData uses a YAML anchor or alias")

	case isNull(ed) || (ed.Kind == yaml.MappingNode && len(ed.Content) == 0):
		if flowSpec {
			// {"encryptedData": {}} or null, as in JSON: write the keys inline
			start, end, err := flowTokenSpan(t, ed)
			if err != nil {
				return nil, err
			}
			quoted := edKey.Style&yaml.DoubleQuotedStyle != 0
			return []op{{start: start, end: end, text: inlineMapping(keys, set, quoted)}}, nil
		}
		// "encryptedData:", "encryptedData: ~" or "encryptedData: {}"
		replace, err := emptyValueSpan(t, edKey, ed)
		if err != nil {
			return nil, err
		}
		var b strings.Builder
		writeBlockEntries(&b, keys, set, edKey.Column-1+step(specKey, edKey), t.nl)
		at, prefix, err := t.after(edKey.Line)
		if err != nil {
			return nil, err
		}
		return []op{replace, {start: at, end: at, text: prefix + b.String()}}, nil

	case ed.Kind != yaml.MappingNode:
		return nil, errors.New("spec.encryptedData is not a mapping")
	}

	flow := ed.Style&yaml.FlowStyle != 0
	mapIndent := ed.Content[0].Column - 1
	existing := map[string]int{}
	sorted := true
	for i := 0; i+1 < len(ed.Content); i += 2 {
		k := ed.Content[i]
		if k.Kind != yaml.ScalarNode || k.Value == "<<" {
			return nil, errors.New("spec.encryptedData uses a YAML merge key, anchor or alias")
		}
		if i > 0 && ed.Content[i-2].Value > k.Value {
			sorted = false
		}
		existing[k.Value] = i
	}

	var ops []op
	inserts := map[int][]string{} // offset -> keys inserted there
	afterLine := map[int]bool{}   // whether an insertion offset starts a line
	prefixes := map[int]string{}  // a line break to write first
	for _, key := range keys {
		if i, ok := existing[key]; ok {
			v := ed.Content[i+1]
			start, end, err := valueSpan(t, v, mapIndent, flow)
			if err != nil {
				return nil, err
			}
			quoted := v.Style&yaml.DoubleQuotedStyle != 0
			ops = append(ops, op{start: start, end: end, text: render(set[key], quoted)})
			continue
		}
		if flow {
			// before the first entry, so no comma has to follow the last
			first := ed.Content[0]
			if first.Line > ed.Line {
				at := t.starts[first.Line-1]
				inserts[at] = append(inserts[at], key)
				afterLine[at] = true
			} else {
				at, err := t.offset(first.Line, first.Column)
				if err != nil {
					return nil, err
				}
				inserts[at] = append(inserts[at], key)
			}
			continue
		}
		// block: after the entry the key sorts after, when the keys are
		// sorted, else after the last entry
		line := edKey.Line
		for i := 0; i+1 < len(ed.Content); i += 2 {
			if sorted && ed.Content[i].Value > key {
				break
			}
			line = lastLine(t, ed.Content[i+1], mapIndent)
		}
		at, prefix, err := t.after(line)
		if err != nil {
			return nil, err
		}
		inserts[at] = append(inserts[at], key)
		afterLine[at] = true
		prefixes[at] = prefix
	}

	for at, ks := range inserts {
		sort.Strings(ks)
		var b strings.Builder
		b.WriteString(prefixes[at])
		switch {
		case !flow:
			writeBlockEntries(&b, ks, set, mapIndent, t.nl)
		case afterLine[at]:
			quoted := ed.Content[0].Style&yaml.DoubleQuotedStyle != 0
			for _, k := range ks {
				b.WriteString(spaces(mapIndent) + render(k, quoted) + ": " + render(set[k], quoted) + "," + t.nl)
			}
		default:
			quoted := ed.Content[0].Style&yaml.DoubleQuotedStyle != 0
			for _, k := range ks {
				b.WriteString(render(k, quoted) + ": " + render(set[k], quoted) + ", ")
			}
		}
		ops = append(ops, op{start: at, end: at, text: b.String()})
	}
	return ops, nil
}

// entry returns the key and value nodes for key in a mapping, without
// following aliases.
func entry(m *yaml.Node, key string) (*yaml.Node, *yaml.Node) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Kind == yaml.ScalarNode && m.Content[i].Value == key {
			return m.Content[i], m.Content[i+1]
		}
	}
	return nil, nil
}

func isNull(n *yaml.Node) bool { return n.Kind == yaml.ScalarNode && n.Tag == "!!null" }

// step is the file's indentation step: how much deeper child sits than
// parent.
func step(parent, child *yaml.Node) int {
	if s := child.Column - parent.Column; s > 0 {
		return s
	}
	return 2
}

func spaces(n int) string { return strings.Repeat(" ", n) }

func writeBlockEntries(b *strings.Builder, keys []string, set map[string]string, indent int, nl string) {
	for _, k := range keys {
		b.WriteString(spaces(indent) + render(k, false) + ": " + render(set[k], false) + nl)
	}
}

func inlineMapping(keys []string, set map[string]string, quoted bool) string {
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = render(k, quoted) + ": " + render(set[k], quoted)
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

// render writes a key or base64 value, plain when every YAML parser reads it
// back as the same string, else double-quoted. Keys and values hold no
// quotes or backslashes, so the quoted form needs no escapes and is also
// valid JSON.
func render(s string, quoted bool) string {
	if !quoted && plainSafe.MatchString(s) && !yaml11Words[s] {
		return s
	}
	return `"` + s + `"`
}

// emptyValueSpan returns the operation that clears the value written after
// a block key whose value is empty ("", "~", "null" or "{}"), keeping any
// comment on the line.
func emptyValueSpan(t *text, key, value *yaml.Node) (op, error) {
	colon, err := colonAfter(t, key)
	if err != nil {
		return op{}, err
	}
	end := t.lineEnd(key.Line)
	rest := string(t.b[colon+1 : end])
	token := strings.TrimLeft(rest, " \t")
	comment := ""
	if i := commentStart(token); i >= 0 {
		comment = token[i:]
		token = token[:i]
	}
	token = strings.TrimRight(token, " \t")
	switch {
	case token == "" && value.Line != key.Line:
		return op{}, errors.New("spec.encryptedData's value is on its own line")
	case token == "", token == "~", token == "null", token == "Null", token == "NULL":
	case strings.HasPrefix(token, "{") && strings.HasSuffix(token, "}") && strings.TrimSpace(token[1:len(token)-1]) == "":
	default:
		return op{}, errors.New("spec.encryptedData is written in an unexpected way")
	}
	text := ""
	if comment != "" {
		text = " " + comment
	}
	return op{start: colon + 1, end: end, text: text}, nil
}

// commentStart returns the index of a comment in s, which starts after any
// indentation, or -1.
func commentStart(s string) int {
	if strings.HasPrefix(s, "#") {
		return 0
	}
	for i := 1; i < len(s); i++ {
		if s[i] == '#' && (s[i-1] == ' ' || s[i-1] == '\t') {
			return i
		}
	}
	return -1
}

// colonAfter returns the offset of the ':' that ends a block mapping key.
func colonAfter(t *text, key *yaml.Node) (int, error) {
	start, err := t.offset(key.Line, key.Column)
	if err != nil {
		return 0, err
	}
	line := t.b[start:t.lineEnd(key.Line)]
	var i int
	switch {
	case len(line) > 0 && (line[0] == '"' || line[0] == '\''):
		if i, err = tokenEnd(line, false); err != nil {
			return 0, err
		}
	case bytes.HasPrefix(line, []byte(key.Value)):
		i = len(key.Value)
	default:
		return 0, errors.New("a key is written in an unexpected way")
	}
	for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
		i++
	}
	if i >= len(line) || line[i] != ':' {
		return 0, errors.New("a key is written in an unexpected way")
	}
	return start + i, nil
}

// valueSpan returns where a scalar value is written, without any comment
// after it.
func valueSpan(t *text, v *yaml.Node, mapIndent int, flow bool) (int, int, error) {
	if v.Kind != yaml.ScalarNode || v.Anchor != "" {
		return 0, 0, errors.New("a spec.encryptedData value is not a plain string")
	}
	start, err := t.offset(v.Line, v.Column)
	if err != nil {
		return 0, 0, err
	}
	block := v.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0
	if !flow {
		if last := lastLine(t, v, mapIndent); block || last != v.Line {
			// a value over several lines is replaced whole
			return start, t.lineEnd(last), nil
		}
	} else if block {
		return 0, 0, errors.New("a spec.encryptedData value is a block scalar inside a flow mapping")
	}
	n, err := tokenEnd(t.b[start:t.lineEnd(v.Line)], flow)
	if err != nil {
		return 0, 0, err
	}
	return start, start + n, nil
}

// tokenEnd returns the length of the scalar at the start of line, which must
// end on that line: a quoted string to its closing quote, or a plain one up
// to a comment (or, in flow context, an indicator), without trailing space.
// A leading tag such as !!str is part of the token.
func tokenEnd(line []byte, flow bool) (int, error) {
	i := 0
	if i < len(line) && line[i] == '!' {
		for i < len(line) && line[i] != ' ' && line[i] != '\t' {
			i++
		}
		for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
			i++
		}
	}
	if i >= len(line) {
		return 0, errors.New("a value is written in an unexpected way")
	}
	switch line[i] {
	case '"':
		for j := i + 1; j < len(line); j++ {
			switch line[j] {
			case '\\':
				j++
			case '"':
				return j + 1, nil
			}
		}
		return 0, errors.New("a quoted value spans several lines")
	case '\'':
		for j := i + 1; j < len(line); j++ {
			if line[j] == '\'' {
				if j+1 < len(line) && line[j+1] == '\'' {
					j++
					continue
				}
				return j + 1, nil
			}
		}
		return 0, errors.New("a quoted value spans several lines")
	}
	end := len(line)
	if c := commentStart(string(line[i:])); c >= 0 {
		end = i + c
	}
	if flow {
		if j := bytes.IndexAny(line[i:end], ",}]"); j >= 0 {
			end = i + j
		}
	}
	for end > i && (line[end-1] == ' ' || line[end-1] == '\t') {
		end--
	}
	if end == i {
		return 0, errors.New("a value is written in an unexpected way")
	}
	return end, nil
}

// flowTokenSpan returns where a null or empty mapping inside a flow mapping
// is written.
func flowTokenSpan(t *text, n *yaml.Node) (int, int, error) {
	start, err := t.offset(n.Line, n.Column)
	if err != nil {
		return 0, 0, err
	}
	line := t.b[start:t.lineEnd(n.Line)]
	if n.Kind == yaml.MappingNode {
		close := bytes.IndexByte(line, '}')
		if close < 0 || len(bytes.TrimSpace(line[1:close])) > 0 {
			return 0, 0, errors.New("spec.encryptedData is written in an unexpected way")
		}
		return start, start + close + 1, nil
	}
	if n.Value == "" || !bytes.HasPrefix(line, []byte(n.Value)) {
		return 0, 0, errors.New("spec.encryptedData is written in an unexpected way")
	}
	return start, start + len(n.Value), nil
}

// lastLine returns the last line of a block mapping value: following lines
// indented deeper than the mapping's keys belong to it, except comments
// after a value that is not a block scalar. Trailing blank lines do not.
func lastLine(t *text, v *yaml.Node, mapIndent int) int {
	block := v.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0
	last := v.Line
	for n := v.Line + 1; n <= len(t.starts); n++ {
		line := t.line(n)
		trimmed := bytes.TrimLeft(line, " ")
		if len(bytes.TrimSpace(trimmed)) == 0 {
			continue
		}
		if len(line)-len(trimmed) <= mapIndent || (!block && trimmed[0] == '#') {
			break
		}
		last = n
	}
	return last
}

// verify checks that after decodes to before with exactly the edits made.
func verify(before, after []byte, edits []Edit) error {
	want, err := decodeAll(before)
	if err != nil {
		return err
	}
	got, err := decodeAll(after)
	if err != nil {
		return fmt.Errorf("%w: the edited file does not parse", ErrLayout)
	}
	if len(want) != len(got) {
		return fmt.Errorf("%w: the edit would change the documents", ErrLayout)
	}
	for _, e := range edits {
		if e.Document >= len(want) {
			return fmt.Errorf("%w: document %d is missing", ErrLayout, e.Document)
		}
		root, ok := want[e.Document].(map[string]any)
		if !ok {
			return fmt.Errorf("%w: document %d is not a mapping", ErrLayout, e.Document)
		}
		spec, ok := root["spec"].(map[string]any)
		if !ok {
			return fmt.Errorf("%w: document %d has no spec mapping", ErrLayout, e.Document)
		}
		data, _ := spec["encryptedData"].(map[string]any)
		if data == nil {
			data = map[string]any{}
			spec["encryptedData"] = data
		}
		data[e.Key] = e.Value
	}
	if !reflect.DeepEqual(want, got) {
		return fmt.Errorf("%w: the edit would change more than spec.encryptedData", ErrLayout)
	}
	return nil
}

func decodeAll(content []byte) ([]any, error) {
	dec := yaml.NewDecoder(bytes.NewReader(content))
	var out []any
	for {
		var v any
		err := dec.Decode(&v)
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, ErrInvalidYAML
		}
		out = append(out, v)
	}
}

// text indexes content by line. Lines end at "\n"; a "\r" before it is not
// part of the line.
type text struct {
	b      []byte
	starts []int
	nl     string
}

func newText(b []byte) *text {
	t := &text{b: b, starts: []int{0}, nl: "\n"}
	for i, c := range b {
		if c == '\n' && i+1 < len(b) {
			t.starts = append(t.starts, i+1)
		}
	}
	if bytes.Contains(b, []byte("\r\n")) {
		t.nl = "\r\n"
	}
	return t
}

// line returns line n (from 1) without its line break.
func (t *text) line(n int) []byte { return t.b[t.starts[n-1]:t.lineEnd(n)] }

// lineEnd returns the offset where line n's line break starts.
func (t *text) lineEnd(n int) int {
	end := len(t.b)
	if n < len(t.starts) {
		end = t.starts[n] - 1
	} else if end > 0 && t.b[end-1] == '\n' {
		end--
	}
	if end > t.starts[n-1] && t.b[end-1] == '\r' {
		end--
	}
	return end
}

// after returns where to insert lines after line n, and the line break to
// write first when n is a last line without one.
func (t *text) after(n int) (int, string, error) {
	if n < 1 || n > len(t.starts) {
		return 0, "", errors.New("a position is outside the file")
	}
	if n < len(t.starts) {
		return t.starts[n], "", nil
	}
	if len(t.b) > 0 && t.b[len(t.b)-1] != '\n' {
		return len(t.b), t.nl, nil
	}
	return len(t.b), "", nil
}

// offset converts a line and column (from 1, counting characters) to a byte
// offset.
func (t *text) offset(line, col int) (int, error) {
	if line < 1 || line > len(t.starts) || col < 1 {
		return 0, errors.New("a position is outside the file")
	}
	b := t.line(line)
	at := 0
	for range col - 1 {
		if at >= len(b) {
			break
		}
		_, size := utf8.DecodeRune(b[at:])
		at += size
	}
	return t.starts[line-1] + at, nil
}
