package mcp

import "fmt"

const DefaultToolResultMaxBytes = 12000

// NormalizeToolResultForStorage returns the canonical result used by both the
// agent-facing response and monitor persistence.
func NormalizeToolResultForStorage(result *ToolResult, maxBytes int) *ToolResult {
	if result == nil {
		return nil
	}
	out := cloneToolResult(result)
	if maxBytes <= 0 {
		return out
	}

	total := 0
	for _, c := range out.Content {
		if c.Type == "text" {
			total += len(c.Text)
		}
	}
	if total <= maxBytes {
		return out
	}

	remaining := maxBytes
	truncated := false
	for i := range out.Content {
		if out.Content[i].Type != "text" {
			continue
		}
		if remaining <= 0 {
			out.Content[i].Text = ""
			truncated = true
			continue
		}
		text := out.Content[i].Text
		if len(text) <= remaining {
			remaining -= len(text)
			continue
		}
		out.Content[i].Text = truncateUTF8Bytes(text, remaining)
		remaining = 0
		truncated = true
	}

	if truncated {
		marker := fmt.Sprintf("\n\n...[tool output truncated: original %d bytes, kept %d bytes]...", total, maxBytes)
		textBudget := maxBytes - len(marker)
		if textBudget < 0 {
			marker = truncateUTF8Bytes(marker, maxBytes)
			textBudget = 0
		}
		for i := range out.Content {
			if out.Content[i].Type == "text" {
				out.Content[i].Text = truncateUTF8Bytes(out.Content[i].Text, textBudget) + marker
				remaining = 0
				for j := range out.Content {
					if j != i && out.Content[j].Type == "text" {
						out.Content[j].Text = ""
					}
				}
				return out
			}
		}
		out.Content = append(out.Content, Content{Type: "text", Text: marker})
	}
	return out
}

func cloneToolResult(in *ToolResult) *ToolResult {
	if in == nil {
		return nil
	}
	out := *in
	if in.Content != nil {
		out.Content = append([]Content(nil), in.Content...)
	}
	return &out
}

func truncateUTF8Bytes(s string, maxBytes int) string {
	if maxBytes <= 0 {
		return ""
	}
	if len(s) <= maxBytes {
		return s
	}
	cut := maxBytes
	for cut > 0 && (s[cut]&0xC0) == 0x80 {
		cut--
	}
	if cut <= 0 {
		return ""
	}
	return s[:cut]
}
