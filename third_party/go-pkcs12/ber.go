package pkcs12

import "fmt"

// normalizeBER converts ASN.1 wrappers to definite lengths, without interpreting
// primitive payloads (which can contain ciphertext or MAC-authenticated bytes).
func normalizeBER(in []byte) ([]byte, error) {
	out, consumed, err := berElement(in, 0)
	if err != nil {
		return nil, fmt.Errorf("pkcs12: invalid BER: %w", err)
	}
	if consumed != len(in) {
		return nil, fmt.Errorf("pkcs12: trailing data found")
	}
	return out, nil
}

func berElement(in []byte, depth int) ([]byte, int, error) {
	if depth > 64 {
		return nil, 0, fmt.Errorf("nesting limit exceeded")
	}
	if len(in) < 2 {
		return nil, 0, fmt.Errorf("truncated tag or length")
	}
	tagEnd := 1
	if in[0]&0x1f == 0x1f {
		for {
			if tagEnd >= len(in) || tagEnd > 6 {
				return nil, 0, fmt.Errorf("invalid high tag number")
			}
			b := in[tagEnd]
			tagEnd++
			if b&0x80 == 0 {
				break
			}
		}
	}
	if tagEnd >= len(in) {
		return nil, 0, fmt.Errorf("missing length")
	}
	if in[0] == 0 {
		return nil, 0, fmt.Errorf("unexpected end-of-contents")
	}
	pos := tagEnd + 1
	firstLength := in[tagEnd]
	indefinite := firstLength == 0x80
	length := int(firstLength)
	if firstLength > 0x80 {
		n := int(firstLength & 0x7f)
		if n > 8 || n > len(in)-pos {
			return nil, 0, fmt.Errorf("invalid long length")
		}
		length = 0
		for _, b := range in[pos : pos+n] {
			// Bound before multiplying to avoid overflow on 32-bit systems.
			if length > len(in)/256 {
				return nil, 0, fmt.Errorf("length exceeds input")
			}
			length = length*256 + int(b)
			if length > len(in) {
				return nil, 0, fmt.Errorf("length exceeds input")
			}
		}
		pos += n
	}
	constructed := in[0]&0x20 != 0
	if indefinite && !constructed {
		return nil, 0, fmt.Errorf("primitive with indefinite length")
	}
	end := len(in)
	if !indefinite {
		if length > len(in)-pos {
			return nil, 0, fmt.Errorf("truncated content")
		}
		end = pos + length
	}
	tag := in[:tagEnd]
	var content []byte
	if !constructed {
		content = in[pos:end]
		pos = end
	} else {
		for {
			if indefinite {
				if len(in)-pos < 2 {
					return nil, 0, fmt.Errorf("missing end-of-contents")
				}
				if in[pos] == 0 && in[pos+1] == 0 {
					pos += 2
					break
				}
			} else if pos == end {
				break
			}
			child, consumed, err := berElement(in[pos:end], depth+1)
			if err != nil {
				return nil, 0, err
			}
			pos += consumed
			if in[0] == 0x24 { // Constructed universal OCTET STRING.
				if child[0] != 0x04 {
					return nil, 0, fmt.Errorf("non-octet child in OCTET STRING")
				}
				header := 2
				if child[1]&0x80 != 0 {
					header += int(child[1] & 0x7f)
				}
				content = append(content, child[header:]...)
			} else {
				content = append(content, child...)
			}
		}
		if in[0] == 0x24 {
			tag = []byte{0x04}
		}
	}
	out := append([]byte(nil), tag...)
	if len(content) < 128 {
		out = append(out, byte(len(content)))
	} else {
		var encoded [8]byte
		n, v := 0, len(content)
		for v > 0 {
			n++
			encoded[len(encoded)-n] = byte(v)
			v >>= 8
		}
		out = append(out, 0x80|byte(n))
		out = append(out, encoded[len(encoded)-n:]...)
	}
	out = append(out, content...)
	return out, pos, nil
}
