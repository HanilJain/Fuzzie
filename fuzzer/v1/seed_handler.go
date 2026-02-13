package main

import (
    "bytes"
    "encoding/binary"
    "encoding/json"
    "fmt"
    "reflect"
    "math"
)

// TLVItem represents a single Type-Length-Value entry.
type TLVItem struct {
    Type string      `json:"type"`  // Type as string (e.g., "string", "int")
    Name string      `json:"name"`  // Human-readable name
    Len  int         `json:"len"`   // Length of value
    Value interface{} `json:"value"` // Original Go value (any)
    Raw   []byte     `json:"raw,omitempty"` // Serialized bytes for TLV
}

// NewTLVItem creates and stores a TLVItem from inputs.
// Converts value to bytes based on its type, stores raw bytes.
// Supports common types: string, int*, uint*, float*, bool, []byte.
// For complex types, uses JSON marshaling as fallback [web:2].
func NewTLVItem(typ string, leng int, value interface{}, name string) (*TLVItem, error) {
	item := &TLVItem{
		Type:  typ,
		Name:  name,
		Len:   leng,
		Value: value,
	}

	var raw []byte
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.String:
		raw = []byte(v.String())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		raw = make([]byte, 8)
		binary.LittleEndian.PutUint64(raw, uint64(v.Int()))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		raw = make([]byte, 8)
		binary.LittleEndian.PutUint64(raw, v.Uint())
	case reflect.Float32, reflect.Float64:
		raw = make([]byte, 8)
		binary.LittleEndian.PutUint64(raw, math.Float64bits(v.Float()))
	case reflect.Bool:
		if v.Bool() {
			raw = []byte{1}
		} else {
			raw = []byte{0}
		}
	case reflect.Slice:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			raw = v.Bytes()
		} else {
			data, err := json.Marshal(value)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal value: %w", err)
			}
			raw = data
		}
	default:
		data, err := json.Marshal(value)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal value: %w", err)
		}
		raw = data
	}

	if len(raw) != leng {
		return nil, fmt.Errorf("value length %d does not match provided leng %d", len(raw), leng)
	}

	item.Raw = raw
	item.Len = leng // Update if needed, but validate match
	return item, nil
}

// EncodeTLV encodes TLVItem to raw TLV bytes (2-byte tag, 2-byte len, value) [web:2].
func (i *TLVItem) EncodeTLV(tag uint16) []byte {
    var buf bytes.Buffer
    // Tag (2 bytes)
    binary.BigEndian.PutUint16(buf.Bytes()[:2], tag) // Assume tag provided externally
    tagBytes := buf.Bytes()
    buf.Reset()
    binary.BigEndian.PutUint16(buf.Bytes()[:2], tag)
    buf.Write(tagBytes)
    // Length (2 bytes)
    binary.BigEndian.PutUint16(buf.Bytes()[2:4], uint16(i.Len))
    // Value
    buf.Write(i.Raw)
    return buf.Bytes()
}

// Example usage.
func main() {
    v := "0x01"
    item1, err := NewTLVItem("string", len(v), v, "Protocol Version")
    if err != nil {
        panic(err)
    }
    fmt.Printf("%+v\n", item1) // Stores in struct

    item2, err := NewTLVItem("int", 8,int64(0x000000000000001), "Replay Counter")
    if err != nil {
        panic(err)
    }
    fmt.Printf("%+v\n", item2)

    // For fuzzer integration, collect []TLVItem and encode to full TLV stream
}
