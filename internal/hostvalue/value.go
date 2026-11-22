// Package hostvalue is the value model of the plugin host API bindings:
// call arguments and results are JSON-shaped values, host-built objects and
// host functions. It keeps the small part of the goja API the bindings were
// written against (FunctionCall, Value, Object, Runtime, Exception), with
// JavaScript's conversion rules, but it has no interpreter: plugins are
// native code and reach the bindings through the host's method dispatch.
package hostvalue

import (
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

// Value is one argument or result.
type Value interface {
	// Export returns the Go value: nil, bool, int64, float64, string, the
	// Go map/slice a wrapped object was made from, or a map[string]any of
	// a host-built object's properties.
	Export() any
	// String converts like JavaScript's String(value).
	String() string
	// ToBoolean converts like JavaScript's Boolean(value).
	ToBoolean() bool
	// ToInteger converts like JavaScript's ToIntegerOrInfinity, with NaN
	// as 0 and the infinities clamped to the int64 range.
	ToInteger() int64
	// ToFloat converts like JavaScript's Number(value).
	ToFloat() float64
	// ToObject returns the value as an object; null and undefined throw.
	ToObject(*Runtime) *Object
}

// FunctionCall is one call of a host function.
type FunctionCall struct {
	This      Value
	Arguments []Value
}

// Argument returns argument i, or undefined.
func (call FunctionCall) Argument(i int) Value {
	if i >= 0 && i < len(call.Arguments) {
		return call.Arguments[i]
	}
	return Undefined()
}

// Function is a host function.
type Function func(FunctionCall) Value

// Callable calls a host function value.
type Callable func(this Value, args ...Value) (Value, error)

type undefinedValue struct{}
type nullValue struct{}
type boolValue bool
type intValue int64
type floatValue float64
type stringValue string

var (
	undefinedSingleton Value = undefinedValue{}
	nullSingleton      Value = nullValue{}
)

func Undefined() Value { return undefinedSingleton }
func Null() Value      { return nullSingleton }

// IsUndefined reports whether v is undefined; a missing value (nil) counts
// as undefined.
func IsUndefined(v Value) bool {
	if v == nil {
		return true
	}
	_, ok := v.(undefinedValue)
	return ok
}

func IsNull(v Value) bool {
	_, ok := v.(nullValue)
	return ok
}

// AssertFunction returns a callable for a host function value.
func AssertFunction(v Value) (Callable, bool) {
	object, ok := v.(*Object)
	if !ok || object.fn == nil {
		return nil, false
	}
	return func(this Value, args ...Value) (Value, error) {
		if this == nil {
			this = Undefined()
		}
		result := object.fn(FunctionCall{This: this, Arguments: args})
		if result == nil {
			result = Undefined()
		}
		return result, nil
	}, true
}

func (undefinedValue) Export() any        { return nil }
func (undefinedValue) String() string     { return "undefined" }
func (undefinedValue) ToBoolean() bool    { return false }
func (undefinedValue) ToInteger() int64   { return 0 }
func (undefinedValue) ToFloat() float64   { return math.NaN() }
func (undefinedValue) ToObject(r *Runtime) *Object {
	panic(r.NewTypeError("Cannot convert undefined or null to object"))
}

func (nullValue) Export() any      { return nil }
func (nullValue) String() string   { return "null" }
func (nullValue) ToBoolean() bool  { return false }
func (nullValue) ToInteger() int64 { return 0 }
func (nullValue) ToFloat() float64 { return 0 }
func (nullValue) ToObject(r *Runtime) *Object {
	panic(r.NewTypeError("Cannot convert undefined or null to object"))
}

func (v boolValue) Export() any { return bool(v) }
func (v boolValue) String() string {
	if v {
		return "true"
	}
	return "false"
}
func (v boolValue) ToBoolean() bool { return bool(v) }
func (v boolValue) ToInteger() int64 {
	if v {
		return 1
	}
	return 0
}
func (v boolValue) ToFloat() float64            { return float64(v.ToInteger()) }
func (v boolValue) ToObject(*Runtime) *Object { return &Object{class: "Boolean", primitive: v} }

func (v intValue) Export() any                 { return int64(v) }
func (v intValue) String() string              { return strconv.FormatInt(int64(v), 10) }
func (v intValue) ToBoolean() bool             { return v != 0 }
func (v intValue) ToInteger() int64            { return int64(v) }
func (v intValue) ToFloat() float64            { return float64(v) }
func (v intValue) ToObject(*Runtime) *Object { return &Object{class: "Number", primitive: v} }

func (v floatValue) Export() any               { return float64(v) }
func (v floatValue) String() string            { return formatNumber(float64(v)) }
func (v floatValue) ToBoolean() bool           { return v != 0 && !math.IsNaN(float64(v)) }
func (v floatValue) ToInteger() int64          { return floatToInteger(float64(v)) }
func (v floatValue) ToFloat() float64          { return float64(v) }
func (v floatValue) ToObject(*Runtime) *Object { return &Object{class: "Number", primitive: v} }

func (v stringValue) Export() any                 { return string(v) }
func (v stringValue) String() string              { return string(v) }
func (v stringValue) ToBoolean() bool             { return v != "" }
func (v stringValue) ToInteger() int64            { return floatToInteger(stringToNumber(string(v))) }
func (v stringValue) ToFloat() float64            { return stringToNumber(string(v)) }
func (v stringValue) ToObject(*Runtime) *Object { return &Object{class: "String", primitive: v} }

// Object is a host-built object (NewObject, then Set), a host function, or
// a view of a Go map, slice or struct.
type Object struct {
	class     string
	keys      []string
	props     map[string]Value
	fn        Function
	goValue   any
	wrapped   bool
	primitive Value
}

// ClassName is "Object", "Array", "Function", or the primitive wrapper's.
func (o *Object) ClassName() string { return o.class }

func (o *Object) Export() any {
	switch {
	case o.fn != nil:
		return o.fn
	case o.wrapped:
		return o.goValue
	case o.primitive != nil:
		return o.primitive.Export()
	}
	out := make(map[string]any, len(o.keys))
	for _, key := range o.keys {
		out[key] = o.props[key].Export()
	}
	return out
}

func (o *Object) String() string {
	switch {
	case o.primitive != nil:
		return o.primitive.String()
	case o.fn != nil:
		return "function () { [native code] }"
	case o.class == "Array":
		length := o.length()
		parts := make([]string, length)
		for i := range parts {
			item := o.Get(strconv.Itoa(i))
			if item != nil && !IsUndefined(item) && !IsNull(item) {
				parts[i] = item.String()
			}
		}
		return strings.Join(parts, ",")
	}
	return "[object Object]"
}

func (o *Object) ToBoolean() bool { return true }

func (o *Object) ToFloat() float64 {
	if o.primitive != nil {
		return o.primitive.ToFloat()
	}
	if o.class == "Array" {
		switch o.length() {
		case 0:
			return 0
		case 1:
			if item := o.Get("0"); item != nil {
				return stringToNumber(item.String())
			}
		}
	}
	return math.NaN()
}

func (o *Object) ToInteger() int64          { return floatToInteger(o.ToFloat()) }
func (o *Object) ToObject(*Runtime) *Object { return o }

// Get returns a property, or nil when the object has none of that name.
func (o *Object) Get(name string) Value {
	if o.wrapped {
		return getGo(o.goValue, name)
	}
	if o.props == nil {
		return nil
	}
	return o.props[name]
}

// Set sets a property. On a wrapped Go map it stores the exported value.
func (o *Object) Set(name string, value any) error {
	if o.wrapped {
		if m, ok := o.goValue.(map[string]any); ok {
			m[name] = ToValue(value).Export()
			return nil
		}
		return fmt.Errorf("cannot set property %s of a %T", name, o.goValue)
	}
	if o.fn != nil || o.primitive != nil {
		return fmt.Errorf("cannot set property %s of a %s", name, o.class)
	}
	if o.props == nil {
		o.props = make(map[string]Value)
	}
	if _, ok := o.props[name]; !ok {
		o.keys = append(o.keys, name)
	}
	o.props[name] = ToValue(value)
	return nil
}

func (o *Object) Delete(name string) error {
	if o.wrapped {
		if m, ok := o.goValue.(map[string]any); ok {
			delete(m, name)
			return nil
		}
		return fmt.Errorf("cannot delete property %s of a %T", name, o.goValue)
	}
	if _, ok := o.props[name]; !ok {
		return nil
	}
	delete(o.props, name)
	for i, key := range o.keys {
		if key == name {
			o.keys = append(o.keys[:i], o.keys[i+1:]...)
			break
		}
	}
	return nil
}

// Keys lists the own property names: insertion order for host-built
// objects, sorted for maps, indexes for arrays.
func (o *Object) Keys() []string {
	if !o.wrapped {
		return append([]string(nil), o.keys...)
	}
	rv := reflect.ValueOf(o.goValue)
	switch rv.Kind() {
	case reflect.Map:
		keys := make([]string, 0, rv.Len())
		for _, key := range rv.MapKeys() {
			keys = append(keys, fmt.Sprint(key.Interface()))
		}
		sort.Strings(keys)
		return keys
	case reflect.Slice, reflect.Array:
		keys := make([]string, rv.Len())
		for i := range keys {
			keys[i] = strconv.Itoa(i)
		}
		return keys
	case reflect.Pointer:
		if rv.IsNil() {
			return nil
		}
		rv = rv.Elem()
		fallthrough
	case reflect.Struct:
		if rv.Kind() != reflect.Struct {
			return nil
		}
		keys := make([]string, 0, rv.NumField())
		for i := 0; i < rv.NumField(); i++ {
			if rv.Type().Field(i).IsExported() {
				keys = append(keys, rv.Type().Field(i).Name)
			}
		}
		return keys
	}
	return nil
}

func (o *Object) length() int {
	if o.wrapped {
		rv := reflect.ValueOf(o.goValue)
		if rv.Kind() == reflect.Slice || rv.Kind() == reflect.Array {
			return rv.Len()
		}
		return 0
	}
	if length := o.Get("length"); length != nil {
		return int(length.ToInteger())
	}
	return 0
}

func getGo(value any, name string) Value {
	switch typed := value.(type) {
	case map[string]any:
		item, ok := typed[name]
		if !ok {
			return nil
		}
		return ToValue(item)
	case []any:
		if name == "length" {
			return intValue(len(typed))
		}
		if index, ok := arrayIndex(name); ok && index < len(typed) {
			return ToValue(typed[index])
		}
		return nil
	}
	rv := reflect.ValueOf(value)
	switch rv.Kind() {
	case reflect.Map:
		if rv.Type().Key().Kind() != reflect.String {
			return nil
		}
		item := rv.MapIndex(reflect.ValueOf(name).Convert(rv.Type().Key()))
		if !item.IsValid() {
			return nil
		}
		return ToValue(item.Interface())
	case reflect.Slice, reflect.Array:
		if name == "length" {
			return intValue(rv.Len())
		}
		if index, ok := arrayIndex(name); ok && index < rv.Len() {
			return ToValue(rv.Index(index).Interface())
		}
		return nil
	case reflect.Pointer:
		if rv.IsNil() {
			return nil
		}
		rv = rv.Elem()
		if rv.Kind() != reflect.Struct {
			return nil
		}
		fallthrough
	case reflect.Struct:
		field := rv.FieldByName(name)
		if !field.IsValid() || !field.CanInterface() {
			return nil
		}
		return ToValue(field.Interface())
	}
	return nil
}

func arrayIndex(name string) (int, bool) {
	if name == "" || (len(name) > 1 && name[0] == '0') {
		return 0, false
	}
	index, err := strconv.Atoi(name)
	if err != nil || index < 0 {
		return 0, false
	}
	return index, true
}

// ToValue converts a Go value. Integral floats become integers, as in goja,
// so Export returns int64 for them.
func ToValue(value any) Value {
	switch typed := value.(type) {
	case nil:
		return Null()
	case Value:
		if object, ok := typed.(*Object); ok && object == nil {
			return Null()
		}
		return typed
	case bool:
		return boolValue(typed)
	case string:
		return stringValue(typed)
	case int:
		return intValue(typed)
	case int8:
		return intValue(typed)
	case int16:
		return intValue(typed)
	case int32:
		return intValue(typed)
	case int64:
		return intValue(typed)
	case uint:
		return uintToValue(uint64(typed))
	case uint8:
		return intValue(typed)
	case uint16:
		return intValue(typed)
	case uint32:
		return intValue(typed)
	case uint64:
		return uintToValue(typed)
	case float32:
		return numberToValue(float64(typed))
	case float64:
		return numberToValue(typed)
	case json.Number:
		if number, err := typed.Float64(); err == nil {
			return numberToValue(number)
		}
		return stringValue(typed.String())
	case Function:
		return &Object{class: "Function", fn: typed}
	case func(FunctionCall) Value:
		return &Object{class: "Function", fn: typed}
	case map[string]any:
		if typed == nil {
			return Null()
		}
		return &Object{class: "Object", goValue: typed, wrapped: true}
	case []any:
		if typed == nil {
			return Null()
		}
		return &Object{class: "Array", goValue: typed, wrapped: true}
	}
	rv := reflect.ValueOf(value)
	switch rv.Kind() {
	case reflect.Map, reflect.Slice, reflect.Pointer, reflect.Interface, reflect.Func:
		if rv.IsNil() {
			return Null()
		}
	}
	switch rv.Kind() {
	case reflect.Slice, reflect.Array:
		return &Object{class: "Array", goValue: value, wrapped: true}
	case reflect.Func:
		return &Object{class: "Function", goValue: value, wrapped: true}
	case reflect.String:
		return stringValue(rv.String())
	case reflect.Bool:
		return boolValue(rv.Bool())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return intValue(rv.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return uintToValue(rv.Uint())
	case reflect.Float32, reflect.Float64:
		return numberToValue(rv.Float())
	}
	return &Object{class: "Object", goValue: value, wrapped: true}
}

func uintToValue(value uint64) Value {
	if value > math.MaxInt64 {
		return floatValue(float64(value))
	}
	return intValue(value)
}

func numberToValue(value float64) Value {
	if value == math.Trunc(value) && value >= -(1<<53) && value <= 1<<53 && !(value == 0 && math.Signbit(value)) {
		return intValue(int64(value))
	}
	return floatValue(value)
}

func floatToInteger(value float64) int64 {
	switch {
	case math.IsNaN(value):
		return 0
	case value >= math.MaxInt64:
		return math.MaxInt64
	case value <= math.MinInt64:
		return math.MinInt64
	}
	return int64(math.Trunc(value))
}

// stringToNumber converts like JavaScript's Number(string).
func stringToNumber(text string) float64 {
	text = strings.TrimFunc(text, isJSWhitespace)
	if text == "" {
		return 0
	}
	switch text {
	case "Infinity", "+Infinity":
		return math.Inf(1)
	case "-Infinity":
		return math.Inf(-1)
	}
	if len(text) > 2 && text[0] == '0' {
		base := 0
		switch text[1] {
		case 'x', 'X':
			base = 16
		case 'o', 'O':
			base = 8
		case 'b', 'B':
			base = 2
		}
		if base != 0 {
			number, err := strconv.ParseUint(text[2:], base, 64)
			if err != nil || strings.Contains(text, "_") {
				return math.NaN()
			}
			return float64(number)
		}
	}
	for _, r := range text {
		if !(r >= '0' && r <= '9') && r != '.' && r != 'e' && r != 'E' && r != '+' && r != '-' {
			return math.NaN()
		}
	}
	number, err := strconv.ParseFloat(text, 64)
	if err != nil {
		if numErr, ok := err.(*strconv.NumError); ok && numErr.Err == strconv.ErrRange {
			return number
		}
		return math.NaN()
	}
	return number
}

func isJSWhitespace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ', 0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff:
		return true
	}
	return r >= 0x2000 && r <= 0x200a
}

// formatNumber formats like JavaScript's Number.prototype.toString().
func formatNumber(value float64) string {
	switch {
	case math.IsNaN(value):
		return "NaN"
	case math.IsInf(value, 1):
		return "Infinity"
	case math.IsInf(value, -1):
		return "-Infinity"
	case value == 0:
		return "0"
	}
	abs := math.Abs(value)
	if abs >= 1e21 || abs < 1e-6 {
		text := strconv.FormatFloat(value, 'e', -1, 64)
		mantissa, exponent, _ := strings.Cut(text, "e")
		sign := exponent[:1]
		digits := strings.TrimLeft(exponent[1:], "0")
		if digits == "" {
			digits = "0"
		}
		return mantissa + "e" + sign + digits
	}
	return strconv.FormatFloat(value, 'f', -1, 64)
}

// Exception is a thrown host error; its message is what a caller reads as
// the error message.
type Exception struct {
	message string
	err     error
}

func (e *Exception) Error() string  { return e.message }
func (e *Exception) String() string { return e.message }
func (e *Exception) Unwrap() error  { return e.err }

// Runtime holds the global host API objects.
type Runtime struct {
	globals map[string]Value
	names   []string
}

func New() *Runtime { return &Runtime{globals: make(map[string]Value)} }

func (r *Runtime) NewObject() *Object { return &Object{class: "Object"} }

func (r *Runtime) ToValue(value any) Value { return ToValue(value) }

func (r *Runtime) Set(name string, value any) error {
	if _, ok := r.globals[name]; !ok {
		r.names = append(r.names, name)
	}
	r.globals[name] = ToValue(value)
	return nil
}

// Get returns a global, or nil.
func (r *Runtime) Get(name string) Value { return r.globals[name] }

// GlobalNames lists the globals in the order they were set.
func (r *Runtime) GlobalNames() []string { return append([]string(nil), r.names...) }

// NewTypeError makes an exception from a format and its arguments.
func (r *Runtime) NewTypeError(args ...any) *Exception {
	message := ""
	if len(args) > 0 {
		format, _ := args[0].(string)
		message = fmt.Sprintf(format, args[1:]...)
	}
	return &Exception{message: message}
}

func (r *Runtime) NewGoError(err error) *Exception {
	if err == nil {
		return &Exception{message: "error"}
	}
	return &Exception{message: err.Error(), err: err}
}
