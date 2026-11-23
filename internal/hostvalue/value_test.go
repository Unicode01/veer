package hostvalue

import (
	"errors"
	"math"
	"testing"
)

func TestConversionsFollowJavaScript(t *testing.T) {
	for _, tc := range []struct {
		value   any
		str     string
		boolean bool
		integer int64
	}{
		{nil, "null", false, 0},
		{true, "true", true, 1},
		{false, "false", false, 0},
		{int64(42), "42", true, 42},
		{float64(42), "42", true, 42},
		{1.5, "1.5", true, 1},
		{-1.5, "-1.5", true, -1},
		{1e21, "1e+21", true, math.MaxInt64},
		{1.5e-7, "1.5e-7", true, 0},
		{math.NaN(), "NaN", false, 0},
		{math.Inf(1), "Infinity", true, math.MaxInt64},
		{"", "", false, 0},
		{" 12 ", " 12 ", true, 12},
		{"0x10", "0x10", true, 16},
		{"1e3", "1e3", true, 1000},
		{"12px", "12px", true, 0},
		{"inf", "inf", true, 0},
		{map[string]any{"a": 1}, "[object Object]", true, 0},
		{[]any{int64(1), "x"}, "1,x", true, 0},
		{[]any{"7"}, "7", true, 7},
	} {
		v := ToValue(tc.value)
		if got := v.String(); got != tc.str {
			t.Errorf("String(%#v) = %q, want %q", tc.value, got, tc.str)
		}
		if got := v.ToBoolean(); got != tc.boolean {
			t.Errorf("ToBoolean(%#v) = %v, want %v", tc.value, got, tc.boolean)
		}
		if got := v.ToInteger(); got != tc.integer {
			t.Errorf("ToInteger(%#v) = %d, want %d", tc.value, got, tc.integer)
		}
	}
	if !IsUndefined(Undefined()) || !IsUndefined(nil) || IsUndefined(Null()) || !IsNull(Null()) {
		t.Fatal("undefined/null predicates")
	}
	if Undefined().String() != "undefined" || !math.IsNaN(Undefined().ToFloat()) {
		t.Fatal("undefined conversions")
	}
}

// Integral numbers export as int64, as goja's did; others as float64.
func TestNumbersExportLikeGoja(t *testing.T) {
	if got := ToValue(float64(3)).Export(); got != int64(3) {
		t.Fatalf("Export(3.0) = %#v", got)
	}
	if got := ToValue(3.25).Export(); got != 3.25 {
		t.Fatalf("Export(3.25) = %#v", got)
	}
	if got := ToValue(math.Copysign(0, -1)).Export(); got != math.Copysign(0, -1) {
		t.Fatalf("Export(-0) = %#v", got)
	}
	if got := ToValue(uint64(math.MaxUint64)).Export(); got != float64(math.MaxUint64) {
		t.Fatalf("Export(MaxUint64) = %#v", got)
	}
}

func TestObjectsWrapAndBuild(t *testing.T) {
	r := New()
	data := map[string]any{"name": "eth0", "mtu": float64(1500), "tags": []any{"a", "b"}, "none": nil}
	object := r.ToValue(data).ToObject(r)
	if object.ClassName() != "Object" || object.Get("name").String() != "eth0" || object.Get("mtu").Export() != int64(1500) {
		t.Fatalf("wrapped map = %v / %v", object.Get("name"), object.Get("mtu"))
	}
	if object.Get("missing") != nil {
		t.Fatal("a missing property must be nil, as in goja")
	}
	if !IsNull(object.Get("none")) {
		t.Fatal("a JSON null property is null")
	}
	tags := object.Get("tags").ToObject(r)
	if tags.ClassName() != "Array" || tags.Get("length").ToInteger() != 2 || tags.Get("1").String() != "b" || tags.Get("2") != nil {
		t.Fatalf("wrapped slice = %v", tags.Export())
	}
	if keys := object.Keys(); len(keys) != 4 || keys[0] != "mtu" || keys[3] != "tags" {
		t.Fatalf("map keys = %v, want sorted", keys)
	}

	built := r.NewObject()
	_ = built.Set("z", 1)
	_ = built.Set("a", map[string]any{"x": true})
	_ = built.Set("z", 2)
	if keys := built.Keys(); len(keys) != 2 || keys[0] != "z" || keys[1] != "a" {
		t.Fatalf("built keys = %v, want insertion order", keys)
	}
	exported := built.Export().(map[string]any)
	if exported["z"] != int64(2) || exported["a"].(map[string]any)["x"] != true {
		t.Fatalf("built export = %#v", exported)
	}
	_ = built.Delete("z")
	if built.Get("z") != nil || len(built.Keys()) != 1 {
		t.Fatal("delete")
	}
	func() {
		defer func() {
			if _, ok := recover().(*Exception); !ok {
				t.Fatal("ToObject(null) must throw an Exception")
			}
		}()
		Null().ToObject(r)
	}()
}

func TestFunctionsAndExceptions(t *testing.T) {
	r := New()
	api := r.NewObject()
	_ = api.Set("echo", func(call FunctionCall) Value {
		if len(call.Arguments) == 0 {
			panic(r.NewTypeError("echo: %s is required", "value"))
		}
		return call.Argument(0)
	})
	_ = r.Set("api", api)
	fn, ok := AssertFunction(r.Get("api").ToObject(r).Get("echo"))
	if !ok {
		t.Fatal("echo is not callable")
	}
	result, err := fn(nil, r.ToValue("hi"))
	if err != nil || result.String() != "hi" {
		t.Fatalf("echo = %v, %v", result, err)
	}
	func() {
		defer func() {
			exception, ok := recover().(*Exception)
			if !ok || exception.Error() != "echo: value is required" {
				t.Fatalf("panic = %v", exception)
			}
		}()
		_, _ = fn(nil)
	}()
	if _, ok := AssertFunction(r.ToValue("not a function")); ok {
		t.Fatal("a string is not callable")
	}
	cause := errors.New("disk full")
	if exception := r.NewGoError(cause); exception.Error() != "disk full" || !errors.Is(exception, cause) {
		t.Fatalf("NewGoError = %v", exception)
	}
	if names := r.GlobalNames(); len(names) != 1 || names[0] != "api" {
		t.Fatalf("globals = %v", names)
	}
}
