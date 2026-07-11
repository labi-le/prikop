package nfqws2

import "testing"

func TestToArgsEmpty(t *testing.T) {
	if got := (Strategy{}).String(); got != "" {
		t.Fatalf("empty strategy String() = %q, want empty", got)
	}
}

func TestToArgsCanonical(t *testing.T) {
	// Mirrors the fake+multisplit example from the zapret2 README: the v1
	// "fake,multisplit" directive becomes two ordered lua-desync instances.
	s := Strategy{
		Filter: Filter{
			TCP:     "80,443",
			L7:      []string{"tls", "http"},
			Payload: []string{"tls_client_hello"},
		},
		Actions: []Action{
			{Func: "fake", Params: []Param{P("blob", "fake_default_tls"), Flag("tcp_md5"), P("tls_mod", "rnd,rndsni,dupsid")}},
			{Func: "multisplit", Params: []Param{P("pos", "1"), P("seqovl", "5"), P("seqovl_pattern", "0x1603030000")}},
		},
	}
	want := "--filter-tcp=80,443 --filter-l7=tls,http --payload=tls_client_hello " +
		"--lua-desync=fake:blob=fake_default_tls:tcp_md5:tls_mod=rnd,rndsni,dupsid " +
		"--lua-desync=multisplit:pos=1:seqovl=5:seqovl_pattern=0x1603030000"
	if got := s.String(); got != want {
		t.Fatalf("String() =\n  %q\nwant\n  %q", got, want)
	}
}

func TestActionBooleanFlag(t *testing.T) {
	a := Action{Func: "send", Params: []Param{Flag("badsum"), P("repeats", "3")}}
	want := "--lua-desync=send:badsum:repeats=3"
	if got := a.arg(); got != want {
		t.Fatalf("arg() = %q, want %q", got, want)
	}
}

func TestUDPProfile(t *testing.T) {
	s := Strategy{
		Filter:  Filter{UDP: "443", L7: []string{"quic"}, Payload: []string{"quic_initial"}},
		Actions: []Action{{Func: "fake", Params: []Param{P("blob", "fake_default_quic"), P("repeats", "6")}}},
	}
	want := "--filter-udp=443 --filter-l7=quic --payload=quic_initial " +
		"--lua-desync=fake:blob=fake_default_quic:repeats=6"
	if got := s.String(); got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}
