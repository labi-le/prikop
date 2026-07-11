package nfqws

import (
	"strings"
	"testing"
)

func TestToArgsExact(t *testing.T) {
	tests := []struct {
		name string
		s    Strategy
		want string
	}{
		{
			name: "empty strategy yields no args",
			s:    Strategy{},
			want: "",
		},
		{
			name: "repeats of 1 is omitted",
			s:    Strategy{Mode: "multisplit", Repeats: 1},
			want: "--dpi-desync=multisplit",
		},
		{
			name: "repeats greater than 1 is emitted",
			s:    Strategy{Mode: "multisplit", Repeats: 2},
			want: "--dpi-desync=multisplit --dpi-desync-repeats=2",
		},
		{
			name: "zero increment is skipped",
			s:    Strategy{Mode: "fake", Fooling: FoolingSet{BadSum: true}},
			want: "--dpi-desync=fake --dpi-desync-fooling=badsum",
		},
		{
			name: "negative increment is emitted",
			s:    Strategy{Mode: "fake", Fooling: FoolingSet{BadSum: true, BadSeqIncrement: -10000}},
			want: "--dpi-desync=fake --dpi-desync-fooling=badsum --dpi-desync-badseq-increment=-10000",
		},
		{
			name: "wssize falls back to default when enabled without value",
			s:    Strategy{Mode: "fake", WSS: WSSOptions{Enabled: true}},
			want: "--dpi-desync=fake --wssize=1:6",
		},
		{
			name: "wssize uses explicit value",
			s:    Strategy{Mode: "fake", WSS: WSSOptions{Value: "1:8"}},
			want: "--dpi-desync=fake --wssize=1:8",
		},
		{
			// Verifies phase ordering: main -> fooling -> fake -> split.
			name: "composite keeps phase ordering",
			s: Strategy{
				Mode:    "fake,multisplit",
				Repeats: 3,
				Fooling: FoolingSet{BadSeq: true},
				Fake:    FakeOptions{TLS: "/app/fake/g.bin", TlsMod: "rnd"},
				Split:   SplitOptions{Pos: "1,sniext+1", SeqOvl: 1},
			},
			want: "--dpi-desync=fake,multisplit --dpi-desync-repeats=3 --dpi-desync-fooling=badseq " +
				"--dpi-desync-fake-tls=/app/fake/g.bin --dpi-desync-fake-tls-mod=rnd " +
				"--dpi-desync-split-pos=1,sniext+1 --dpi-desync-split-seqovl=1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.s.String(); got != tc.want {
				t.Fatalf("String() =\n  %q\nwant\n  %q", got, tc.want)
			}
		})
	}
}

func TestToArgsConditionalFakedSplit(t *testing.T) {
	// FakedPattern must only appear when the mode is fakedsplit/fakeddisorder.
	withFaked := Strategy{
		Mode:  "fakedsplit",
		Split: SplitOptions{Pos: "2", FakedPattern: "/app/fake/f.bin", FakedMod: "altorder=1"},
	}
	got := withFaked.String()
	if !strings.Contains(got, "--dpi-desync-fakedsplit-pattern=/app/fake/f.bin") {
		t.Fatalf("expected fakedsplit-pattern in %q", got)
	}
	if !strings.Contains(got, "--dpi-desync-fakedsplit-mod=altorder=1") {
		t.Fatalf("expected fakedsplit-mod in %q", got)
	}

	withoutFaked := Strategy{
		Mode:  "multisplit",
		Split: SplitOptions{Pos: "2", FakedPattern: "/app/fake/f.bin"},
	}
	got = withoutFaked.String()
	if strings.Contains(got, "fakedsplit-pattern") {
		t.Fatalf("did not expect fakedsplit-pattern for multisplit mode: %q", got)
	}
}
