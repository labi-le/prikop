package verifier

import (
	"context"
	"fmt"
	"prikop/internal/verifier/checker"
	"prikop/internal/verifier/types"

	"github.com/rs/zerolog"
)

type GeneralVerifier struct {
	Mode    string
	Targets []types.Target
	Log     zerolog.Logger
}

func NewGeneralVerifier(mode string, log zerolog.Logger) *GeneralVerifier {
	return &GeneralVerifier{Mode: mode, Log: log}
}

func (v *GeneralVerifier) Name() string {
	return fmt.Sprintf("Verifier (%s)", v.Mode)
}

func (v *GeneralVerifier) Run(ctx context.Context) types.CheckResult {
	if len(v.Targets) == 0 {
		return types.CheckResult{Success: false, Details: "No targets defined"}
	}
	return checker.ExecuteChecks(ctx, v.Log, v.Targets)
}
