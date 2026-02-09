package verifier

import (
	"context"
	"fmt"

	"github.com/rs/zerolog"
)

type GeneralVerifier struct {
	Mode    string
	Targets []Target
	log     zerolog.Logger
}

func (v *GeneralVerifier) Name() string {
	return fmt.Sprintf("Verifier (%s)", v.Mode)
}

func (v *GeneralVerifier) Run(ctx context.Context) CheckResult {
	if len(v.Targets) == 0 {
		return CheckResult{Success: false, Details: "No targets defined"}
	}
	return ExecuteChecks(ctx, v.log, v.Targets)
}
