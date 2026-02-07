package verifier

import (
	"context"
)

type GeneralVerifier struct {
	Mode string
}

func (v *GeneralVerifier) Name() string { return "General Verifier (HTML Logic)" }

func (v *GeneralVerifier) Run(ctx context.Context) CheckResult {
	return ExecuteChecks(ctx, GeneralTargets)
}
