package main

import (
	"github.com/gogf/gf/v2/os/gctx"
	"github.com/mayugene/gtoken/example/internal/cmd"
	_ "github.com/mayugene/gtoken/example/internal/logic"
)

func main() {
	cmd.Main.Run(gctx.GetInitCtx())
}
