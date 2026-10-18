package browserlogin

import (
	"context"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
)

// Inspect field presence only, never values or page text. The fill operations
// still run only in the approved top document with their exact origin checks.
func foreignLoginField(ctx context.Context, origin string) bool {
	tree, err := chromedp.Call(ctx, page.GetFrameTree, cdp.Empty{})
	if err != nil || tree.FrameTree == nil {
		return false
	}
	frames := append([]*page.FrameTree(nil), tree.FrameTree.ChildFrames...)
	for len(frames) > 0 {
		frame := frames[0]
		frames = frames[1:]
		frames = append(frames, frame.ChildFrames...)
		if frame.Frame == nil || frame.Frame.SecurityOrigin == origin {
			continue
		}
		world, err := chromedp.Call(ctx, page.CreateIsolatedWorld, page.CreateIsolatedWorldParams{FrameID: frame.Frame.ID, WorldName: "ralx-field-presence"})
		if err != nil {
			continue
		} // A loading or detached frame has no field we can fill.
		found, err := chromedp.Run(ctx, chromedp.Evaluate[bool](`(()=>{const visible=e=>e.getClientRects().length&&!e.disabled;return [...document.querySelectorAll('input[type=password],input[autocomplete=username],input[type=email],input[name=identifier],input[name=username],input[name=email],input[type=text],input:not([type]),input[autocomplete="one-time-code"],input[name=code]')].some(visible)})()`, func(p *runtime.EvaluateParams) { p.ContextID = world.ExecutionContextID }))
		if err == nil && found {
			return true
		}
	}
	return false
}
