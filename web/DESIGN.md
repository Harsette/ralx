# RalX local app polish

18 October 2026. Implementation follows the supplied Opus v0.1.0 review.
The accepted `wt-landing/site/DESIGN.md` supplies the brand and typography.
Existing components, routes and account flows remain in place.

The user connects accounts, gives agents access, and approves held actions.
Desktop content is 1040px wide inside its padding. Manrope body and row titles
are 15px, secondary copy is at least 13px, Space Grotesk page titles are 28px
and section headings are 18px. The secondary ink is dark enough for bone.
Buttons have more height. Phone content keeps its existing layout.

Onboarding uses the same navy, bone and brass, existing RalX mark, locally
hosted Instrument Serif italic phrase, and three plain progress steps.
Button copy follows Windows Hello, Touch ID or passkey for the current platform.
An expired setup link gives an inline command to create another one.

Protection notes start collapsed with a count, neutral colour and one copyable
fix command per known issue. Optional Google app setup is separate. Agent use
comes from the latest saved call or recorded audit event, without event counts.

Rendered desktop and phone evidence belongs in
`ui-review-20261018/after/`. Opus acceptance remains with the coordinating parent.
