# Component Health figures were unreadable at the values that matter

**Date:** 2026-07-29

**Area:** `platform/frontend/src/pages/ComponentHealth.jsx`, `platform/frontend/src/theme.css`

**Status:** fixed

## Defect

Two layout faults on the Component Health page, both obscuring the number rather than the
decoration.

**Percentage centred over the usage bar.** The label sat in the middle of the track with the
fill drawn beneath it, so wherever the fill edge crossed the text, that character lost its
contrast. At mid-range values the edge lands mid-label: `49.8%` read as `49|8%`, with the
decimal point the casualty. Worst precisely in the middle of the range, and clean at 0% and
100% where nobody needs to read it carefully.

**Memory row overflowing.** `host (no container limit)` is a wide label. With the bar and its
percentage beside it, the value had nowhere left to go, wrapped to a second line, and landed
on top of the percentage — `38.1%` printed through `14.0 GB free`.

## Changes

The percentage now sits beside the track rather than on it, in its own fixed-width column, so
nothing is ever drawn behind text.

Metric rows no longer wrap. The label is the only element allowed to give way, shrinking and
ellipsing; the value is `nowrap` and holds its width. A wrapped value is what collided with
the row above it.

The memory label reads `host (uncapped)`, with the explanation moved to a tooltip. The
parenthetical was stating what the absent cgroup row already shows.

## Verification

Frontend image builds and the styles are live in the served bundle. Both figures render on one
line at every value the deployed components report, including the 49.8% case that exposed the
first fault.

## Note

Neither fault was visible in the values a freshly-deployed stack produces: empty volumes read
0% and full ones 100%, and both render cleanly. They appeared once real components reported
mid-range usage. A screenshot taken at the wrong moment would have shown a page that looked
correct.
