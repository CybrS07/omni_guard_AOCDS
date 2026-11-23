# theme/

All colours live in `theme.css` as CSS variables; nothing else in the app uses a raw colour.

- Dark: Midnight Violet `#1C0221`, Brick Ember `#B80C09`, White `#FFFFFF`.
- Light: Coral Glow `#FF7F51`, Imperial Blue `#01295F`, Wine Plum `#702632`.

| File | Job |
|---|---|
| `theme.css` | Palette tokens for both modes (`--text`, `--muted`, `--accent`, ...) |
| `ThemeProvider.jsx` | Chooses dark or light (saved choice, else system), sets `data-theme` on the page |
| `ThemeToggle.jsx` | The button in the sidebar and in Settings |

To re-colour the app change the palette block at the top of `theme.css` only.
