# Two writers on y-arkiv

One file, [main.ts](main.ts), using only the public API of `y-arkiv`: Asha creates a document, Bea asks to join and is added, both type at once, someone with only the link reads along, Asha removes Bea (the key rotates), and `blame` attributes every character to the key that wrote it.

```bash
pnpm install
pnpm --dir packages/y-arkiv build
pnpm --dir examples/two-writers start                 # MemoryChain: no network, no gas
QUIRE_KEY=0x… pnpm --dir examples/two-writers live    # Tiramisu: QUIRE_KEY pays 0.02 test GLM to two fresh keys
```

Expected output on MemoryChain:

```
Bea is now a writer
Asha sees: "Bea adds a line. Asha writes the opening. "
Bea sees:  "Bea adds a line. Asha writes the opening. "
a link holder reads: "Bea adds a line. Asha writes the opening. " (3 queries)
epoch 1; Bea still sees "Bea adds a line. Asha writes the opening. "
  Bea  proven by 0x…  "Bea adds a line. "
  Asha  proven by 0x…  "Asha writes the opening. "
  Asha  proven by 0x…  "Written after Bea left."
```

Bea's line stays proven after she is removed: she wrote it while she was a member. Anything she writes afterwards is ignored.
