# openlfcp/server

Application-agnostic reference LFCP server, written in TypeScript for Node.js.

The server stores and coordinates LFCP objects according to LFCP Wire.
It must not understand Markdown, Obsidian Tasks, Task status, or Automerge
object semantics.

## Status

Repository scaffold only. The server bootstrap is LFCP-044.

## Build from a clean checkout

```sh
pnpm install --frozen-lockfile
pnpm run build
pnpm test
```

Requires Node.js 24 or later and pnpm 10.

## License

Apache License 2.0. See [LICENSE](LICENSE).
