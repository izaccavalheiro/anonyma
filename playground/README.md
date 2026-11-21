# anonyma playground

A web page to try anonyma without installing anything: text on the left, the anonymized text on
the right, with presets (several combine), the replacement — redaction, masks, pseudonyms,
synthetic values or reversible `{{EMAIL_1}}` tokens with their vault — the findings, and a
receipt.

Everything runs in the browser, on the library's own source. The page's Content Security Policy
(`connect-src 'none'`, `form-action 'none'`, scripts from the page's own origin only) means that no
script on it can send what is typed anywhere; `npm run check:privacy` fails if that policy is
loosened.

```sh
npm run playground          # http://localhost:8000, rebuilt on change
npm run build:playground    # type-check, then build into playground/dist
```

`playground/dist` is a static site: three files and their source maps. The **Playground**
workflow publishes it to GitHub Pages when started by hand; set the Pages source to GitHub Actions,
and a custom domain such as `play.anonyma.dev`, in the repository settings first.

| File             | What it is                                                                       |
| ---------------- | -------------------------------------------------------------------------------- |
| `index.html`     | The page and its Content Security Policy                                         |
| `src/process.ts` | Text and settings in, output, findings, counts and vault out; tested in `tests/` |
| `src/main.ts`    | The page's behaviour; every value is inserted as text, never as HTML             |
| `src/main.css`   | Styles, light and dark                                                           |
| `build.mjs`      | Bundles with esbuild (which comes with tsup); `--serve` for development          |
