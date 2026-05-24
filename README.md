# Email Checker

A small, single-page Node.js app that checks email addresses in the browser.

## Features

- Lightweight dev server using `index.js`.
- Static UI served from `public/index.html`.
- Simple setup: `npm install` and `npm start`.

## Prerequisites

- Node.js 16+ and npm installed.

## Install

Run:

```bash
npm install
```

## Run (development)

Start the app locally:

```bash
npm start
```

Open your browser at http://localhost:3000 (or the port shown in console).

## Project structure

- `index.js` — app entry / dev server
- `package.json` — project metadata & scripts
- `public/index.html` — frontend UI

## Contributing

Small, focused changes welcome. Open an issue or submit a PR.

## Troubleshooting

- If `npm start` exits immediately, check for errors printed to the console.
- If the port is in use, set `PORT` env var before starting, e.g. `PORT=4000 npm start` on Unix or use PowerShell on Windows:

```powershell
$env:PORT=4000; npm start
```

## License

This project has no license specified.

---


