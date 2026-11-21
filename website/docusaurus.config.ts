import type * as Preset from "@docusaurus/preset-classic";
import type { Config } from "@docusaurus/types";
import { themes as prismThemes } from "prism-react-renderer";

const repository = "https://github.com/izaccavalheiro/anonyma";

/**
 * The privacy guarantee of the whole site, the playground included: no script
 * on it can open a connection (connect-src 'none'), submit a form, or load
 * anything from another origin. Docusaurus inlines a small script that sets
 * the colour mode before the page paints, hence 'unsafe-inline' for scripts;
 * with connect-src 'none' and same-origin images, even an inline script has
 * no channel to send data out. `npm run check:privacy` checks this policy.
 *
 * Applied to the production build only: the development server needs a
 * WebSocket for hot reloading.
 */
const CONTENT_SECURITY_POLICY = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "font-src 'self' data:",
  "connect-src 'none'",
  "form-action 'none'",
  "frame-src 'none'",
  "object-src 'none'",
  "base-uri 'self'",
].join("; ");

const production = process.env["NODE_ENV"] === "production";

const config: Config = {
  title: "anonyma",
  tagline:
    "Find and anonymize personal data in TypeScript — zero dependencies, in your process, on the edge.",
  favicon: "img/logo.svg",

  url: "https://izaccavalheiro.github.io",
  baseUrl: "/anonyma/",
  organizationName: "izaccavalheiro",
  projectName: "anonyma",
  trailingSlash: false,

  onBrokenLinks: "throw",
  onBrokenAnchors: "throw",
  markdown: {
    // .md files are CommonMark, so the repository's own Markdown is used as it is;
    // .mdx files may use components.
    format: "detect",
    hooks: { onBrokenMarkdownLinks: "throw" },
  },

  i18n: { defaultLocale: "en", locales: ["en"] },

  headTags: production
    ? [
        {
          tagName: "meta",
          attributes: { "http-equiv": "Content-Security-Policy", content: CONTENT_SECURITY_POLICY },
        },
        { tagName: "meta", attributes: { name: "referrer", content: "no-referrer" } },
      ]
    : [],

  presets: [
    [
      "classic",
      {
        docs: {
          sidebarPath: "./sidebars.ts",
          editUrl: `${repository}/edit/main/website/`,
          showLastUpdateTime: false,
        },
        blog: {
          showReadingTime: true,
          blogTitle: "anonyma blog",
          blogDescription: "Releases, guides and notes on privacy engineering with anonyma.",
          feedOptions: { type: ["rss", "atom"], xslt: true },
          onInlineTags: "throw",
          onInlineAuthors: "throw",
          onUntruncatedBlogPosts: "throw",
        },
        theme: { customCss: "./src/css/custom.css" },
        sitemap: { changefreq: "weekly" },
      } satisfies Preset.Options,
    ],
  ],

  themeConfig: {
    colorMode: { respectPrefersColorScheme: true },
    navbar: {
      title: "anonyma",
      logo: { alt: "anonyma", src: "img/logo.svg" },
      items: [
        { type: "docSidebar", sidebarId: "docs", position: "left", label: "Docs" },
        { to: "/playground", label: "Playground", position: "left" },
        { to: "/benchmarks", label: "Benchmarks", position: "left" },
        { to: "/blog", label: "Blog", position: "left" },
        { to: "/docs/project/changelog", label: "Changelog", position: "right" },
        { href: "https://www.npmjs.com/package/anonyma", label: "npm", position: "right" },
        { href: repository, label: "GitHub", position: "right" },
      ],
    },
    footer: {
      style: "dark",
      links: [
        {
          title: "Learn",
          items: [
            { label: "Introduction", to: "/docs" },
            { label: "Quick start", to: "/docs/guide/quick-start" },
            { label: "Recipes", to: "/docs/guides/scrub-files" },
            { label: "API reference", to: "/docs/reference/api" },
          ],
        },
        {
          title: "Try",
          items: [
            { label: "Playground", to: "/playground" },
            { label: "Benchmarks", to: "/benchmarks" },
            { label: "Command line", to: "/docs/packages/cli" },
          ],
        },
        {
          title: "Project",
          items: [
            { label: "GitHub", href: repository },
            { label: "npm", href: "https://www.npmjs.com/package/anonyma" },
            { label: "Changelog", to: "/docs/project/changelog" },
            { label: "Security", to: "/docs/project/security" },
          ],
        },
      ],
      copyright: `MIT licensed. This site runs entirely in your browser and cannot send what you type anywhere.`,
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
      additionalLanguages: ["bash", "json"],
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
